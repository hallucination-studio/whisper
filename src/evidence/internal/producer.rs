use super::*;
use super::{format::*, package::*, semantics::*, verifier::*};

// These are the Identifier and TeamIdentifier reported by macOS codesign for the official Google
// Chrome bundle. This producer-owned copy records the observer identity without sharing verifier
// authority; changing either admits a different signed browser and requires acceptance review.
const PRODUCER_CHROME_APPLICATION_ID: &str = "com.google.Chrome";
const PRODUCER_CHROME_TEAM_ID: &str = "EQHXZ8M8AV";

pub(crate) fn seal_producer(root: &Path) -> Result<(), EvidenceError> {
    if root.join("verification.json").exists() {
        return Err(EvidenceError::ExistingVerification);
    }
    let files = read_package(root, ReadMode::SealProducer)?;
    let run_file = required(&files, "run.json")?;
    let physical_file = required(&files, "physical-input.json")?;
    let run: RunReceipt = parse_canonical_json("run.json", &run_file.bytes)?;
    let physical: PhysicalInput =
        parse_canonical_json("physical-input.json", &physical_file.bytes)?;
    if run.schema_version != 1
        || !run.privacy.ciphertext_source_mac_recoverable
        || run.result.eq_ignore_ascii_case("pass")
    {
        return Err(EvidenceError::Json("run.json".to_owned()));
    }
    validate_physical_root(&physical)?;
    let expected_paths = producer_paths(&physical);
    let mut expected =
        expected_paths.iter().map(|(path, _)| (*path).to_owned()).collect::<BTreeSet<_>>();
    expected.insert("run.json".to_owned());
    if files.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(EvidenceError::FileSet);
    }
    validate_manifest("run.json", &run.artifacts, expected_paths.clone(), &files)?;
    validate_formats(&files)?;
    validate_sensitive_cleartext(&files)?;
    authenticate_datagrams(&physical, &files)?;
    validate_producer_store_semantics(&run.identities.subject, &physical, &files)?;
    let host = host_identity(&SystemEvidenceEnvironment)?;
    validate_run_semantics(&run, &physical, &files, &host)?;
    seal_paths(
        root,
        std::iter::once("run.json").chain(expected_paths.into_iter().map(|(path, _)| path)),
    )?;
    seal_directory(root, "datagrams")
}

pub(crate) fn write_current_store_export(
    runtime: &crate::HostRuntime,
    path: &Path,
) -> Result<(), EvidenceError> {
    let snapshot = runtime.evidence_snapshot().map_err(EvidenceError::Store)?;
    write_store_export(path, &snapshot)
}

pub(crate) fn write_rebuild_store_export(
    runtime: &crate::HostRuntime,
    path: &Path,
) -> Result<(), EvidenceError> {
    let snapshot = runtime.rebuild_evidence_snapshot().ok_or(EvidenceError::RebuildUnavailable)?;
    write_store_export(path, &snapshot.store)
}

pub(crate) fn write_input_and_commit_artifacts(
    runtime: &crate::HostRuntime,
    root: &Path,
    sensor_id: &str,
    metadata: &crate::evidence::EvidenceRunMetadata,
    pre_restart_audit: &crate::evidence::EvidencePreRestartAudit,
) -> Result<(), EvidenceError> {
    validate_run_metadata(metadata)?;
    if sensor_id.is_empty() || sensitive_string(sensor_id) {
        return Err(EvidenceError::Semantic("physical fixture Sensor ID is empty"));
    }
    let (snapshot, current_audit) = runtime
        .evidence_snapshot_with_transaction_b_audit()
        .map_err(EvidenceError::Store)?
        .ok_or(EvidenceError::Semantic("transaction-B evidence audit is incomplete"))?;
    if snapshot.active_session.session_id != metadata.subject.session_id {
        return Err(EvidenceError::Semantic("physical input Semantic Session is incompatible"));
    }
    if pre_restart_audit.store_id != snapshot.store_id
        || pre_restart_audit.session_id != snapshot.active_session.session_id
    {
        return Err(EvidenceError::Semantic("pre-restart transaction-B audit identity changed"));
    }
    validate_transaction_b_audit(&snapshot, &current_audit, false)?;
    let mut transaction_b_audit = pre_restart_audit.effects.clone();
    transaction_b_audit.extend(current_audit);
    validate_transaction_b_audit(&snapshot, &transaction_b_audit, true)?;
    selected_relationship(
        &snapshot,
        &metadata.subject,
        "physical input relationship subject is absent",
    )?;
    if snapshot.datagrams.is_empty() {
        return Err(EvidenceError::Semantic("committed Store contains no physical input"));
    }
    let datagram_root = root.join("datagrams");
    fs::create_dir(&datagram_root)
        .map_err(|source| EvidenceError::Io { path: datagram_root.clone(), source })?;
    let mut physical_datagrams = Vec::with_capacity(snapshot.datagrams.len());
    for (index, datagram) in snapshot.datagrams.iter().enumerate() {
        let relative = format!("datagrams/{index:06}.bin");
        write_new_file(&root.join(&relative), &datagram.bytes)?;
        physical_datagrams.push(PhysicalDatagram {
            body_binding_sha256: datagram.body_binding_sha256.clone(),
            context: PhysicalReceiveContext {
                capture_record_seq: datagram.capture_record_seq.to_string(),
                capture_session_id: datagram.capture_session_id.clone(),
                capture_session_time: datagram.capture_session_time.to_string(),
                semantic_record_seq: datagram.record_seq.to_string(),
                semantic_session_time: datagram.session_time.to_string(),
                transport: "udp".to_owned(),
                wire_format: "native_frame_v1".to_owned(),
            },
            device_id: datagram.device_id.to_string(),
            key_epoch: datagram.key_epoch.to_string(),
            path: relative,
            receive_order: index.to_string(),
            received_monotonic_ns: datagram.receive_monotonic_ns.to_string(),
            received_utc_ns: datagram.receive_utc_ns.to_string(),
            sha256: datagram.sha256.clone(),
        });
    }
    let physical = PhysicalInput {
        datagrams: physical_datagrams,
        fixture: FixtureIdentity {
            capability_sha256: metadata.identity.firmware_capability_sha256.clone(),
            firmware_image_sha256: metadata.identity.firmware_image_sha256.clone(),
            kind: "development_fixture".to_owned(),
            provisioning_sha256: metadata.identity.provisioning_sha256.clone(),
            sensor_id: sensor_id.to_owned(),
        },
        schema_version: 1,
    };
    write_canonical_json_file(&root.join("physical-input.json"), &physical)?;

    let mut budget = ReadBudget::default();

    let facts = snapshot
        .facts
        .iter()
        .zip(&snapshot.commits)
        .zip(&transaction_b_audit)
        .map(|((fact, commit), transaction_b)| {
            let capture = fact.capture.as_ref().map(|capture| HostTraceCapture {
                capture_record_seq: capture.capture_record_seq.to_string(),
                capture_session_id: capture.capture_session_id.clone(),
                capture_session_time: capture.capture_session_time.to_string(),
            });
            let mut effects = vec!["ordered_fact".to_owned()];
            if fact.kind == "packet" {
                effects.extend(["replay_admission".to_owned(), "capture_membership".to_owned()]);
            }
            let mut transaction_b_effects = vec![
                "processed_cursor".to_owned(),
                "timeline_digest".to_owned(),
                "projection_watermark".to_owned(),
            ];
            if transaction_b.baseline_sha256.is_some() {
                transaction_b_effects.push("complete_baseline".to_owned());
            }
            if transaction_b.relationship_sha256.is_some() {
                transaction_b_effects
                    .extend(["relationship_projection".to_owned(), "creator_commit".to_owned()]);
            }
            Ok(HostTraceFact {
                body_sha256: fact.body_sha256.clone(),
                capture,
                command: fact.command.as_ref().map(|command| HostTraceCommand {
                    command: command.command.clone(),
                    link: command.link.clone(),
                    profile: command.profile.clone(),
                }),
                datagram_sha256: fact.datagram_sha256.clone(),
                decoded_message: fact
                    .datagram_sha256
                    .as_ref()
                    .map(|digest| decoded_message_for_digest(&physical, root, digest, &mut budget))
                    .transpose()?,
                kind: fact.kind.clone(),
                record_seq: fact.record_seq.to_string(),
                session_time: fact.session_time.to_string(),
                transaction_a: HostTraceTransactionA {
                    effects,
                    identity: format!(
                        "{}:A:{}",
                        snapshot.active_session.session_id, fact.record_seq
                    ),
                },
                transaction_b: HostTraceTransactionB {
                    baseline_sha256: transaction_b.baseline_sha256.clone(),
                    commit_seq: commit.commit_seq.to_string(),
                    creator_commit_seq: transaction_b
                        .creator_commit_seq
                        .map(|value| value.to_string()),
                    effects: transaction_b_effects,
                    identity: format!("{}:B:{}", snapshot.store_id, commit.commit_seq),
                    processed_cursor: fact.record_seq.to_string(),
                    relationship_sha256: transaction_b.relationship_sha256.clone(),
                    timeline_digest: commit.timeline_digest.clone(),
                    watermark: commit.commit_seq.to_string(),
                },
            })
        })
        .collect::<Result<Vec<_>, EvidenceError>>()?;
    let trace = HostCommitTrace {
        facts,
        schema_version: 1,
        session_id: snapshot.active_session.session_id,
        store_id: snapshot.store_id,
    };
    write_canonical_json_file(&root.join("host-commit-trace.json"), &trace)
}

pub(crate) fn write_restart_artifact(
    runtime: &crate::HostRuntime,
    root: &Path,
    sensor_id: &str,
    subject: &crate::evidence::EvidenceSubject,
    downtime: crate::evidence::EvidenceInterval,
) -> Result<(), EvidenceError> {
    write_restart_artifact_with_environment(
        runtime,
        root,
        sensor_id,
        subject,
        downtime,
        &SystemEvidenceEnvironment,
    )
}

pub(super) fn write_restart_artifact_with_environment(
    runtime: &crate::HostRuntime,
    root: &Path,
    sensor_id: &str,
    subject: &crate::evidence::EvidenceSubject,
    downtime: crate::evidence::EvidenceInterval,
    environment: &dyn EvidenceEnvironment,
) -> Result<(), EvidenceError> {
    let stopped_utc_ns = downtime.started_utc_ns;
    let started_utc_ns = downtime.ended_utc_ns;
    if sensor_id.is_empty() || started_utc_ns <= stopped_utc_ns {
        return Err(EvidenceError::Semantic("restart identity or interval is invalid"));
    }
    let mut budget = ReadBudget::default();
    let pre_file = read_unsealed_artifact(&root.join("store-pre-stop.cbor"), &mut budget)?;
    let rebuild_file = read_unsealed_artifact(&root.join("store-post-rebuild.cbor"), &mut budget)?;
    if pre_file.bytes != rebuild_file.bytes {
        return Err(EvidenceError::Semantic("pre-stop and rebuild exports differ"));
    }
    let pre = parse_store_export(&pre_file)?;
    let continued = runtime.evidence_snapshot().map_err(EvidenceError::Store)?;
    let rebuilt = runtime.rebuild_evidence_snapshot().ok_or(EvidenceError::RebuildUnavailable)?;
    let mut rebuilt_logical = rebuilt.store.clone();
    rebuilt_logical.datagrams.clear();
    if rebuilt_logical != pre || continued.facts.len() <= pre.facts.len() {
        return Err(EvidenceError::Semantic("runtime restart snapshots are incompatible"));
    }
    validate_subject(subject)?;
    let before = selected_relationship(&pre, subject, "pre-stop relationship is absent")?;
    let after = selected_relationship(&continued, subject, "continued relationship is absent")?;
    let first_index = pre.facts.len();
    let first_fact = &continued.facts[first_index];
    let first_commit = &continued.commits[first_index];
    let later_commit = continued
        .commits
        .iter()
        .find(|commit| commit.record_seq == after.source_record_seq)
        .ok_or(EvidenceError::Semantic("later relationship creator is absent"))?;
    let old_capture = pre
        .facts
        .iter()
        .rev()
        .find_map(|fact| fact.capture.as_ref())
        .ok_or(EvidenceError::Semantic("old Capture Session is absent"))?;
    let new_capture = first_fact
        .capture
        .as_ref()
        .ok_or(EvidenceError::Semantic("new Capture Session is absent"))?;
    let executable = capture_executable_sha256(environment)?;
    let trace = RestartTrace {
        continuation: RestartContinuation {
            first_commit_seq: first_commit.commit_seq.to_string(),
            first_datagram_sha256: first_fact
                .datagram_sha256
                .clone()
                .ok_or(EvidenceError::Semantic("first continuation ciphertext is absent"))?,
            first_record_seq: first_fact.record_seq.to_string(),
            knowledge: "stable".to_owned(),
            later_commit_seq: later_commit.commit_seq.to_string(),
            later_record_seq: after.source_record_seq.to_string(),
            later_result_time: after.result_time.to_string(),
            most_recent_change_preserved: after.changed_at == before.changed_at
                && after.change_previous == before.change_previous
                && after.change_current == before.change_current,
            previous_result_time: before.result_time.to_string(),
        },
        rebuild: RestartRebuild {
            authorizer: if rebuilt.audit.authorizer_write_deny {
                "write_deny".to_owned()
            } else {
                "not_enforced".to_owned()
            },
            comparisons: RestartComparisons {
                baseline: pre.baselines == rebuilt.store.baselines,
                bytes: pre_file.bytes == rebuild_file.bytes,
                creator: pre.relationships == rebuilt.store.relationships,
                cursor: pre.processed_cursor == rebuilt.store.processed_cursor,
                relationship: pre.relationships == rebuilt.store.relationships,
                tail: pre.durable_tail == rebuilt.store.durable_tail,
                timeline: pre.timeline_digest == rebuilt.store.timeline_digest,
                watermark: pre.watermark == rebuilt.store.watermark,
            },
            open_flags: [
                (rebuilt.audit.read_only, "read_only"),
                (rebuilt.audit.no_mutex, "no_mutex"),
                (rebuilt.audit.nofollow, "nofollow"),
            ]
            .into_iter()
            .filter(|(enabled, _)| *enabled)
            .map(|(_, name)| name.to_owned())
            .collect(),
            post_export_sha256: rebuild_file.digest,
            pre_export_sha256: pre_file.digest,
            query_only: rebuilt.audit.query_only,
            total_changes: rebuilt.audit.total_changes.to_string(),
            write_attempted: rebuilt.audit.write_attempted,
            writer_opens: rebuilt.audit.writer_opens.to_string(),
        },
        retained: RestartRetained {
            link: before.link.clone(),
            physical_sensor: sensor_id.to_owned(),
            profile: before.profile.clone(),
            session_id: pre.active_session.session_id.clone(),
            store_id: pre.store_id.clone(),
        },
        schema_version: 1,
        start: RestartEndpoint {
            capture_session_id: new_capture.capture_session_id.clone(),
            durable_tail: pre.durable_tail.to_string(),
            host_executable_sha256: executable.clone(),
            processed_cursor: pre.processed_cursor.to_string(),
            utc_ns: started_utc_ns.to_string(),
            watermark: pre.watermark.to_string(),
        },
        stop: RestartEndpoint {
            capture_session_id: old_capture.capture_session_id.clone(),
            durable_tail: pre.durable_tail.to_string(),
            host_executable_sha256: executable,
            processed_cursor: pre.processed_cursor.to_string(),
            utc_ns: stopped_utc_ns.to_string(),
            watermark: pre.watermark.to_string(),
        },
    };
    write_canonical_json_file(&root.join("restart-trace.json"), &trace)
}

pub(crate) fn write_run_receipt(
    runtime: &crate::HostRuntime,
    root: &Path,
    metadata: &crate::evidence::EvidenceRunMetadata,
) -> Result<(), EvidenceError> {
    write_run_receipt_with_environment(runtime, root, metadata, &SystemEvidenceEnvironment)
}

pub(super) fn write_run_receipt_with_environment(
    runtime: &crate::HostRuntime,
    root: &Path,
    metadata: &crate::evidence::EvidenceRunMetadata,
    environment: &dyn EvidenceEnvironment,
) -> Result<(), EvidenceError> {
    validate_run_metadata(metadata)?;
    let snapshot = runtime.evidence_snapshot().map_err(EvidenceError::Store)?;
    if snapshot.config_digest != metadata.identity.config_sha256
        || snapshot.active_session.session_id != metadata.subject.session_id
    {
        return Err(EvidenceError::Semantic("producer metadata does not bind committed Store"));
    }
    let relationship = selected_relationship(
        &snapshot,
        &metadata.subject,
        "producer metadata does not bind committed Store",
    )?;
    let mut budget = ReadBudget::default();
    let physical_file = read_unsealed_artifact(&root.join("physical-input.json"), &mut budget)?;
    let physical: PhysicalInput =
        parse_canonical_json("physical-input.json", &physical_file.bytes)?;
    let mut artifacts = Vec::new();
    for (relative, media_type) in producer_paths(&physical) {
        let artifact = read_unsealed_artifact(&root.join(relative), &mut budget)?;
        artifacts.push(Artifact {
            media_type: media_type.to_owned(),
            path: relative.to_owned(),
            sha256: artifact.digest,
        });
    }
    let receipt = RunReceipt {
        artifacts,
        identities: RunIdentities {
            asset_sha256: runtime.evidence_served_asset_sha256().to_owned(),
            config_sha256: metadata.identity.config_sha256.clone(),
            firmware: FirmwareIdentity {
                capability_sha256: metadata.identity.firmware_capability_sha256.clone(),
                image_sha256: metadata.identity.firmware_image_sha256.clone(),
                source_revision: metadata.identity.firmware_source_revision.clone(),
            },
            host: host_identity(environment)?,
            provisioning_sha256: metadata.identity.provisioning_sha256.clone(),
            session_id: snapshot.active_session.session_id.clone(),
            store_id: snapshot.store_id.clone(),
            subject: Selection {
                link: relationship.link.clone(),
                profile: relationship.profile.clone(),
                session_id: snapshot.active_session.session_id,
            },
        },
        interval: Interval {
            ended_utc_ns: metadata.interval.ended_utc_ns.to_string(),
            started_utc_ns: metadata.interval.started_utc_ns.to_string(),
        },
        negative_claims: vec![
            "not_program_completion".to_owned(),
            "not_formal_e2e_classification".to_owned(),
        ],
        privacy: Privacy { ciphertext_source_mac_recoverable: true },
        procedure_version: "rf-relationship-v1".to_owned(),
        result: "candidate".to_owned(),
        run_id: metadata.run_id.clone(),
        schema_version: 1,
    };
    write_canonical_json_file(&root.join("run.json"), &receipt)
}

pub(crate) fn write_observer_receipt(
    root: &Path,
    metadata: &crate::evidence::EvidenceObserverMetadata,
) -> Result<(), EvidenceError> {
    validate_observer_metadata(metadata)?;
    let mut budget = ReadBudget::default();
    let run: RunReceipt = parse_canonical_json(
        "run.json",
        &read_unsealed_artifact(&root.join("run.json"), &mut budget)?.bytes,
    )?;
    let pre = parse_store_export(&read_unsealed_artifact(
        &root.join("store-pre-stop.cbor"),
        &mut budget,
    )?)?;
    let relationship =
        selected_relationship(&pre, &metadata.subject, "observer subject is absent")?;
    let mut artifacts = Vec::new();
    for (relative, media_type) in observer_paths() {
        let artifact = read_unsealed_artifact(&root.join(relative), &mut budget)?;
        artifacts.push(Artifact {
            media_type: media_type.to_owned(),
            path: relative.to_owned(),
            sha256: artifact.digest,
        });
    }
    let receipt = ObserverReceipt {
        artifacts,
        browser: Browser {
            application_id: PRODUCER_CHROME_APPLICATION_ID.to_owned(),
            executable_sha256: metadata.chrome.executable_sha256.clone(),
            name: "Chrome".to_owned(),
            team_id: PRODUCER_CHROME_TEAM_ID.to_owned(),
            version: metadata.chrome.version.clone(),
        },
        environment: "local_production".to_owned(),
        interval: Interval {
            ended_utc_ns: metadata.interval.ended_utc_ns.to_string(),
            started_utc_ns: metadata.interval.started_utc_ns.to_string(),
        },
        page_instance_id: metadata.page_instance_id.clone(),
        schema_version: 1,
        selection: Selection {
            link: relationship.link.clone(),
            profile: relationship.profile.clone(),
            session_id: pre.active_session.session_id,
        },
        served_asset_sha256: run.identities.asset_sha256,
        viewport: Viewport {
            device_scale_factor: metadata.viewport.device_scale_factor.clone(),
            height: metadata.viewport.height.to_string(),
            width: metadata.viewport.width.to_string(),
        },
    };
    write_canonical_json_file(&root.join("observer.json"), &receipt)
}

pub(super) fn write_canonical_json_file<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), EvidenceError> {
    let value =
        serde_json::to_value(value).map_err(|_| EvidenceError::Json("artifact".to_owned()))?;
    let bytes = canonical_json(&value)?;
    write_new_file(path, &bytes)
}

pub(super) fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), EvidenceError> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|source| EvidenceError::Io { path: path.to_path_buf(), source })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| EvidenceError::Io { path: path.to_path_buf(), source })
}

pub(super) fn write_store_export(
    path: &Path,
    snapshot: &crate::store::EvidenceStoreSnapshot,
) -> Result<(), EvidenceError> {
    let value = CborValue::serialized(snapshot).map_err(|_| cbor_error())?;
    let mut bytes = Vec::new();
    write_cbor(&value, &mut bytes)?;
    write_new_file(path, &bytes)
}

pub(crate) fn seal_observer(root: &Path) -> Result<(), EvidenceError> {
    if root.join("verification.json").exists() {
        return Err(EvidenceError::ExistingVerification);
    }
    let files = read_package(root, ReadMode::SealObserver)?;
    let run_file = required(&files, "run.json")?;
    let observer_file = required(&files, "observer.json")?;
    let physical_file = required(&files, "physical-input.json")?;
    let run: RunReceipt = parse_canonical_json("run.json", &run_file.bytes)?;
    let observer: ObserverReceipt = parse_canonical_json("observer.json", &observer_file.bytes)?;
    let physical: PhysicalInput =
        parse_canonical_json("physical-input.json", &physical_file.bytes)?;
    validate_receipt_roots(&run, &observer)?;
    validate_physical_root(&physical)?;
    if files.keys().cloned().collect::<BTreeSet<_>>() != expected_tree(&physical)? {
        return Err(EvidenceError::FileSet);
    }
    validate_manifest("run.json", &run.artifacts, producer_paths(&physical), &files)?;
    let observer_paths = observer_paths();
    validate_manifest("observer.json", &observer.artifacts, observer_paths.clone(), &files)?;
    validate_formats(&files)?;
    validate_sensitive_cleartext(&files)?;
    authenticate_datagrams(&physical, &files)?;
    validate_store_semantics(&run.identities.subject, &physical, &files)?;
    let host = host_identity(&SystemEvidenceEnvironment)?;
    validate_run_semantics(&run, &physical, &files, &host)?;
    validate_observer_semantics(&observer, &files)?;
    seal_paths(
        root,
        std::iter::once("observer.json").chain(observer_paths.into_iter().map(|(path, _)| path)),
    )?;
    seal_directory(root, "http")?;
    seal_directory(root, "screenshots")
}
