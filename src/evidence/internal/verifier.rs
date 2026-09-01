use super::*;
use super::{format::*, package::*, semantics::*};

// These observer-contract limits bound attacker-controlled Chrome DOM text retained in memory.
// Raising them increases verifier allocation and privacy-scan work; lowering them makes existing
// v1 observer packages incompatible and therefore requires a coordinated observer contract change.
const MAX_VISIBLE_TEXT_ITEMS: usize = 512;
const MAX_VISIBLE_TEXT_BYTES: usize = 4096;
// These verifier-owned values are the Identifier and TeamIdentifier reported by macOS codesign for
// the official Google Chrome bundle. They deliberately do not share producer constants: changing
// either broadens the independently accepted browser identity and requires acceptance review.
const VERIFIED_CHROME_APPLICATION_ID: &str = "com.google.Chrome";
const VERIFIED_CHROME_TEAM_ID: &str = "EQHXZ8M8AV";

pub(crate) fn verify(root: &Path) -> Result<(), EvidenceError> {
    verify_with_environment(root, &SystemEvidenceEnvironment)
}

pub(super) fn verify_with_environment(
    root: &Path,
    environment: &dyn EvidenceEnvironment,
) -> Result<(), EvidenceError> {
    if root.join("verification.json").exists() {
        return Err(EvidenceError::ExistingVerification);
    }
    let execution = VerifierExecution::capture(environment)?;
    let first = read_package(root, ReadMode::Verify)?;
    let run_file = required(&first, "run.json")?;
    let observer_file = required(&first, "observer.json")?;
    let physical_file = required(&first, "physical-input.json")?;
    let run: RunReceipt = parse_canonical_json("run.json", &run_file.bytes)?;
    let observer: ObserverReceipt = parse_canonical_json("observer.json", &observer_file.bytes)?;
    validate_run_directory(root, &run.run_id)?;
    validate_receipt_roots(&run, &observer)?;
    let physical: PhysicalInput =
        parse_canonical_json("physical-input.json", &physical_file.bytes)?;
    validate_physical_root(&physical)?;

    let expected = expected_tree(&physical)?;
    if first.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(EvidenceError::FileSet);
    }
    validate_manifest("run.json", &run.artifacts, producer_paths(&physical), &first)?;
    validate_manifest("observer.json", &observer.artifacts, observer_paths(), &first)?;
    validate_formats(&first)?;
    validate_sensitive_cleartext(&first)?;
    authenticate_datagrams(&physical, &first)?;
    validate_store_semantics(&run.identities.subject, &physical, &first)?;
    validate_run_semantics(&run, &physical, &first, &execution.host)?;
    validate_observer_semantics(&observer, &first)?;
    validate_execution_interval(&run, &observer, &physical, &first)?;

    let second = read_package(root, ReadMode::Verify)?;
    if first != second {
        let changed = first
            .iter()
            .find_map(|(path, artifact)| (second.get(path) != Some(artifact)).then_some(path))
            .or_else(|| second.keys().find(|path| !first.contains_key(*path)))
            .cloned()
            .unwrap_or_else(|| "package directory".to_owned());
        return Err(EvidenceError::Changed(changed));
    }

    let ended = environment.utc_now_ns()?;
    let receipt = VerificationReceipt {
        checks: [
            "exact_file_set",
            "portable_contained_paths",
            "sealed_regular_unaliased_files",
            "canonical_json_and_cbor",
            "producer_digests",
            "observer_digests",
            "fixture_ciphertext_authentication",
            "transaction_a_before_b",
            "store_session_subject_identity",
            "mechanically_read_only_rebuild",
            "byte_equal_rebuild_export",
            "exactly_once_continuation",
            "active_result_time_advancement",
            "same_page_http_websocket_chrome_binding",
            "stable_double_read",
        ]
        .map(|name| VerificationCheck { name, result: "PASS" }),
        interval: VerificationInterval {
            ended_utc_ns: ended.to_string(),
            started_utc_ns: execution.started_utc_ns.to_string(),
        },
        observer_artifacts: &observer.artifacts,
        observer_sha256: &observer_file.digest,
        producer_artifacts: &run.artifacts,
        result: "PASS",
        run_sha256: &run_file.digest,
        schema_version: 1,
        verifier: VerifierIdentity {
            executable_sha256: execution.executable_sha256,
            source_sha256: execution.source_sha256,
        },
    };
    let bytes = canonical_json(&serde_json::to_value(receipt).map_err(|_| {
        EvidenceError::Json("verification.json could not be serialized".to_owned())
    })?)?;
    write_verification(root, &bytes)?;
    seal_complete_package(root)?;
    Ok(())
}

fn validate_run_directory(root: &Path, run_id: &str) -> Result<(), EvidenceError> {
    super::validate_evidence_run_id(run_id)?;
    let expected = Path::new("docs")
        .join("evidence")
        .join("receipts")
        .join(format!("rf-relationship-{run_id}"));
    if root.ends_with(expected) {
        Ok(())
    } else {
        Err(EvidenceError::Semantic("evidence run directory is incompatible"))
    }
}

pub(super) fn required<'a>(
    files: &'a BTreeMap<String, ReadArtifact>,
    path: &str,
) -> Result<&'a ReadArtifact, EvidenceError> {
    files.get(path).ok_or(EvidenceError::FileSet)
}

pub(super) fn validate_receipt_roots(
    run: &RunReceipt,
    observer: &ObserverReceipt,
) -> Result<(), EvidenceError> {
    let valid = run.schema_version == 1
        && observer.schema_version == 1
        && run.privacy.ciphertext_source_mac_recoverable
        && !run.run_id.is_empty()
        && !run.procedure_version.is_empty()
        && !run.result.eq_ignore_ascii_case("pass")
        && !run.negative_claims.is_empty()
        && parse_decimal(&run.interval.started_utc_ns).is_some()
        && parse_decimal(&run.interval.ended_utc_ns).is_some()
        && !observer.page_instance_id.is_empty()
        && observer.browser.name == "Chrome"
        && observer.browser.application_id == VERIFIED_CHROME_APPLICATION_ID
        && observer.browser.team_id == VERIFIED_CHROME_TEAM_ID
        && is_sha256(&observer.browser.executable_sha256)
        && !observer.browser.version.is_empty()
        && observer.environment == "local_production"
        && !observer.selection.session_id.is_empty()
        && !observer.selection.link.is_empty()
        && is_hex_64(&observer.selection.profile)
        && is_sha256(&observer.served_asset_sha256)
        && observer.served_asset_sha256 == run.identities.asset_sha256
        && parse_decimal(&observer.interval.started_utc_ns).is_some()
        && parse_decimal(&observer.interval.ended_utc_ns).is_some();
    let valid = valid
        && observer.viewport.width.parse::<u32>().is_ok_and(|value| value > 0)
        && observer.viewport.height.parse::<u32>().is_ok_and(|value| value > 0)
        && valid_positive_decimal(&observer.viewport.device_scale_factor);
    let run_started = parse_decimal(&run.interval.started_utc_ns);
    let run_ended = parse_decimal(&run.interval.ended_utc_ns);
    let observer_started = parse_decimal(&observer.interval.started_utc_ns);
    let observer_ended = parse_decimal(&observer.interval.ended_utc_ns);
    let valid = valid
        && run.identities.subject.session_id == observer.selection.session_id
        && run.identities.subject.link == observer.selection.link
        && run.identities.subject.profile == observer.selection.profile
        && matches!(
            (run_started, run_ended, observer_started, observer_ended),
            (Some(run_started), Some(run_ended), Some(observer_started), Some(observer_ended))
                if run_started <= observer_started
                    && observer_started < observer_ended
                    && observer_ended <= run_ended
        );
    if valid { Ok(()) } else { Err(EvidenceError::Json("run.json or observer.json".to_owned())) }
}

pub(super) fn validate_run_semantics(
    run: &RunReceipt,
    physical: &PhysicalInput,
    files: &BTreeMap<String, ReadArtifact>,
    expected_host: &HostIdentity,
) -> Result<(), EvidenceError> {
    let pre = parse_store_export(required(files, "store-pre-stop.cbor")?)?;
    let continued = parse_store_export(required(files, "store-post-continuation.cbor")?)?;
    let relationship = selected_relationship_from_selection(
        &continued,
        &run.identities.subject,
        "run relationship subject is absent",
    )?;
    let restart: RestartTrace =
        parse_canonical_json("restart-trace.json", &required(files, "restart-trace.json")?.bytes)?;
    let valid = run.procedure_version == "rf-relationship-v1"
        && run.result == "candidate"
        && run.negative_claims == ["not_program_completion", "not_formal_e2e_classification"]
        && run.identities.store_id == pre.store_id
        && run.identities.store_id == continued.store_id
        && run.identities.session_id == pre.active_session.session_id
        && run.identities.session_id == continued.active_session.session_id
        && run.identities.subject.session_id == continued.active_session.session_id
        && run.identities.subject.link == relationship.link
        && run.identities.subject.profile == relationship.profile
        && run.identities.config_sha256 == continued.config_digest
        && run.identities.provisioning_sha256 == physical.fixture.provisioning_sha256
        && run.identities.firmware.capability_sha256 == physical.fixture.capability_sha256
        && run.identities.firmware.image_sha256 == physical.fixture.firmware_image_sha256
        && run.identities.host == *expected_host
        && run.identities.host.source_clean
        && run.identities.host.executable_sha256 == restart.stop.host_executable_sha256
        && is_revision(&run.identities.host.source_revision)
        && is_sha256(&run.identities.host.source_sha256)
        && is_revision(&run.identities.firmware.source_revision)
        && !run.identities.host.target.is_empty()
        && !sensitive_string(&run.identities.host.target)
        && is_sha256(&run.identities.asset_sha256)
        && is_sha256(&run.identities.provisioning_sha256)
        && is_sha256(&run.identities.firmware.image_sha256)
        && is_sha256(&run.identities.firmware.capability_sha256);
    if !valid {
        return Err(EvidenceError::Semantic("run identity binding is incompatible"));
    }
    let first =
        physical.datagrams.first().ok_or(EvidenceError::Semantic("physical input is absent"))?;
    let epoch = first
        .key_epoch
        .parse::<u16>()
        .map_err(|_| EvidenceError::Semantic("fixture epoch is incompatible"))?;
    let key = derive_public_development_fixture_key(&physical.fixture.sensor_id, epoch)
        .map_err(|_| EvidenceError::Semantic("fixture key is incompatible"))?;
    let mut capability = None;
    for datagram in &physical.datagrams {
        let bytes = &required(files, &datagram.path)?.bytes;
        let decoded = crate::wire::open_datagram(key.as_bytes(), bytes)
            .map_err(|_| EvidenceError::Semantic("fixture datagram decoding failed"))?;
        if let crate::wire::Message::Capabilities(value) = decoded.message() {
            capability = Some(value.clone());
            break;
        }
    }
    let capability = capability.ok_or(EvidenceError::Semantic("capability input is absent"))?;
    let capability_sha = hex_bytes(&capability.capability_digest());
    let image_sha = hex_bytes(&capability.descriptor().firmware_build_digest());
    if capability_sha != run.identities.firmware.capability_sha256
        || image_sha != run.identities.firmware.image_sha256
    {
        return Err(EvidenceError::Semantic("firmware capability identity is incompatible"));
    }
    Ok(())
}

pub(super) fn validate_execution_interval(
    run: &RunReceipt,
    observer: &ObserverReceipt,
    physical: &PhysicalInput,
    files: &BTreeMap<String, ReadArtifact>,
) -> Result<(), EvidenceError> {
    let restart: RestartTrace =
        parse_canonical_json("restart-trace.json", &required(files, "restart-trace.json")?.bytes)?;
    let Some(run_started) = parse_decimal(&run.interval.started_utc_ns) else {
        return Err(EvidenceError::Semantic("execution interval is incompatible"));
    };
    let Some(run_ended) = parse_decimal(&run.interval.ended_utc_ns) else {
        return Err(EvidenceError::Semantic("execution interval is incompatible"));
    };
    let Some(observer_started) = parse_decimal(&observer.interval.started_utc_ns) else {
        return Err(EvidenceError::Semantic("execution interval is incompatible"));
    };
    let Some(observer_ended) = parse_decimal(&observer.interval.ended_utc_ns) else {
        return Err(EvidenceError::Semantic("execution interval is incompatible"));
    };
    let Some(restart_stopped) = parse_decimal(&restart.stop.utc_ns) else {
        return Err(EvidenceError::Semantic("execution interval is incompatible"));
    };
    let Some(restart_started) = parse_decimal(&restart.start.utc_ns) else {
        return Err(EvidenceError::Semantic("execution interval is incompatible"));
    };
    let first_continuation = physical
        .datagrams
        .iter()
        .position(|datagram| datagram.sha256 == restart.continuation.first_datagram_sha256)
        .ok_or(EvidenceError::Semantic("execution interval is incompatible"))?;
    if first_continuation == 0 {
        return Err(EvidenceError::Semantic("execution interval is incompatible"));
    }
    let received = physical
        .datagrams
        .iter()
        .map(|datagram| parse_decimal(&datagram.received_utc_ns))
        .collect::<Option<Vec<_>>>()
        .ok_or(EvidenceError::Semantic("execution interval is incompatible"))?;
    let in_order = received.windows(2).all(|pair| pair[0] <= pair[1]);
    let all_in_run =
        received.iter().all(|received| run_started <= *received && *received <= run_ended);
    let before_restart =
        received[..first_continuation].iter().all(|received| *received <= restart_stopped);
    let after_restart =
        received[first_continuation..].iter().all(|received| restart_started <= *received);
    let observer_spans_restart = run_started <= observer_started
        && observer_started <= restart_stopped
        && restart_stopped < restart_started
        && restart_started <= observer_ended
        && observer_ended <= run_ended;
    if in_order && all_in_run && before_restart && after_restart && observer_spans_restart {
        Ok(())
    } else {
        Err(EvidenceError::Semantic("execution interval is incompatible"))
    }
}

pub(super) fn validate_observer_semantics(
    observer: &ObserverReceipt,
    files: &BTreeMap<String, ReadArtifact>,
) -> Result<(), EvidenceError> {
    validate_screenshot_dimensions(observer, files)?;
    let pre = parse_store_export(required(files, "store-pre-stop.cbor")?)?;
    let continued = parse_store_export(required(files, "store-post-continuation.cbor")?)?;
    let unknown: HttpRelationship =
        parse_canonical_json("http/unknown.json", &required(files, "http/unknown.json")?.bytes)?;
    let stable_pre: HttpRelationship = parse_canonical_json(
        "http/stable-pre-restart.json",
        &required(files, "http/stable-pre-restart.json")?.bytes,
    )?;
    let stable_post: HttpRelationship = parse_canonical_json(
        "http/stable-post-restart.json",
        &required(files, "http/stable-post-restart.json")?.bytes,
    )?;
    validate_http_relationship(observer, &unknown, &pre, false)?;
    validate_unknown_trace_binding(observer, &unknown, files)?;
    validate_http_relationship(observer, &stable_pre, &pre, true)?;
    validate_http_relationship(observer, &stable_post, &continued, true)?;
    let pre_relationship = selected_relationship_from_selection(
        &pre,
        &observer.selection,
        "observer relationship subject is absent",
    )?;
    let post_relationship = continued
        .relationships
        .iter()
        .find(|candidate| {
            candidate.link == pre_relationship.link && candidate.profile == pre_relationship.profile
        })
        .ok_or(EvidenceError::Semantic("observer relationship subject is absent"))?;
    let stable_change = stable_pre
        .data
        .most_recent_change
        .as_ref()
        .ok_or(EvidenceError::Semantic("Stable HTTP change is absent"))?;
    let stable_change_time =
        parse_decimal(&stable_change.changed_at).and_then(|value| u64::try_from(value).ok());
    let valid_http = matches!(
        unknown.data.knowledge,
        HttpKnowledge::Unknown { ref reason } if reason == "baseline_learning"
    ) && matches!(
        stable_pre.data.knowledge,
        HttpKnowledge::Known { ref value } if value == "stable"
    ) && matches!(
        stable_post.data.knowledge,
        HttpKnowledge::Known { ref value } if value == "stable"
    ) && matches!(
        stable_change.previous,
        HttpKnowledge::Unknown { ref reason } if reason == "baseline_learning"
    ) && matches!(
        stable_change.current,
        HttpKnowledge::Known { ref value } if value == "stable"
    ) && stable_pre.data.result_time == pre_relationship.result_time.to_string()
        && stable_post.data.result_time == post_relationship.result_time.to_string()
        && stable_pre.data.creator_commit.sequence
            == pre_relationship.creator_commit_seq.to_string()
        && stable_post.data.creator_commit.sequence
            == post_relationship.creator_commit_seq.to_string()
        && stable_change_time == pre_relationship.changed_at
        && stable_change_time == post_relationship.changed_at
        && http_knowledge_matches_store(
            &stable_change.previous,
            pre_relationship.change_previous.as_ref(),
        )
        && http_knowledge_matches_store(
            &stable_change.current,
            pre_relationship.change_current.as_ref(),
        )
        && http_knowledge_matches_store(
            &stable_change.previous,
            post_relationship.change_previous.as_ref(),
        )
        && http_knowledge_matches_store(
            &stable_change.current,
            post_relationship.change_current.as_ref(),
        )
        && stable_post.data.most_recent_change.as_ref() == Some(stable_change);
    if !valid_http {
        return Err(EvidenceError::Semantic("HTTP relationship observations are incompatible"));
    }

    let websocket: WebsocketTrace =
        parse_canonical_json("websocket.json", &required(files, "websocket.json")?.bytes)?;
    if websocket.schema_version != 1
        || websocket.events.len() < 5
        || !valid_loopback_live_websocket_url(&websocket.url)
    {
        return Err(EvidenceError::Semantic("WebSocket transcript root is incompatible"));
    }
    let mut disconnected = None;
    let mut reconnected = None;
    let mut previous_watermark = None;
    let mut active_socket = None;
    for (index, event) in websocket.events.iter().enumerate() {
        if event.order != index.to_string()
            || !matches!(
                event.kind.as_str(),
                "connected" | "message" | "disconnected" | "reconnected"
            )
            || (index == 0 && event.kind != "connected")
        {
            return Err(EvidenceError::Semantic("WebSocket transcript order is incompatible"));
        }
        match event.kind.as_str() {
            "connected" => {
                if event.socket_id != "0"
                    || event.url.as_deref() != Some(websocket.url.as_str())
                    || active_socket.replace(event.socket_id.as_str()).is_some()
                {
                    return Err(EvidenceError::Semantic(
                        "WebSocket connection identity is incompatible",
                    ));
                }
            }
            "disconnected" => {
                if event.url.is_some()
                    || active_socket != Some(event.socket_id.as_str())
                    || disconnected.replace(index).is_some()
                    || reconnected.is_some()
                {
                    return Err(EvidenceError::Semantic(
                        "WebSocket connection identity is incompatible",
                    ));
                }
                active_socket = None;
            }
            "reconnected" => {
                if event.socket_id != "1"
                    || event.url.as_deref() != Some(websocket.url.as_str())
                    || disconnected.is_none()
                    || reconnected.replace(index).is_some()
                    || active_socket.replace(event.socket_id.as_str()).is_some()
                {
                    return Err(EvidenceError::Semantic(
                        "WebSocket connection identity is incompatible",
                    ));
                }
            }
            "message" => {
                if event.url.is_some() || active_socket != Some(event.socket_id.as_str()) {
                    return Err(EvidenceError::Semantic(
                        "WebSocket connection identity is incompatible",
                    ));
                }
            }
            _ => unreachable!("WebSocket event kind was checked above"),
        }
        if event.kind == "message" {
            let Some(delivery) = event.delivery_sequence.as_deref() else {
                return Err(EvidenceError::Semantic("WebSocket watermark message is incompatible"));
            };
            let Some(store_id) = event.store_id.as_deref() else {
                return Err(EvidenceError::Semantic("WebSocket watermark message is incompatible"));
            };
            let Some(watermark) = event.watermark.as_deref() else {
                return Err(EvidenceError::Semantic("WebSocket watermark message is incompatible"));
            };
            let raw = serde_json::to_vec(&LiveEnvelopeEvidence {
                http_schema_version: 1,
                delivery_sequence: delivery,
                projection_commit: LiveWatermarkEvidence { store_id, sequence: watermark },
                payload: LivePayloadEvidence { kind: "projection_watermark" },
            })
            .map_err(|_| EvidenceError::Json("websocket.json".to_owned()))?;
            let parsed_watermark = parse_decimal(watermark);
            if store_id != pre.store_id
                || parse_decimal(delivery).is_none()
                || parsed_watermark.is_none()
                || event.raw_text_sha256.as_deref() != Some(sha256(&raw).as_str())
                || matches!((previous_watermark, parsed_watermark), (Some(previous), Some(current)) if current < previous)
            {
                return Err(EvidenceError::Semantic("WebSocket watermark message is incompatible"));
            }
            previous_watermark = parsed_watermark;
        } else if event.store_id.is_some()
            || event.raw_text_sha256.is_some()
            || event.watermark.is_some()
            || event.delivery_sequence.is_some()
        {
            return Err(EvidenceError::Semantic("WebSocket control event carries semantic data"));
        }
    }
    let (Some(disconnected), Some(reconnected)) = (disconnected, reconnected) else {
        return Err(EvidenceError::Semantic("WebSocket transcript order is incompatible"));
    };
    if active_socket != Some("1") {
        return Err(EvidenceError::Semantic("WebSocket connection identity is incompatible"));
    }
    let chrome: ChromeTrace =
        parse_canonical_json("chrome-trace.json", &required(files, "chrome-trace.json")?.bytes)?;
    let expected = [
        (
            "unknown",
            "LIVE",
            "LIVE",
            false,
            "unknown:baseline_learning",
            Some("screenshots/unknown.png"),
        ),
        (
            "stable_pre_restart",
            "LIVE",
            "LIVE",
            false,
            "stable",
            Some("screenshots/stable-pre-restart.png"),
        ),
        ("stale", "STALE", "POLLING", true, "stable", None),
        ("resynchronizing", "RESYNCHRONIZING", "POLLING", true, "stable", None),
        (
            "stable_post_restart",
            "LIVE",
            "LIVE",
            false,
            "stable",
            Some("screenshots/stable-post-restart.png"),
        ),
    ];
    if chrome.schema_version != 1
        || !is_sha256(&chrome.document_id)
        || chrome.page_instance_id != observer.page_instance_id
        || chrome.selection != observer.selection
        || chrome.events.len() != expected.len()
    {
        return Err(EvidenceError::Semantic("Chrome trace root is incompatible"));
    }
    for (index, (event, expected)) in chrome.events.iter().zip(expected).enumerate() {
        if event.order != index.to_string()
            || event.kind != expected.0
            || event.connection_state != expected.1
            || event.connection_text != expected.2
            || event.stale != expected.3
            || event.knowledge != expected.4
            || event.screenshot.as_deref() != expected.5
            || event.document_id != chrome.document_id
            || event.selection != observer.selection
            || event.connection_detail.is_empty()
            || event.visible_text.is_empty()
            || event.visible_text.len() > MAX_VISIBLE_TEXT_ITEMS
            || event.visible_text.iter().any(|text| text.len() > MAX_VISIBLE_TEXT_BYTES)
            || !event.opaque_visual_surfaces.is_empty()
            || if matches!(index, 1 | 4) {
                event.trigger_websocket_order.is_none()
                    || event.trigger_websocket_socket_id.is_none()
                    || event.trigger_websocket_watermark.is_none()
            } else {
                event.trigger_websocket_order.is_some()
                    || event.trigger_websocket_socket_id.is_some()
                    || event.trigger_websocket_watermark.is_some()
            }
        {
            return Err(EvidenceError::Semantic("Chrome same-page sequence is incompatible"));
        }
        match expected.5 {
            Some(path) => {
                if event.screenshot_sha256.as_deref()
                    != Some(required(files, path)?.digest.as_str())
                    || event.state_bounds.is_none()
                {
                    return Err(EvidenceError::Semantic(
                        "Chrome screenshot trace binding is incompatible",
                    ));
                }
            }
            None => {
                if event.screenshot_sha256.is_some() || event.state_bounds.is_some() {
                    return Err(EvidenceError::Semantic(
                        "Chrome screenshot trace binding is incompatible",
                    ));
                }
            }
        }
    }
    let stable_bindings = [
        (1_usize, stable_pre.data.creator_commit.sequence.as_str(), 0..disconnected),
        (
            4_usize,
            stable_post.data.creator_commit.sequence.as_str(),
            reconnected + 1..websocket.events.len(),
        ),
    ];
    for (chrome_index, creator, allowed_orders) in stable_bindings {
        let event = &chrome.events[chrome_index];
        let order =
            event.trigger_websocket_order.as_deref().and_then(|value| value.parse::<usize>().ok());
        let last_message = allowed_orders
            .clone()
            .filter(|order| websocket.events[*order].kind == "message")
            .next_back();
        let Some(order) =
            order.filter(|order| allowed_orders.contains(order) && Some(*order) == last_message)
        else {
            return Err(EvidenceError::Semantic(
                "Chrome Stable observation does not follow its WebSocket invalidation",
            ));
        };
        let trigger = &websocket.events[order];
        if trigger.kind != "message"
            || trigger.watermark.as_deref() != Some(creator)
            || event.trigger_websocket_socket_id.as_deref() != Some(trigger.socket_id.as_str())
            || event.trigger_websocket_watermark.as_deref() != Some(creator)
        {
            return Err(EvidenceError::Semantic(
                "Chrome Stable observation does not follow its WebSocket invalidation",
            ));
        }
    }
    if chrome.events[2].connection_detail != "WebSocket closed \u{b7} fixed 250 ms HTTP polling"
        || chrome.events[3].connection_detail
            != "Watermark received \u{b7} reading complete HTTP resources"
    {
        return Err(EvidenceError::Semantic("Chrome connection trace is incompatible"));
    }
    if chrome.events[0].result_time.as_deref() != Some(unknown.data.result_time.as_str())
        || chrome.events[1].result_time.as_deref() != Some(stable_pre.data.result_time.as_str())
        || chrome.events[2].result_time.as_deref() != Some(stable_pre.data.result_time.as_str())
        || chrome.events[3].result_time.as_deref() != Some(stable_pre.data.result_time.as_str())
        || chrome.events[4].result_time.as_deref() != Some(stable_post.data.result_time.as_str())
    {
        return Err(EvidenceError::Semantic("Chrome trace result times are incompatible"));
    }
    let expected_change_state = "Unknown(BaselineLearning) \u{2192} Stable";
    if chrome.events[0].change_state.is_some()
        || chrome.events[0].change_time.is_some()
        || chrome.events[1].change_state.as_deref() != Some(expected_change_state)
        || chrome.events[1].change_time.as_deref() != Some(stable_change.changed_at.as_str())
        || chrome.events[4].change_state.as_deref() != Some(expected_change_state)
        || chrome.events[4].change_time.as_deref() != Some(stable_change.changed_at.as_str())
        || chrome.events[2..4].iter().any(|event| {
            event.change_state.as_deref() != Some(expected_change_state)
                || event.change_time.as_deref() != Some(stable_change.changed_at.as_str())
        })
    {
        return Err(EvidenceError::Semantic("Chrome trace change values are incompatible"));
    }
    Ok(())
}

fn valid_loopback_live_websocket_url(value: &str) -> bool {
    let Some(port_and_path) = value.strip_prefix("ws://loopback:") else {
        return false;
    };
    let Some(port) = port_and_path.strip_suffix("/api/live") else {
        return false;
    };
    port.parse::<u16>().is_ok_and(|value| value != 0 && value.to_string() == port)
}

pub(super) fn http_knowledge_matches_store(
    http: &HttpKnowledge,
    store: Option<&crate::store::EvidenceKnowledge>,
) -> bool {
    match (http, store) {
        (
            HttpKnowledge::Known { value: http },
            Some(crate::store::EvidenceKnowledge::Known { value: store }),
        ) => http == store,
        (
            HttpKnowledge::Unknown { reason: http },
            Some(crate::store::EvidenceKnowledge::Unknown { reason: store }),
        ) => http == store,
        _ => false,
    }
}

pub(super) fn validate_screenshot_dimensions(
    observer: &ObserverReceipt,
    files: &BTreeMap<String, ReadArtifact>,
) -> Result<(), EvidenceError> {
    let expected_width =
        scaled_viewport_dimension(&observer.viewport.width, &observer.viewport.device_scale_factor);
    let expected_height = scaled_viewport_dimension(
        &observer.viewport.height,
        &observer.viewport.device_scale_factor,
    );
    let (Some(expected_width), Some(expected_height)) = (expected_width, expected_height) else {
        return Err(EvidenceError::Semantic("observer viewport is incompatible"));
    };
    let chrome: ChromeTrace =
        parse_canonical_json("chrome-trace.json", &required(files, "chrome-trace.json")?.bytes)?;
    let screenshots = [
        (0_usize, "screenshots/unknown.png"),
        (1_usize, "screenshots/stable-pre-restart.png"),
        (4_usize, "screenshots/stable-post-restart.png"),
    ];
    let mut state_regions = Vec::with_capacity(screenshots.len());
    for (event_index, path) in screenshots {
        let image = validate_png(path, &required(files, path)?.bytes)?;
        if image.dimensions.width != expected_width || image.dimensions.height != expected_height {
            return Err(EvidenceError::Semantic("screenshot dimensions are incompatible"));
        }
        let bounds = chrome
            .events
            .get(event_index)
            .and_then(|event| event.state_bounds.as_ref())
            .ok_or(EvidenceError::Semantic("screenshot state bounds are incompatible"))?;
        state_regions.push(screenshot_state_region(
            &image,
            bounds,
            &observer.viewport.device_scale_factor,
        )?);
    }
    if chrome.events[1].state_bounds != chrome.events[4].state_bounds
        || state_regions[0] == state_regions[1]
        || state_regions[1] != state_regions[2]
        || !state_regions.iter().all(|pixels| {
            pixels
                .chunks_exact(4)
                .next()
                .is_some_and(|first| pixels.chunks_exact(4).any(|pixel| pixel != first))
        })
    {
        return Err(EvidenceError::Semantic("screenshot visual state is incompatible"));
    }
    Ok(())
}

fn screenshot_state_region(
    image: &PngImage,
    bounds: &StateBounds,
    scale: &str,
) -> Result<Vec<u8>, EvidenceError> {
    let scaled = |value: u32| {
        scaled_viewport_dimension(&value.to_string(), scale)
            .ok_or(EvidenceError::Semantic("screenshot state bounds are incompatible"))
    };
    let x = scaled(bounds.x)?;
    let y = scaled(bounds.y)?;
    let width = scaled(bounds.width)?;
    let height = scaled(bounds.height)?;
    let image_width = usize::try_from(image.dimensions.width)
        .map_err(|_| EvidenceError::Semantic("screenshot visual state is incompatible"))?;
    let image_height = usize::try_from(image.dimensions.height)
        .map_err(|_| EvidenceError::Semantic("screenshot visual state is incompatible"))?;
    let x = usize::try_from(x)
        .map_err(|_| EvidenceError::Semantic("screenshot visual state is incompatible"))?;
    let y = usize::try_from(y)
        .map_err(|_| EvidenceError::Semantic("screenshot visual state is incompatible"))?;
    let width = usize::try_from(width)
        .map_err(|_| EvidenceError::Semantic("screenshot visual state is incompatible"))?;
    let height = usize::try_from(height)
        .map_err(|_| EvidenceError::Semantic("screenshot visual state is incompatible"))?;
    if width == 0
        || height == 0
        || x.checked_add(width).is_none_or(|end| end > image_width)
        || y.checked_add(height).is_none_or(|end| end > image_height)
    {
        return Err(EvidenceError::Semantic("screenshot visual state is incompatible"));
    }
    let mut region = Vec::with_capacity(width * height * 4);
    for row in y..y + height {
        let start = (row * image_width + x) * 4;
        let end = start + width * 4;
        region.extend_from_slice(&image.pixels[start..end]);
    }
    Ok(region)
}

pub(super) fn scaled_viewport_dimension(css_pixels: &str, scale: &str) -> Option<u32> {
    let css_pixels = css_pixels.parse::<u128>().ok()?;
    let (integer, fraction) = scale.split_once('.').map_or((scale, ""), |parts| parts);
    let denominator = 10_u128.checked_pow(u32::try_from(fraction.len()).ok()?)?;
    let numerator = integer
        .parse::<u128>()
        .ok()?
        .checked_mul(denominator)?
        .checked_add(if fraction.is_empty() { 0 } else { fraction.parse::<u128>().ok()? })?;
    let scaled = css_pixels.checked_mul(numerator)?;
    if scaled % denominator != 0 {
        return None;
    }
    u32::try_from(scaled / denominator).ok()
}

pub(super) fn validate_http_relationship(
    observer: &ObserverReceipt,
    response: &HttpRelationship,
    snapshot: &crate::store::EvidenceStoreSnapshot,
    exact_cursor: bool,
) -> Result<(), EvidenceError> {
    let creator = parse_decimal(&response.data.creator_commit.sequence);
    let watermark = parse_decimal(&response.receipt.projection_commit.sequence);
    let response_cursor = parse_decimal(&response.receipt.last_record_seq);
    let valid = response.http_schema_version == 1
        && response.kind == "ok"
        && response.resource == "relationship_latest"
        && response.data.session_id == observer.selection.session_id
        && response.data.link == observer.selection.link
        && response.data.profile == observer.selection.profile
        && response.data.creator_commit.store_id == snapshot.store_id
        && response.receipt.projection_commit.store_id == snapshot.store_id
        && response.receipt.session_id == observer.selection.session_id
        && response.receipt.first_record_seq == "0"
        && matches!(response_cursor, Some(cursor) if cursor <= u128::from(snapshot.processed_cursor))
        && (!exact_cursor
            || response.receipt.last_record_seq == snapshot.processed_cursor.to_string())
        && !response.receipt.decoder_version.is_empty()
        && !response.receipt.conditioning_version.is_empty()
        && !response.receipt.algorithm_version.is_empty()
        && matches!((creator, watermark), (Some(creator), Some(watermark)) if creator <= watermark);
    if valid {
        Ok(())
    } else {
        Err(EvidenceError::Semantic("HTTP receipt binding is incompatible"))
    }
}

pub(super) fn validate_unknown_trace_binding(
    observer: &ObserverReceipt,
    response: &HttpRelationship,
    files: &BTreeMap<String, ReadArtifact>,
) -> Result<(), EvidenceError> {
    let trace: HostCommitTrace = parse_canonical_json(
        "host-commit-trace.json",
        &required(files, "host-commit-trace.json")?.bytes,
    )?;
    let creator = trace
        .facts
        .iter()
        .position(|fact| fact.transaction_b.commit_seq == response.data.creator_commit.sequence)
        .ok_or(EvidenceError::Semantic("Unknown creator commit is absent"))?;
    let receipt = trace
        .facts
        .iter()
        .find(|fact| fact.transaction_b.commit_seq == response.receipt.projection_commit.sequence)
        .ok_or(EvidenceError::Semantic("Unknown receipt commit is absent"))?;
    let begin = trace.facts.iter().position(|fact| {
        fact.command.as_ref().is_some_and(|command| {
            command.command == "begin_learning"
                && command.link == observer.selection.link
                && command.profile == observer.selection.profile
        })
    });
    let commit = trace.facts.iter().position(|fact| {
        fact.command.as_ref().is_some_and(|command| {
            command.command == "commit"
                && command.link == observer.selection.link
                && command.profile == observer.selection.profile
        })
    });
    let creator_fact = &trace.facts[creator];
    let creator_commit = parse_decimal(&response.data.creator_commit.sequence)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(EvidenceError::Semantic("Unknown creator commit is invalid"))?;
    let result_time = parse_decimal(&response.data.result_time)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(EvidenceError::Semantic("Unknown result time is invalid"))?;
    let source_record_seq = creator_fact
        .record_seq
        .parse::<u64>()
        .map_err(|_| EvidenceError::Semantic("Unknown source record is invalid"))?;
    let expected_relationship = vec![crate::store::EvidenceRelationship {
        changed_at: None,
        change_current: None,
        change_previous: None,
        creator_commit_seq: creator_commit,
        knowledge: crate::store::EvidenceKnowledge::Unknown {
            reason: "baseline_learning".to_owned(),
        },
        link: response.data.link.clone(),
        profile: response.data.profile.clone(),
        result_time,
        source_record_seq,
    }];
    let expected_relationship_sha256 = canonical_cbor_sha256(&expected_relationship)?;
    let expected_effects = [
        "processed_cursor",
        "timeline_digest",
        "projection_watermark",
        "relationship_projection",
        "creator_commit",
    ];
    let valid = matches!((begin, commit), (Some(begin), Some(commit)) if begin < creator && creator < commit)
        && matches!(creator_fact.kind.as_str(), "packet" | "timeline_advance")
        && creator_fact.transaction_b.processed_cursor == creator_fact.record_seq
        && creator_fact.transaction_b.creator_commit_seq.as_deref()
            == Some(response.data.creator_commit.sequence.as_str())
        && creator_fact.transaction_b.relationship_sha256.as_deref()
            == Some(expected_relationship_sha256.as_str())
        && creator_fact.transaction_b.effects.iter().map(String::as_str).eq(expected_effects)
        && receipt.transaction_b.processed_cursor == response.receipt.last_record_seq
        && response.data.most_recent_change.is_none();
    if valid {
        Ok(())
    } else {
        Err(EvidenceError::Semantic("Unknown relationship commit binding is incompatible"))
    }
}
