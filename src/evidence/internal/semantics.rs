use super::*;
use super::{package::*, verifier::required};

// These verifier-local preimages deliberately do not call the producer implementation: #147
// requires an independent recomputation capable of detecting producer drift.
const PACKET_BODY_DOMAIN: &[u8] = b"rf-relationship-packet-body-v1\0";
const PACKET_BINDING_DOMAIN: &[u8] = b"rf-relationship-packet-binding-v1\0";

pub(crate) fn validate_transaction_b_audit(
    snapshot: &crate::store::EvidenceStoreSnapshot,
    effects: &[crate::store::EvidenceTransactionBEffect],
    exact_length: bool,
) -> Result<(), EvidenceError> {
    if (exact_length && effects.len() != snapshot.commits.len())
        || (!exact_length && effects.len() > snapshot.commits.len())
    {
        return Err(EvidenceError::Semantic("transaction-B audit length is incompatible"));
    }
    let start = snapshot.commits.len().saturating_sub(effects.len());
    for ((effect, commit), fact) in
        effects.iter().zip(&snapshot.commits[start..]).zip(&snapshot.facts[start..])
    {
        let baseline_valid = effect.baseline_sha256.as_deref().is_none_or(is_sha256);
        let relationship_valid = effect.relationship_sha256.as_deref().is_none_or(is_sha256);
        if effect.commit_seq != commit.commit_seq
            || effect.record_seq != fact.record_seq
            || effect.record_seq != commit.record_seq
            || effect.timeline_digest != commit.timeline_digest
            || !baseline_valid
            || !relationship_valid
            || effect.creator_commit_seq.is_some() != effect.relationship_sha256.is_some()
            || effect.creator_commit_seq.is_some_and(|creator| creator != effect.commit_seq)
        {
            return Err(EvidenceError::Semantic("transaction-B audit entry is incompatible"));
        }
    }
    Ok(())
}

fn packet_body_sha256(receive_utc_ns: i64, bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(PACKET_BODY_DOMAIN);
    digest.update(receive_utc_ns.to_be_bytes());
    digest.update(b"native_frame_v1\0");
    digest.update(u64::try_from(bytes.len()).expect("packet length fits u64").to_be_bytes());
    digest.update(bytes);
    digest.finalize().into()
}

fn packet_binding_sha256(receive_utc_ns: i64, bytes: &[u8], body_sha256: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(PACKET_BINDING_DOMAIN);
    digest.update(body_sha256);
    digest.update(receive_utc_ns.to_be_bytes());
    digest.update(u64::try_from(bytes.len()).expect("packet length fits u64").to_be_bytes());
    digest.update(bytes);
    digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn authenticate_datagrams(
    physical: &PhysicalInput,
    files: &BTreeMap<String, ReadArtifact>,
) -> Result<(), EvidenceError> {
    let mut source_mac = None;
    for datagram in &physical.datagrams {
        let file = files
            .get(&datagram.path)
            .ok_or_else(|| EvidenceError::Ciphertext(datagram.path.clone()))?;
        if file.digest != datagram.sha256 {
            return Err(EvidenceError::Digest(datagram.path.clone()));
        }
        let decoded = decode_physical_datagram(&physical.fixture.sensor_id, datagram, &file.bytes)?;
        let header = decoded.header();
        if header.device_id().to_string() != datagram.device_id
            || header.key_epoch().to_string() != datagram.key_epoch
        {
            return Err(EvidenceError::Ciphertext(datagram.path.clone()));
        }
        if let crate::wire::Message::CsiData(csi) = decoded.message() {
            if source_mac.is_some_and(|expected| expected != csi.source_mac()) {
                return Err(EvidenceError::Semantic(
                    "retained CSI datagrams do not retain one physical source",
                ));
            }
            source_mac = Some(csi.source_mac());
        }
    }
    Ok(())
}

pub(super) fn decode_physical_datagram(
    sensor_id: &str,
    datagram: &PhysicalDatagram,
    bytes: &[u8],
) -> Result<crate::wire::DecodedDatagram, EvidenceError> {
    let epoch = datagram
        .key_epoch
        .parse::<u16>()
        .map_err(|_| EvidenceError::Ciphertext(datagram.path.clone()))?;
    let key = derive_public_development_fixture_key(sensor_id, epoch)
        .map_err(|_| EvidenceError::Ciphertext(datagram.path.clone()))?;
    crate::wire::open_datagram(key.as_bytes(), bytes)
        .map_err(|_| EvidenceError::Ciphertext(datagram.path.clone()))
}

pub(super) fn decoded_message_for_digest(
    physical: &PhysicalInput,
    root: &Path,
    digest: &str,
    budget: &mut ReadBudget,
) -> Result<DecodedMessage, EvidenceError> {
    let datagram = physical
        .datagrams
        .iter()
        .find(|datagram| datagram.sha256 == digest)
        .ok_or(EvidenceError::Semantic("committed packet ciphertext is absent"))?;
    let bytes = read_unsealed_artifact(&root.join(&datagram.path), budget)?.bytes;
    let decoded = decode_physical_datagram(&physical.fixture.sensor_id, datagram, &bytes)?;
    Ok(decoded_message_descriptor(decoded.message()))
}

pub(super) fn decoded_message_descriptor(message: &crate::wire::Message) -> DecodedMessage {
    match message {
        crate::wire::Message::Capabilities(capability) => DecodedMessage::Capabilities {
            capability_sha256: hex_bytes(&capability.capability_digest()),
            firmware_image_sha256: hex_bytes(&capability.descriptor().firmware_build_digest()),
        },
        crate::wire::Message::CsiData(data) => DecodedMessage::CsiData {
            callback_tick_us: data.callback_tick_us().to_string(),
            capability_sha256: hex_bytes(&data.capability_digest()),
            capture_sequence: data.capture_sequence().to_string(),
            channel: data.radio().channel().to_string(),
            complex_sample_count: data.complex_sample_count().to_string(),
            driver_rx_timestamp_us: data.driver_rx_timestamp_us().to_string(),
        },
        crate::wire::Message::Health(health) => DecodedMessage::Health {
            callback_tick_us: health.callback_tick_us().to_string(),
            capability_sha256: hex_bytes(&health.capability_digest()),
            capture_seen: health.capture_seen().to_string(),
            queue_drop_full: health.queue_drop_full().to_string(),
            queue_drop_no_slot: health.queue_drop_no_slot().to_string(),
        },
    }
}

pub(super) fn validate_store_semantics(
    selection: &Selection,
    physical: &PhysicalInput,
    files: &BTreeMap<String, ReadArtifact>,
) -> Result<(), EvidenceError> {
    let unknown: HttpRelationship =
        parse_canonical_json("http/unknown.json", &required(files, "http/unknown.json")?.bytes)?;
    validate_store_semantics_inner(selection, physical, files, Some(&unknown))
}

pub(super) fn validate_producer_store_semantics(
    selection: &Selection,
    physical: &PhysicalInput,
    files: &BTreeMap<String, ReadArtifact>,
) -> Result<(), EvidenceError> {
    validate_store_semantics_inner(selection, physical, files, None)
}

fn validate_store_semantics_inner(
    selection: &Selection,
    physical: &PhysicalInput,
    files: &BTreeMap<String, ReadArtifact>,
    unknown: Option<&HttpRelationship>,
) -> Result<(), EvidenceError> {
    let pre = parse_store_export(required(files, "store-pre-stop.cbor")?)?;
    let rebuilt = parse_store_export(required(files, "store-post-rebuild.cbor")?)?;
    let continued = parse_store_export(required(files, "store-post-continuation.cbor")?)?;
    if pre != rebuilt {
        return Err(EvidenceError::Semantic("pre-stop and post-rebuild exports differ"));
    }
    if pre.store_id != continued.store_id
        || pre.active_session != continued.active_session
        || pre.topology_digest != continued.topology_digest
        || pre.config_digest != continued.config_digest
    {
        return Err(EvidenceError::Semantic("Store or Semantic Session identity changed"));
    }
    validate_store_export(&pre)?;
    validate_store_export(&continued)?;
    validate_observation_ciphertexts(&continued, pre.durable_tail, physical, files)?;
    validate_formal_run_sequence(&pre, selection)?;
    let first_continuation = pre
        .durable_tail
        .checked_add(1)
        .ok_or(EvidenceError::Semantic("pre-stop durable tail overflow"))?;
    if continued.durable_tail <= first_continuation
        || continued.facts.get(pre.facts.len()).map(|fact| fact.record_seq)
            != Some(first_continuation)
        || continued.facts[..pre.facts.len()] != pre.facts
        || continued.commits[..pre.commits.len()] != pre.commits
    {
        return Err(EvidenceError::Semantic("post-restart continuation is not exact and ordered"));
    }
    let first_fact = &continued.facts[pre.facts.len()];
    if first_fact.kind != "packet" || first_fact.capture.is_none() {
        return Err(EvidenceError::Semantic("first continuation fact is not physical input"));
    }
    let first_commit = &continued.commits[pre.commits.len()];
    if first_commit.record_seq != first_continuation {
        return Err(EvidenceError::Semantic("first continuation did not commit exactly once"));
    }
    let before = selected_relationship_from_selection(
        &pre,
        selection,
        "pre-stop Stable relationship is absent",
    )?;
    let after = selected_relationship_from_selection(
        &continued,
        selection,
        "continued relationship subject is absent",
    )?;
    if !matches!(
        &before.knowledge,
        crate::store::EvidenceKnowledge::Known { value } if value == "stable"
    ) || !matches!(
        &after.knowledge,
        crate::store::EvidenceKnowledge::Known { value } if value == "stable"
    ) || after.result_time <= before.result_time
        || after.changed_at != before.changed_at
        || after.change_previous != before.change_previous
        || after.change_current != before.change_current
        || after.creator_commit_seq <= before.creator_commit_seq
        || !selected_observation_at_or_immediately_before(
            &continued,
            selection,
            after.source_record_seq,
        )
    {
        return Err(EvidenceError::Semantic(
            "Stable continuation did not advance result time while preserving change",
        ));
    }
    let physical_digests =
        physical.datagrams.iter().map(|datagram| datagram.sha256.as_str()).collect::<Vec<_>>();
    let committed_digests = continued
        .facts
        .iter()
        .filter_map(|fact| fact.datagram_sha256.as_deref())
        .collect::<Vec<_>>();
    if physical_digests != committed_digests {
        return Err(EvidenceError::Semantic(
            "physical ciphertext order does not match committed packet facts",
        ));
    }
    let packet_facts = continued.facts.iter().filter(|fact| fact.kind == "packet");
    for (datagram, fact) in physical.datagrams.iter().zip(packet_facts) {
        let capture = fact
            .capture
            .as_ref()
            .ok_or(EvidenceError::Semantic("physical context Capture Session is absent"))?;
        if datagram.context.capture_session_id != capture.capture_session_id
            || datagram.context.capture_record_seq != capture.capture_record_seq.to_string()
            || datagram.context.capture_session_time != capture.capture_session_time.to_string()
            || datagram.context.semantic_record_seq != fact.record_seq.to_string()
            || datagram.context.semantic_session_time != fact.session_time.to_string()
            || datagram.received_monotonic_ns != datagram.context.capture_session_time
        {
            return Err(EvidenceError::Semantic(
                "sanitized physical receive context does not match transaction A",
            ));
        }
    }
    if unknown.is_some() {
        validate_host_commit_trace(physical, files, &pre, false)?;
        validate_host_commit_trace(physical, files, &continued, true)?;
    }
    validate_restart_trace(selection, physical, files, &pre, &continued)?;
    Ok(())
}

pub(super) fn validate_observation_ciphertexts(
    snapshot: &crate::store::EvidenceStoreSnapshot,
    pre_stop_tail: u64,
    physical: &PhysicalInput,
    files: &BTreeMap<String, ReadArtifact>,
) -> Result<(), EvidenceError> {
    let mut saw_pre_stop_csi = false;
    let mut saw_post_restart_csi = false;
    for observation in &snapshot.observations {
        let fact = snapshot
            .facts
            .get(usize::try_from(observation.record_seq).map_err(|_| {
                EvidenceError::Semantic("committed CSI observation record is incompatible")
            })?)
            .ok_or(EvidenceError::Semantic("committed CSI observation record is absent"))?;
        let digest = fact
            .datagram_sha256
            .as_deref()
            .ok_or(EvidenceError::Semantic("committed CSI observation ciphertext is absent"))?;
        let datagram = physical
            .datagrams
            .iter()
            .find(|datagram| datagram.sha256 == digest)
            .ok_or(EvidenceError::Semantic("committed CSI observation ciphertext is absent"))?;
        let decoded = decode_physical_datagram(
            &physical.fixture.sensor_id,
            datagram,
            &required(files, &datagram.path)?.bytes,
        )?;
        let crate::wire::Message::CsiData(csi) = decoded.message() else {
            return Err(EvidenceError::Semantic(
                "committed CSI observation ciphertext is not CSI data",
            ));
        };
        if hex_bytes(&csi.capability_digest()) != physical.fixture.capability_sha256 {
            return Err(EvidenceError::Semantic(
                "committed CSI observation capability is incompatible",
            ));
        }
        if observation.record_seq <= pre_stop_tail {
            saw_pre_stop_csi = true;
        } else {
            saw_post_restart_csi = true;
        }
    }
    if !saw_pre_stop_csi || !saw_post_restart_csi {
        return Err(EvidenceError::Semantic(
            "committed CSI observations do not span the controlled restart",
        ));
    }
    Ok(())
}

pub(super) fn validate_restart_trace(
    selection: &Selection,
    physical: &PhysicalInput,
    files: &BTreeMap<String, ReadArtifact>,
    pre: &crate::store::EvidenceStoreSnapshot,
    continued: &crate::store::EvidenceStoreSnapshot,
) -> Result<(), EvidenceError> {
    let artifact = required(files, "restart-trace.json")?;
    let trace: RestartTrace = parse_canonical_json("restart-trace.json", &artifact.bytes)?;
    let before = selected_relationship_from_selection(
        pre,
        selection,
        "restart relationship subject is absent",
    )?;
    let after = selected_relationship_from_selection(
        continued,
        selection,
        "restart relationship subject is absent",
    )?;
    let first_index = pre.facts.len();
    let first_fact = &continued.facts[first_index];
    let first_commit = &continued.commits[first_index];
    let later_commit = continued
        .commits
        .iter()
        .find(|commit| commit.record_seq == after.source_record_seq)
        .ok_or(EvidenceError::Semantic("later relationship creator record is absent"))?;
    let old_capture = pre
        .facts
        .iter()
        .rev()
        .find_map(|fact| fact.capture.as_ref())
        .ok_or(EvidenceError::Semantic("pre-stop physical Capture Session is absent"))?;
    let new_capture = first_fact
        .capture
        .as_ref()
        .ok_or(EvidenceError::Semantic("continuation Capture Session is absent"))?;
    let pre_digest = &required(files, "store-pre-stop.cbor")?.digest;
    let rebuild_digest = &required(files, "store-post-rebuild.cbor")?.digest;
    let stop_time = parse_decimal(&trace.stop.utc_ns);
    let start_time = parse_decimal(&trace.start.utc_ns);
    let valid = trace.schema_version == 1
        && trace.retained.store_id == pre.store_id
        && trace.retained.session_id == pre.active_session.session_id
        && trace.retained.link == before.link
        && trace.retained.profile == before.profile
        && trace.retained.physical_sensor == physical.fixture.sensor_id
        && trace.stop.capture_session_id == old_capture.capture_session_id
        && trace.start.capture_session_id == new_capture.capture_session_id
        && trace.stop.capture_session_id != trace.start.capture_session_id
        && trace.stop.durable_tail == pre.durable_tail.to_string()
        && trace.stop.processed_cursor == pre.processed_cursor.to_string()
        && trace.stop.watermark == pre.watermark.to_string()
        && trace.start.durable_tail == pre.durable_tail.to_string()
        && trace.start.processed_cursor == pre.processed_cursor.to_string()
        && trace.start.watermark == pre.watermark.to_string()
        && is_sha256(&trace.stop.host_executable_sha256)
        && trace.stop.host_executable_sha256 == trace.start.host_executable_sha256
        && matches!((stop_time, start_time), (Some(stop), Some(start)) if start > stop)
        && trace.rebuild.open_flags == ["read_only", "no_mutex", "nofollow"]
        && trace.rebuild.query_only
        && trace.rebuild.authorizer == "write_deny"
        && trace.rebuild.writer_opens == "0"
        && trace.rebuild.total_changes == "0"
        && !trace.rebuild.write_attempted
        && trace.rebuild.pre_export_sha256 == *pre_digest
        && trace.rebuild.post_export_sha256 == *rebuild_digest
        && trace.rebuild.comparisons.bytes
        && trace.rebuild.comparisons.timeline
        && trace.rebuild.comparisons.baseline
        && trace.rebuild.comparisons.relationship
        && trace.rebuild.comparisons.creator
        && trace.rebuild.comparisons.tail
        && trace.rebuild.comparisons.cursor
        && trace.rebuild.comparisons.watermark
        && trace.continuation.first_record_seq == first_fact.record_seq.to_string()
        && trace.continuation.first_commit_seq == first_commit.commit_seq.to_string()
        && first_fact.datagram_sha256.as_deref()
            == Some(trace.continuation.first_datagram_sha256.as_str())
        && trace.continuation.later_record_seq == after.source_record_seq.to_string()
        && trace.continuation.later_commit_seq == later_commit.commit_seq.to_string()
        && trace.continuation.previous_result_time == before.result_time.to_string()
        && trace.continuation.later_result_time == after.result_time.to_string()
        && trace.continuation.knowledge == "stable"
        && trace.continuation.most_recent_change_preserved;
    if valid { Ok(()) } else { Err(EvidenceError::Semantic("restart trace is incompatible")) }
}

pub(super) fn validate_host_commit_trace(
    physical: &PhysicalInput,
    files: &BTreeMap<String, ReadArtifact>,
    snapshot: &crate::store::EvidenceStoreSnapshot,
    exact_length: bool,
) -> Result<(), EvidenceError> {
    let artifact = required(files, "host-commit-trace.json")?;
    let trace: HostCommitTrace = parse_canonical_json("host-commit-trace.json", &artifact.bytes)?;
    if trace.schema_version != 1
        || trace.store_id != snapshot.store_id
        || trace.session_id != snapshot.active_session.session_id
        || (exact_length && trace.facts.len() != snapshot.facts.len())
        || (!exact_length && trace.facts.len() < snapshot.facts.len())
    {
        return Err(EvidenceError::Semantic("Host commit trace root is incompatible"));
    }
    for ((trace, fact), commit) in trace.facts.iter().zip(&snapshot.facts).zip(&snapshot.commits) {
        let expected_a = format!("{}:A:{}", snapshot.active_session.session_id, fact.record_seq);
        let expected_b = format!("{}:B:{}", snapshot.store_id, commit.commit_seq);
        let capture_matches = match (&trace.capture, &fact.capture) {
            (None, None) => true,
            (Some(trace), Some(capture)) => {
                trace.capture_record_seq == capture.capture_record_seq.to_string()
                    && trace.capture_session_id == capture.capture_session_id
                    && trace.capture_session_time == capture.capture_session_time.to_string()
            }
            _ => false,
        };
        let command_matches = match (&trace.command, &fact.command) {
            (None, None) => true,
            (Some(trace), Some(command)) => {
                trace.command == command.command
                    && trace.link == command.link
                    && trace.profile == command.profile
            }
            _ => false,
        };
        let expected_effects = if fact.kind == "packet" {
            ["ordered_fact", "replay_admission", "capture_membership"].as_slice()
        } else {
            ["ordered_fact"].as_slice()
        };
        let decoded_message = match fact.datagram_sha256.as_deref() {
            Some(digest) => {
                let datagram = physical
                    .datagrams
                    .iter()
                    .find(|datagram| datagram.sha256 == digest)
                    .ok_or(EvidenceError::Semantic("transaction-A ciphertext is absent"))?;
                let bytes = &required(files, &datagram.path)?.bytes;
                let receive_utc_ns = datagram.received_utc_ns.parse::<i64>().map_err(|_| {
                    EvidenceError::Semantic("transaction-A receive time is invalid")
                })?;
                let body_sha256 = packet_body_sha256(receive_utc_ns, bytes);
                if hex_bytes(&body_sha256) != fact.body_sha256
                    || packet_binding_sha256(receive_utc_ns, bytes, &body_sha256)
                        != datagram.body_binding_sha256
                {
                    return Err(EvidenceError::Semantic(
                        "transaction-A packet body binding does not match retained ciphertext",
                    ));
                }
                let decoded =
                    decode_physical_datagram(&physical.fixture.sensor_id, datagram, bytes)?;
                Some(decoded_message_descriptor(decoded.message()))
            }
            None => None,
        };
        let mut expected_b_effects =
            vec!["processed_cursor", "timeline_digest", "projection_watermark"];
        if trace.transaction_b.baseline_sha256.is_some() {
            expected_b_effects.push("complete_baseline");
        }
        if trace.transaction_b.relationship_sha256.is_some() {
            expected_b_effects.extend(["relationship_projection", "creator_commit"]);
        }
        let baseline_digest_valid =
            trace.transaction_b.baseline_sha256.as_deref().is_none_or(is_sha256);
        let relationship_digest_valid =
            trace.transaction_b.relationship_sha256.as_deref().is_none_or(is_sha256);
        let creator_valid = trace.transaction_b.creator_commit_seq.is_some()
            == trace.transaction_b.relationship_sha256.is_some()
            && trace
                .transaction_b
                .creator_commit_seq
                .as_deref()
                .is_none_or(|creator| creator == commit.commit_seq.to_string());
        if trace.body_sha256 != fact.body_sha256
            || trace.datagram_sha256 != fact.datagram_sha256
            || trace.decoded_message != decoded_message
            || trace.kind != fact.kind
            || trace.record_seq != fact.record_seq.to_string()
            || trace.session_time != fact.session_time.to_string()
            || !capture_matches
            || !command_matches
            || trace.transaction_a.identity != expected_a
            || trace.transaction_a.effects.iter().map(String::as_str).collect::<Vec<_>>()
                != expected_effects
            || trace.transaction_b.commit_seq != commit.commit_seq.to_string()
            || trace.transaction_b.effects.iter().map(String::as_str).collect::<Vec<_>>()
                != expected_b_effects
            || !baseline_digest_valid
            || !relationship_digest_valid
            || !creator_valid
            || trace.transaction_b.identity != expected_b
            || trace.transaction_b.processed_cursor != fact.record_seq.to_string()
            || trace.transaction_b.timeline_digest != commit.timeline_digest
            || trace.transaction_b.watermark != commit.commit_seq.to_string()
        {
            return Err(EvidenceError::Semantic("Host A/B trace does not match committed Store"));
        }
    }
    validate_snapshot_effect_bindings(&trace, snapshot)?;
    Ok(())
}

fn validate_snapshot_effect_bindings(
    trace: &HostCommitTrace,
    snapshot: &crate::store::EvidenceStoreSnapshot,
) -> Result<(), EvidenceError> {
    if let Some(record_seq) =
        snapshot.baselines.iter().map(|baseline| baseline.source_record_seq).max()
    {
        let effect = trace
            .facts
            .iter()
            .find(|fact| fact.record_seq == record_seq.to_string())
            .ok_or(EvidenceError::Semantic("complete baseline creator is absent"))?;
        if effect.transaction_b.baseline_sha256.as_deref()
            != Some(canonical_cbor_sha256(&snapshot.baselines)?.as_str())
        {
            return Err(EvidenceError::Semantic("complete baseline audit binding is incompatible"));
        }
    }
    if let Some(commit_seq) =
        snapshot.relationships.iter().map(|relationship| relationship.creator_commit_seq).max()
    {
        let effect = trace
            .facts
            .iter()
            .find(|fact| fact.transaction_b.commit_seq == commit_seq.to_string())
            .ok_or(EvidenceError::Semantic("relationship creator audit is absent"))?;
        let expected = canonical_cbor_sha256(&snapshot.relationships)?;
        if effect.transaction_b.creator_commit_seq.as_deref()
            != Some(commit_seq.to_string().as_str())
            || effect.transaction_b.relationship_sha256.as_deref() != Some(expected.as_str())
        {
            return Err(EvidenceError::Semantic("relationship audit binding is incompatible"));
        }
    }
    Ok(())
}

pub(super) fn canonical_cbor_sha256<T: Serialize>(value: &T) -> Result<String, EvidenceError> {
    Ok(sha256(&canonical_cbor_bytes(value)?))
}

pub(super) fn parse_store_export(
    artifact: &ReadArtifact,
) -> Result<crate::store::EvidenceStoreSnapshot, EvidenceError> {
    let mut cursor = Cursor::new(&artifact.bytes);
    let snapshot = ciborium::from_reader(&mut cursor)
        .map_err(|_| EvidenceError::Cbor("Store export schema".to_owned()))?;
    if cursor.position() != artifact.bytes.len() as u64 {
        return Err(EvidenceError::Cbor("Store export trailing bytes".to_owned()));
    }
    Ok(snapshot)
}

pub(super) fn validate_store_export(
    snapshot: &crate::store::EvidenceStoreSnapshot,
) -> Result<(), EvidenceError> {
    if snapshot.schema_version != 1
        || snapshot.facts.is_empty()
        || snapshot.facts.len() != snapshot.commits.len()
        || snapshot.durable_tail != snapshot.processed_cursor
        || snapshot.facts.last().map(|fact| fact.record_seq) != Some(snapshot.durable_tail)
        || snapshot.selected_range.first_record_seq != snapshot.facts[0].record_seq
        || snapshot.selected_range.last_record_seq != snapshot.durable_tail
        || snapshot.commits.last().map(|commit| commit.commit_seq) != Some(snapshot.watermark)
        || !is_sha256(&snapshot.store_id)
        || !is_sha256(&snapshot.topology_digest)
        || !is_sha256(&snapshot.config_digest)
        || !is_sha256(&snapshot.timeline_digest)
        || !is_sha256(&snapshot.active_session.manifest_sha256)
    {
        return Err(EvidenceError::Semantic("Store export root is incompatible"));
    }
    if snapshot.capture_sessions.is_empty()
        || snapshot.capture_sessions.iter().any(|capture| {
            capture.started_utc_ns < 0
                || capture.capture_session_id.is_empty()
                || capture.decoder_version.is_empty()
                || capture.conditioning_version.is_empty()
                || capture.algorithm_version.is_empty()
                || capture.durable_tail.is_some() != capture.last_session_time.is_some()
        })
        || !snapshot.capture_sessions.windows(2).all(|pair| {
            (pair[0].started_utc_ns, pair[0].capture_session_id.as_bytes())
                < (pair[1].started_utc_ns, pair[1].capture_session_id.as_bytes())
        })
        || snapshot.replay_identities.is_empty()
        || snapshot.replay_identities.iter().any(|identity| {
            identity.device_id == 0
                || identity.key_epoch == 0
                || !is_sha256(&identity.replay_window_sha256)
        })
        || !snapshot.replay_identities.windows(2).all(|pair| {
            (pair[0].device_id, pair[0].key_epoch) < (pair[1].device_id, pair[1].key_epoch)
        })
        || !snapshot.baselines.windows(2).all(|pair| {
            (pair[0].link.as_bytes(), pair[0].profile.as_bytes(), pair[0].deployment.as_bytes())
                < (
                    pair[1].link.as_bytes(),
                    pair[1].profile.as_bytes(),
                    pair[1].deployment.as_bytes(),
                )
        })
        || !snapshot.relationships.windows(2).all(|pair| {
            (pair[0].link.as_bytes(), pair[0].profile.as_bytes())
                < (pair[1].link.as_bytes(), pair[1].profile.as_bytes())
        })
    {
        return Err(EvidenceError::Semantic("Store runtime identities are incompatible"));
    }
    for baseline in &snapshot.baselines {
        let state = decode_hex(&baseline.state_cbor)
            .ok_or(EvidenceError::Semantic("baseline state encoding is incompatible"))?;
        let decoded = crate::session::decode_baseline_state(&state)
            .map_err(|_| EvidenceError::Semantic("baseline state encoding is incompatible"))?;
        let source_exists = usize::try_from(baseline.source_record_seq)
            .ok()
            .and_then(|index| snapshot.facts.get(index))
            .is_some_and(|fact| fact.record_seq == baseline.source_record_seq);
        if baseline.deployment.is_empty()
            || baseline.link.is_empty()
            || !is_hex_64(&baseline.profile)
            || sha256(&state) != baseline.state_sha256
            || decoded.key().link().as_str() != baseline.link
            || decoded.key().profile().to_string() != baseline.profile
            || decoded.compatibility().deployment().as_str() != baseline.deployment
            || !source_exists
        {
            return Err(EvidenceError::Semantic("complete baseline binding is incompatible"));
        }
    }
    for (index, (fact, commit)) in snapshot.facts.iter().zip(&snapshot.commits).enumerate() {
        let sequence = u64::try_from(index)
            .map_err(|_| EvidenceError::Semantic("Store export sequence overflow"))?;
        if fact.record_seq != sequence
            || commit.record_seq != fact.record_seq
            || commit.commit_seq != sequence + 1
            || !matches!(fact.kind.as_str(), "packet" | "baseline_command" | "timeline_advance")
            || !matches!(commit.kind.as_str(), "semantic" | "decode_rejected")
            || !is_sha256(&fact.body_sha256)
            || !is_sha256(&commit.timeline_digest)
            || fact.datagram_sha256.as_ref().is_some_and(|digest| !is_sha256(digest))
            || (fact.kind == "packet") != fact.capture.is_some()
            || (fact.kind == "packet") != fact.datagram_sha256.is_some()
            || (fact.kind == "baseline_command") != fact.command.is_some()
            || fact.command.as_ref().is_some_and(|command| {
                command_body_sha256(command).as_deref() != Some(&fact.body_sha256)
            })
            || (fact.kind == "timeline_advance" && fact.body_sha256 != sha256(&[0xf6]))
        {
            return Err(EvidenceError::Semantic("Store fact/commit ordering is incompatible"));
        }
    }
    for observation in &snapshot.observations {
        let fact = usize::try_from(observation.record_seq)
            .ok()
            .and_then(|index| snapshot.facts.get(index));
        if crate::domain::RadioLinkId::new(observation.link.clone()).is_err()
            || !is_hex_64(&observation.profile)
            || !matches!(fact, Some(fact)
                if fact.record_seq == observation.record_seq
                    && fact.session_time == observation.session_time
                    && fact.kind == "packet")
        {
            return Err(EvidenceError::Semantic("committed CSI observation is incompatible"));
        }
    }
    if !snapshot.observations.windows(2).all(|pair| pair[0].record_seq < pair[1].record_seq) {
        return Err(EvidenceError::Semantic("committed CSI observation order is incompatible"));
    }
    for relationship in &snapshot.relationships {
        let source_index = usize::try_from(relationship.source_record_seq)
            .map_err(|_| EvidenceError::Semantic("relationship source binding is incompatible"))?;
        let source = snapshot.facts.get(source_index);
        let creator = snapshot.commits.get(source_index);
        let change_valid = match (
            relationship.change_previous.as_ref(),
            relationship.change_current.as_ref(),
            relationship.changed_at,
        ) {
            (None, None, None) => true,
            (Some(previous), Some(current), Some(changed_at)) => {
                valid_evidence_knowledge(previous)
                    && valid_evidence_knowledge(current)
                    && previous != current
                    && current == &relationship.knowledge
                    && changed_at <= relationship.result_time
            }
            _ => false,
        };
        if crate::domain::RadioLinkId::new(relationship.link.clone()).is_err()
            || !is_hex_64(&relationship.profile)
            || !valid_evidence_knowledge(&relationship.knowledge)
            || !change_valid
            || !matches!(source, Some(fact) if fact.record_seq == relationship.source_record_seq)
            || !matches!(creator, Some(commit)
                if commit.record_seq == relationship.source_record_seq
                    && commit.commit_seq == relationship.creator_commit_seq)
        {
            return Err(EvidenceError::Semantic("relationship binding is incompatible"));
        }
    }
    Ok(())
}

pub(super) fn valid_evidence_knowledge(knowledge: &crate::store::EvidenceKnowledge) -> bool {
    match knowledge {
        crate::store::EvidenceKnowledge::Known { value } => {
            matches!(value.as_str(), "stable" | "changing")
        }
        crate::store::EvidenceKnowledge::Unknown { reason } => matches!(
            reason.as_str(),
            "baseline_missing"
                | "baseline_learning"
                | "insufficient_coverage"
                | "low_quality"
                | "ambiguous_evidence"
                | "time_uncertain"
                | "missing_data"
                | "profile_mismatch"
                | "stale"
                | "frozen"
                | "inactive"
                | "non_finite"
        ),
    }
}

pub(super) fn validate_formal_run_sequence(
    snapshot: &crate::store::EvidenceStoreSnapshot,
    selection: &Selection,
) -> Result<(), EvidenceError> {
    let relationship = selected_relationship_from_selection(
        snapshot,
        selection,
        "formal relationship subject is absent",
    )?;
    let commands = snapshot
        .facts
        .iter()
        .filter_map(|fact| {
            fact.command.as_ref().and_then(|command| {
                (command.link == relationship.link && command.profile == relationship.profile)
                    .then_some((fact.record_seq, command))
            })
        })
        .collect::<Vec<_>>();
    let [(begin_record, begin), (commit_record, commit)] = commands.as_slice() else {
        return Err(EvidenceError::Semantic(
            "formal BeginLearning/Commit sequence is incompatible",
        ));
    };
    let learning_observations = snapshot
        .observations
        .iter()
        .filter(|observation| {
            observation.link == relationship.link
                && observation.profile == relationship.profile
                && observation.record_seq > *begin_record
                && observation.record_seq < *commit_record
        })
        .collect::<Vec<_>>();
    let mut previous_window_end = *begin_record;
    let eligible_learning_windows = snapshot
        .facts
        .iter()
        .filter(|fact| {
            fact.kind == "timeline_advance"
                && fact.record_seq > *begin_record
                && fact.record_seq < *commit_record
        })
        .filter(|advance| {
            let has_selected_csi = learning_observations.iter().any(|observation| {
                observation.record_seq > previous_window_end
                    && observation.record_seq < advance.record_seq
            });
            previous_window_end = advance.record_seq;
            has_selected_csi
        })
        .count();
    let baseline = snapshot
        .baselines
        .iter()
        .find(|baseline| {
            baseline.link == relationship.link && baseline.profile == relationship.profile
        })
        .ok_or(EvidenceError::Semantic("formal complete baseline is absent"))?;
    let baseline_bytes = decode_hex(&baseline.state_cbor)
        .ok_or(EvidenceError::Semantic("formal complete baseline encoding is incompatible"))?;
    let baseline_state = crate::session::decode_baseline_state(&baseline_bytes).map_err(|_| {
        EvidenceError::Semantic("formal complete baseline encoding is incompatible")
    })?;
    let active_proves_mature_learning =
        matches!(baseline_state.lifecycle(), crate::domain::world::BaselineLifecycle::Active)
            && !baseline_state.active().is_empty()
            && baseline_state.active().values().all(|coordinate| coordinate.count() >= 10)
            && baseline_state.session_last_eligible_at().is_some();
    let relationship_source = snapshot
        .facts
        .get(usize::try_from(relationship.source_record_seq).map_err(|_| {
            EvidenceError::Semantic("formal relationship source record is incompatible")
        })?)
        .ok_or(EvidenceError::Semantic("formal relationship source record is absent"))?;
    if begin.command != "begin_learning"
        || commit.command != "commit"
        || begin.link != relationship.link
        || commit.link != relationship.link
        || begin.profile != relationship.profile
        || commit.profile != relationship.profile
        || begin_record >= commit_record
    {
        return Err(EvidenceError::Semantic(
            "formal BeginLearning/Commit sequence is incompatible",
        ));
    }
    if learning_observations.len() < 10 || eligible_learning_windows < 10 {
        return Err(EvidenceError::Semantic(
            "formal learning interval has fewer than ten CSI-backed eligible windows",
        ));
    }
    if !active_proves_mature_learning {
        return Err(EvidenceError::Semantic("formal committed baseline is not mature and Active"));
    }
    if relationship.source_record_seq <= *commit_record
        || !matches!(relationship_source.kind.as_str(), "packet" | "timeline_advance")
        || !selected_observation_at_or_immediately_before(
            snapshot,
            selection,
            relationship.source_record_seq,
        )
        || !matches!(
            &relationship.knowledge,
            crate::store::EvidenceKnowledge::Known { value } if value == "stable"
        )
    {
        return Err(EvidenceError::Semantic("formal post-Commit Stable result is not CSI-backed"));
    }
    Ok(())
}

pub(super) fn selected_observation_at(
    snapshot: &crate::store::EvidenceStoreSnapshot,
    selection: &Selection,
    record_seq: u64,
) -> bool {
    snapshot.observations.iter().any(|observation| {
        observation.record_seq == record_seq
            && observation.link == selection.link
            && observation.profile == selection.profile
    })
}

pub(super) fn selected_observation_at_or_immediately_before(
    snapshot: &crate::store::EvidenceStoreSnapshot,
    selection: &Selection,
    source_record_seq: u64,
) -> bool {
    selected_observation_at(snapshot, selection, source_record_seq)
        || source_record_seq
            .checked_sub(1)
            .is_some_and(|record_seq| selected_observation_at(snapshot, selection, record_seq))
}

pub(super) fn command_body_sha256(
    command: &crate::store::EvidenceBaselineCommand,
) -> Option<String> {
    let profile: [u8; 32] = decode_hex(&command.profile)?.try_into().ok()?;
    let link = crate::domain::RadioLinkId::new(command.link.clone()).ok()?;
    let command = match command.command.as_str() {
        "begin_learning" => crate::domain::world::BaselineCommand::BeginLearning,
        "commit" => crate::domain::world::BaselineCommand::Commit,
        _ => return None,
    };
    let targeted = crate::domain::world::TargetedBaselineCommand::new(
        crate::domain::identity::LinkProfileKey::new(
            link,
            crate::domain::csi::CaptureProfileId::from_bytes(profile),
        ),
        command,
    );
    let body = crate::session::encode_record_body(
        &crate::session::SessionRecordKind::BaselineCommand(targeted),
    )
    .ok()?;
    Some(sha256(&body))
}
