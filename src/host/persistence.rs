//! Sole-writer transaction A and durable replay-state persistence.

use super::*;
use crate::measurement::{
    AssemblyCloseReason, AssemblyKey, AssociationUncertainty, ChannelIdentity, EventIdentity,
    EvidenceQuality, FragmentBytes, FragmentFact, FragmentPosition, MeasurementAssembler,
    MeasurementContext, NativeEventIdentity, ProfileIdentity, QualificationRelation, RadioIdentity,
    RetransmissionIdentity, TransmitterIdentity,
};
use crate::native_frame::{
    LTF_BLOCK_BYTES, LtfBlock, LtfKind, S3BandwidthKind, S3PhyKind, S3SecondaryKind,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeRoutePin {
    sensor: SensorId,
    source_mac: SourceMac,
    channel: ChannelPolicy,
    radio: RadioRouteFacts,
    firmware_build: FirmwareBuildIdentity,
    capability: CapabilityIdentity,
}

struct StoredNativeRoutePin {
    sensor: String,
    source_mac: Vec<u8>,
    channel: i64,
    secondary: i64,
    phy: i64,
    bandwidth: i64,
    stbc: i64,
    rate: i64,
    mcs: i64,
    rx_antenna: i64,
    firmware_build: Vec<u8>,
    capability: Vec<u8>,
}

impl NativeRoutePin {
    fn from_route(route: &NativeFrameRoute) -> Self {
        let decoded = route.decoded();
        Self {
            sensor: decoded.sensor().clone(),
            source_mac: decoded.source_mac(),
            channel: decoded.channel(),
            radio: decoded.radio(),
            firmware_build: decoded.firmware_build(),
            capability: decoded.capability(),
        }
    }
}

pub(super) fn writer_loop(
    config: WriterConfig,
    ingress: mpsc::Receiver<AdmittedDatagram>,
    controls: mpsc::Receiver<ControlCommand>,
    control_bytes: &AtomicU64,
    overflow: &OverflowSummary,
    rejections: &Mutex<VecDeque<RejectedDatagram>>,
    ready: mpsc::SyncSender<Result<(), HostError>>,
) -> Result<(), HostError> {
    let startup = match load_replay_states_from_path(
        config.replay_snapshot.database_path(),
        &config.database_path,
        &config.deployment,
        &config.routes,
    ) {
        Ok(startup) => startup,
        Err(error) => {
            let _ = ready.send(Err(error));
            return Ok(());
        }
    };
    let mut connection = match Connection::open_with_flags(
        &config.database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(connection) => connection,
        Err(error) => {
            let error = HostError::database_at(&config.database_path, error);
            let _ = ready.send(Err(error));
            return Ok(());
        }
    };
    if startup.provision
        && let Err(error) =
            provision_replay_states(&mut connection, &config.routes, &startup.states)
    {
        let error = HostError::database_at(&config.database_path, error);
        let _ = ready.send(Err(error));
        return Ok(());
    }
    if let Err(error) =
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
    {
        let error = HostError::database_at(&config.database_path, error);
        let _ = ready.send(Err(error));
        return Ok(());
    }
    let mut replay = startup.states;
    let mut assembler = MeasurementAssembler::new(config.measurement_limits);
    restore_open_fragments(&connection, &config.database_path, &mut assembler)?;
    if ready.send(Ok(())).is_err() {
        return Ok(());
    }

    loop {
        persist_overflow(&mut connection, &config.database_path, overflow, config.clock.as_ref())?;
        // A fixed batch guarantees rotation to ingress even while controls refill concurrently.
        for _ in 0..CONTROL_BATCH_PER_TURN {
            match controls.try_recv() {
                Ok(command) => {
                    control_bytes.fetch_sub(command.queued_bytes(), Ordering::AcqRel);
                    process_control(
                        &mut connection,
                        &config.database_path,
                        &mut assembler,
                        command,
                    )?;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        match ingress.recv_timeout(SOCKET_POLL_INTERVAL) {
            Ok(item) => persist_admitted(
                &mut connection,
                &config.database_path,
                &config.routes,
                &mut replay,
                &mut assembler,
                rejections,
                item,
            )?,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    persist_overflow(&mut connection, &config.database_path, overflow, config.clock.as_ref())?;
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|error| HostError::database_at(&config.database_path, error))?;
    Ok(())
}

fn persist_qualification(
    connection: &Connection,
    path: &Path,
    relation: &QualificationRelation,
) -> Result<(), HostError> {
    let validity = relation.common();
    let (kind, details) = encode_relation_details(relation)?;
    connection
        .execute(
            "INSERT INTO qualification_relations (
                 kind, provenance, sensor, device_id, key_epoch, boot_generation,
                 error_bound, error_unit, valid_from_tick, valid_until_tick, epoch, details
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                kind,
                validity.provenance(),
                validity.source().sensor().as_str(),
                validity.source().device().get().to_be_bytes(),
                validity.source().key_epoch().get().to_be_bytes(),
                validity.source().boot().get().to_be_bytes(),
                validity.error().value().to_be_bytes(),
                encode_error_unit(validity.error().unit()),
                validity.validity().start().get().to_be_bytes(),
                validity.validity().end().get().to_be_bytes(),
                validity.epoch().get().to_be_bytes(),
                details,
            ],
        )
        .map_err(|error| HostError::database_at(path, error))?;
    Ok(())
}

fn process_control(
    connection: &mut Connection,
    path: &Path,
    assembler: &mut MeasurementAssembler,
    command: ControlCommand,
) -> Result<(), HostError> {
    match command {
        ControlCommand::Qualification { relation, reply, .. } => {
            let result = persist_qualification(connection, path, &relation);
            let failed = result.is_err();
            let _ = reply.send(result);
            if failed {
                return Err(HostError::message_at(
                    "persist qualification",
                    path,
                    "qualification persistence failed",
                ));
            }
        }
        ControlCommand::Fragment { fragment, arrival, reply, .. } => {
            let result =
                persist_measurement_fragment(connection, path, assembler, fragment, arrival);
            let failed = result.is_err();
            let _ = reply.send(result);
            if failed {
                return Err(HostError::message_at(
                    "persist measurement fragment",
                    path,
                    "measurement persistence failed",
                ));
            }
        }
        ControlCommand::Expire { source, now, reply, .. } => {
            let result = persist_expired(connection, path, assembler, &source, now);
            let failed = result.is_err();
            let _ = reply.send(result);
            if failed {
                return Err(HostError::message_at(
                    "expire measurements",
                    path,
                    "measurement expiry persistence failed",
                ));
            }
        }
    }
    Ok(())
}

fn encode_error_unit(unit: crate::measurement::ErrorUnit) -> &'static str {
    use crate::measurement::ErrorUnit;
    match unit {
        ErrorUnit::Nanoseconds => "nanoseconds",
        ErrorUnit::Milliradians => "milliradians",
        ErrorUnit::Millimetres => "millimetres",
        ErrorUnit::PartsPerMillion => "parts_per_million",
    }
}

fn push_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), HostError> {
    let length = u16::try_from(value.len()).map_err(|_| {
        HostError::message_during("encode qualification", "qualification label is too long")
    })?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_relation_details(
    relation: &QualificationRelation,
) -> Result<(&'static str, Vec<u8>), HostError> {
    let mut bytes = Vec::new();
    let kind = match relation {
        QualificationRelation::Time(value) => {
            push_text(&mut bytes, value.source_clock())?;
            push_text(&mut bytes, value.target_clock())?;
            bytes.extend_from_slice(&value.fit().bytes());
            "time"
        }
        QualificationRelation::Phase(value) => {
            bytes.extend_from_slice(&value.reference().bytes());
            bytes.extend_from_slice(&value.coherence().start().get().to_be_bytes());
            bytes.extend_from_slice(&value.coherence().end().get().to_be_bytes());
            "phase"
        }
        QualificationRelation::Port(value) => {
            bytes.extend_from_slice(
                &u16::try_from(value.entries().len())
                    .expect("port mapping constructor bounds the count")
                    .to_be_bytes(),
            );
            for entry in value.entries() {
                bytes.extend_from_slice(&entry.tx_stream().to_be_bytes());
                bytes.extend_from_slice(&entry.rx_chain().to_be_bytes());
                match entry.tx_antenna() {
                    Some(antenna) => {
                        bytes.push(1);
                        bytes.extend_from_slice(&antenna.to_be_bytes());
                    }
                    None => bytes.extend_from_slice(&[0, 0, 0]),
                }
                bytes.extend_from_slice(&entry.rx_antenna().to_be_bytes());
            }
            "port"
        }
        QualificationRelation::Geometry(value) => {
            push_text(&mut bytes, value.source_frame())?;
            push_text(&mut bytes, value.target_frame())?;
            for component in value.pose().components() {
                bytes.extend_from_slice(&component.to_be_bytes());
            }
            "geometry"
        }
    };
    Ok((kind, bytes))
}

fn persist_measurement_fragment(
    connection: &mut Connection,
    path: &Path,
    assembler: &mut MeasurementAssembler,
    fragment: MeasurementFragment,
    arrival: SourceTick,
) -> Result<Vec<AssemblyClose>, HostError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| HostError::database_at(path, error))?;
    let closes = persist_fragment_in_transaction(&transaction, path, assembler, fragment, arrival)?;
    transaction.commit().map_err(|error| HostError::database_at(path, error))?;
    Ok(closes)
}

fn persist_fragment_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    path: &Path,
    assembler: &mut MeasurementAssembler,
    fragment: MeasurementFragment,
    arrival: SourceTick,
) -> Result<Vec<AssemblyClose>, HostError> {
    insert_measurement_fragment(transaction, path, &fragment, arrival)?;
    let fragment_id = transaction.last_insert_rowid();
    let trigger_key = fragment.key().clone();
    let closes = if has_durable_primary_close(transaction, path, fragment.key())? {
        vec![assembler.late(fragment, arrival)]
    } else {
        assembler.ingest(fragment, arrival).map_err(|_| measurement_persistence_error(path))?
    };
    for close in &closes {
        let disposition = match close.reason() {
            AssemblyCloseReason::LateFragment => "late",
            AssemblyCloseReason::DuplicateFragment => "duplicate",
            AssemblyCloseReason::ResourceLimit => "resource",
            AssemblyCloseReason::ConflictingDuplicate => "conflict",
            _ => "closed",
        };
        if matches!(
            close.reason(),
            AssemblyCloseReason::LateFragment
                | AssemblyCloseReason::DuplicateFragment
                | AssemblyCloseReason::ResourceLimit
        ) {
            transaction
                .execute(
                    "UPDATE measurement_fragments SET disposition = ?1 WHERE fragment_id = ?2",
                    params![disposition, fragment_id],
                )
                .map_err(|error| HostError::database_at(path, error))?;
        } else {
            mark_open_fragments(transaction, path, close.key(), disposition)?;
        }
        let trigger = (close.key() == &trigger_key
            && close.reason() != AssemblyCloseReason::WaitLimit)
            .then_some(fragment_id);
        persist_close(transaction, path, close, trigger)?;
    }
    Ok(closes)
}

fn identity_from_parts(label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(label);
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

fn persist_expired(
    connection: &mut Connection,
    path: &Path,
    assembler: &mut MeasurementAssembler,
    source: &SourceInstance,
    now: SourceTick,
) -> Result<Vec<AssemblyClose>, HostError> {
    let closes = assembler.expire(source, now);
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| HostError::database_at(path, error))?;
    for close in &closes {
        mark_open_fragments(&transaction, path, close.key(), "closed")?;
        persist_close(&transaction, path, close, None)?;
    }
    transaction.commit().map_err(|error| HostError::database_at(path, error))?;
    Ok(closes)
}

fn insert_measurement_fragment(
    transaction: &rusqlite::Transaction<'_>,
    path: &Path,
    fragment: &MeasurementFragment,
    arrival: SourceTick,
) -> Result<(), HostError> {
    let key = fragment.key();
    let source = key.source();
    let event = key.event();
    let context = key.context();
    transaction
        .execute(
            "INSERT INTO measurement_fragments (
             sensor, device_id, key_epoch, boot_generation, transmitter, native_event,
             retransmission, profile, radio, channel, ordinal, expected_fragments,
             fact_digest, payload_bytes, quality, arrival_tick, disposition
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14, ?15, ?16, 'open')",
            params![
                source.sensor().as_str(),
                source.device().get().to_be_bytes(),
                source.key_epoch().get().to_be_bytes(),
                source.boot().get().to_be_bytes(),
                event.transmitter().bytes(),
                event.native_event().bytes(),
                event.retransmission().map(RetransmissionIdentity::bytes),
                context.profile().bytes(),
                context.radio().bytes(),
                context.channel().bytes(),
                fragment.position().ordinal(),
                fragment.position().expected(),
                fragment.fact().digest(),
                fragment.fact().bytes().get(),
                encode_quality(fragment.fact().quality()),
                arrival.get().to_be_bytes(),
            ],
        )
        .map_err(|error| HostError::database_at(path, error))?;
    Ok(())
}

fn has_durable_primary_close(
    transaction: &rusqlite::Transaction<'_>,
    path: &Path,
    key: &AssemblyKey,
) -> Result<bool, HostError> {
    let source = key.source();
    let event = key.event();
    let context = key.context();
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM measurement_assemblies
         WHERE sensor=?1 AND device_id=?2 AND key_epoch=?3 AND boot_generation=?4
           AND transmitter=?5 AND native_event=?6 AND retransmission IS ?7
           AND profile=?8 AND radio=?9 AND channel=?10
           AND close_reason NOT IN ('late_fragment','duplicate_fragment'))",
            params![
                source.sensor().as_str(),
                source.device().get().to_be_bytes(),
                source.key_epoch().get().to_be_bytes(),
                source.boot().get().to_be_bytes(),
                event.transmitter().bytes(),
                event.native_event().bytes(),
                event.retransmission().map(RetransmissionIdentity::bytes),
                context.profile().bytes(),
                context.radio().bytes(),
                context.channel().bytes()
            ],
            |row| row.get(0),
        )
        .map_err(|error| HostError::database_at(path, error))
}

fn mark_open_fragments(
    transaction: &rusqlite::Transaction<'_>,
    path: &Path,
    key: &AssemblyKey,
    disposition: &str,
) -> Result<(), HostError> {
    let source = key.source();
    let event = key.event();
    let context = key.context();
    transaction
        .execute(
            "UPDATE measurement_fragments SET disposition=?1
         WHERE sensor=?2 AND device_id=?3 AND key_epoch=?4 AND boot_generation=?5
           AND transmitter=?6 AND native_event=?7 AND retransmission IS ?8
           AND profile=?9 AND radio=?10 AND channel=?11 AND disposition='open'",
            params![
                disposition,
                source.sensor().as_str(),
                source.device().get().to_be_bytes(),
                source.key_epoch().get().to_be_bytes(),
                source.boot().get().to_be_bytes(),
                event.transmitter().bytes(),
                event.native_event().bytes(),
                event.retransmission().map(RetransmissionIdentity::bytes),
                context.profile().bytes(),
                context.radio().bytes(),
                context.channel().bytes()
            ],
        )
        .map_err(|error| HostError::database_at(path, error))?;
    Ok(())
}

fn persist_close(
    transaction: &rusqlite::Transaction<'_>,
    path: &Path,
    close: &AssemblyClose,
    trigger_fragment_id: Option<i64>,
) -> Result<(), HostError> {
    let key = close.key();
    let source = key.source();
    let event = key.event();
    let context = key.context();
    let metrics = close.metrics();
    let limits = metrics.limits();
    let missing = close
        .missing_ordinals()
        .iter()
        .flat_map(|ordinal| ordinal.to_be_bytes())
        .collect::<Vec<_>>();
    transaction
        .execute(
            "INSERT INTO measurement_assemblies (
             trigger_fragment_id, sensor, device_id, key_epoch, boot_generation, transmitter, native_event,
             retransmission, profile, radio, channel, expected_fragments, missing_ordinals,
             close_reason, association_uncertainty, total_bytes, first_tick, close_tick,
             limit_open, limit_fragments, limit_bytes, limit_wait, attempted_fragments,
             attempted_bytes, open_assemblies
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,
                   ?16,?17,?18,?19,?20,?21,?22,?23,?24,?25)",
            params![
                trigger_fragment_id,
                source.sensor().as_str(),
                source.device().get().to_be_bytes(),
                source.key_epoch().get().to_be_bytes(),
                source.boot().get().to_be_bytes(),
                event.transmitter().bytes(),
                event.native_event().bytes(),
                event.retransmission().map(RetransmissionIdentity::bytes),
                context.profile().bytes(),
                context.radio().bytes(),
                context.channel().bytes(),
                close.expected_fragments(),
                missing,
                encode_close_reason(close.reason()),
                encode_uncertainty(close.uncertainty()),
                close.total_bytes(),
                metrics.first_tick().get().to_be_bytes(),
                metrics.close_tick().get().to_be_bytes(),
                limits.capacity().open(),
                limits.capacity().fragments(),
                limits.capacity().bytes(),
                limits.wait().get().to_be_bytes(),
                metrics.attempted_fragments(),
                metrics.attempted_bytes(),
                metrics.open_assemblies(),
            ],
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let id = transaction.last_insert_rowid();
    for member in close.members() {
        transaction.execute(
            "INSERT INTO measurement_members (assembly_id,ordinal,fact_digest,payload_bytes,quality) VALUES (?1,?2,?3,?4,?5)",
            params![id, member.ordinal(), member.fact_digest(), member.payload_bytes(), encode_quality(member.quality())],
        ).map_err(|error| HostError::database_at(path, error))?;
    }
    Ok(())
}

fn encode_quality(value: EvidenceQuality) -> &'static str {
    match value {
        EvidenceQuality::Captured => "captured",
        EvidenceQuality::NotCaptured => "not_captured",
        EvidenceQuality::Lost => "lost",
        EvidenceQuality::Invalid => "invalid",
        EvidenceQuality::Interpolated => "interpolated",
        EvidenceQuality::TrainingMasked => "training_masked",
    }
}

fn encode_close_reason(value: AssemblyCloseReason) -> &'static str {
    match value {
        AssemblyCloseReason::Complete => "complete",
        AssemblyCloseReason::WaitLimit => "wait_limit",
        AssemblyCloseReason::CountLimit => "count_limit",
        AssemblyCloseReason::ByteLimit => "byte_limit",
        AssemblyCloseReason::ResourceLimit => "resource_limit",
        AssemblyCloseReason::LateFragment => "late_fragment",
        AssemblyCloseReason::DuplicateFragment => "duplicate_fragment",
        AssemblyCloseReason::ConflictingDuplicate => "conflicting_duplicate",
    }
}

fn encode_uncertainty(value: AssociationUncertainty) -> &'static str {
    match value {
        AssociationUncertainty::ExactNativeIdentity => "exact_native_identity",
        AssociationUncertainty::LateAfterClose => "late_after_close",
        AssociationUncertainty::ConflictingFacts => "conflicting_facts",
    }
}

fn measurement_persistence_error(path: &Path) -> HostError {
    HostError::message_at("persist measurement", path, "measurement assembly invariant failed")
}

#[derive(Debug)]
struct StoredOpenFragment {
    sensor: String,
    device: Vec<u8>,
    key_epoch: Vec<u8>,
    boot: Vec<u8>,
    transmitter: Vec<u8>,
    event: Vec<u8>,
    retransmission: Option<Vec<u8>>,
    profile: Vec<u8>,
    radio: Vec<u8>,
    channel: Vec<u8>,
    ordinal: u16,
    expected: u16,
    digest: Vec<u8>,
    bytes: u32,
    quality: String,
    arrival: Vec<u8>,
}

fn restore_open_fragments(
    connection: &Connection,
    path: &Path,
    assembler: &mut MeasurementAssembler,
) -> Result<(), HostError> {
    let mut statement = connection
        .prepare(
            "SELECT sensor,device_id,key_epoch,boot_generation,transmitter,native_event,
                retransmission,profile,radio,channel,ordinal,expected_fragments,
                fact_digest,payload_bytes,quality,arrival_tick
         FROM measurement_fragments WHERE disposition='open' ORDER BY fragment_id",
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let rows = statement
        .query_map([], |row| {
            Ok(StoredOpenFragment {
                sensor: row.get(0)?,
                device: row.get(1)?,
                key_epoch: row.get(2)?,
                boot: row.get(3)?,
                transmitter: row.get(4)?,
                event: row.get(5)?,
                retransmission: row.get(6)?,
                profile: row.get(7)?,
                radio: row.get(8)?,
                channel: row.get(9)?,
                ordinal: row.get(10)?,
                expected: row.get(11)?,
                digest: row.get(12)?,
                bytes: row.get(13)?,
                quality: row.get(14)?,
                arrival: row.get(15)?,
            })
        })
        .map_err(|error| HostError::database_at(path, error))?;
    for row in rows {
        let row = row.map_err(|error| HostError::database_at(path, error))?;
        let source = SourceInstance::new(
            SensorId::try_from(row.sensor.as_str())
                .map_err(|_| measurement_persistence_error(path))?,
            DeviceId::new(decode_fixed_u64(path, row.device)?),
            KeyEpoch::new(decode_fixed_u16(path, row.key_epoch)?)
                .ok_or_else(|| measurement_persistence_error(path))?,
            BootGeneration::new(decode_fixed_u32(path, row.boot)?)
                .ok_or_else(|| measurement_persistence_error(path))?,
        );
        let key = AssemblyKey::new(
            source,
            EventIdentity::new(
                TransmitterIdentity::new(decode_digest(path, row.transmitter)?),
                NativeEventIdentity::new(decode_digest(path, row.event)?),
                row.retransmission
                    .map(|value| decode_digest(path, value).map(RetransmissionIdentity::new))
                    .transpose()?,
            ),
            MeasurementContext::new(
                ProfileIdentity::new(decode_digest(path, row.profile)?),
                RadioIdentity::new(decode_digest(path, row.radio)?),
                ChannelIdentity::new(decode_digest(path, row.channel)?),
            ),
        );
        let fragment = MeasurementFragment::new(
            key,
            FragmentPosition::new(row.ordinal, row.expected)
                .map_err(|_| measurement_persistence_error(path))?,
            FragmentFact::new(
                decode_digest(path, row.digest)?,
                FragmentBytes::new(row.bytes).map_err(|_| measurement_persistence_error(path))?,
                decode_stored_quality(path, &row.quality)?,
            ),
        );
        assembler
            .restore(fragment, SourceTick::new(decode_fixed_u64(path, row.arrival)?))
            .map_err(|_| measurement_persistence_error(path))?;
    }
    Ok(())
}

fn decode_digest(path: &Path, value: Vec<u8>) -> Result<[u8; 32], HostError> {
    value.try_into().map_err(|_| measurement_persistence_error(path))
}

fn decode_fixed_u64(path: &Path, value: Vec<u8>) -> Result<u64, HostError> {
    Ok(u64::from_be_bytes(value.try_into().map_err(|_| measurement_persistence_error(path))?))
}

fn decode_fixed_u32(path: &Path, value: Vec<u8>) -> Result<u32, HostError> {
    Ok(u32::from_be_bytes(value.try_into().map_err(|_| measurement_persistence_error(path))?))
}

fn decode_fixed_u16(path: &Path, value: Vec<u8>) -> Result<u16, HostError> {
    Ok(u16::from_be_bytes(value.try_into().map_err(|_| measurement_persistence_error(path))?))
}

fn decode_stored_quality(path: &Path, value: &str) -> Result<EvidenceQuality, HostError> {
    match value {
        "captured" => Ok(EvidenceQuality::Captured),
        "not_captured" => Ok(EvidenceQuality::NotCaptured),
        "lost" => Ok(EvidenceQuality::Lost),
        "invalid" => Ok(EvidenceQuality::Invalid),
        "interpolated" => Ok(EvidenceQuality::Interpolated),
        "training_masked" => Ok(EvidenceQuality::TrainingMasked),
        _ => Err(measurement_persistence_error(path)),
    }
}

fn load_replay_states_from_path(
    snapshot_path: &Path,
    store_path: &Path,
    deployment: &DeploymentId,
    routes: &[NativeFrameRoute],
) -> Result<ReplayStartup, HostError> {
    let connection = Connection::open_with_flags(
        snapshot_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| HostError::database_at(store_path, error))?;
    load_replay_states(&connection, store_path, deployment, routes)
}

fn load_replay_states(
    connection: &Connection,
    path: &Path,
    deployment: &DeploymentId,
    routes: &[NativeFrameRoute],
) -> Result<ReplayStartup, HostError> {
    let configured: u8 = connection
        .query_row(
            "SELECT admission_configured FROM store_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let row_count: usize = connection
        .query_row("SELECT count(*) FROM replay_windows", [], |row| row.get(0))
        .map_err(|error| HostError::database_at(path, error))?;
    let pin_count: usize = connection
        .query_row("SELECT count(*) FROM native_route_pins", [], |row| row.get(0))
        .map_err(|error| HostError::database_at(path, error))?;
    if configured == 0 && row_count != 0 {
        return Err(HostError::message_at(
            "validate retained replay state",
            path,
            "unprovisioned Store contains replay state",
        ));
    }
    if configured == 0 && pin_count != 0 {
        return Err(HostError::message_at(
            "validate retained native route identity",
            path,
            "unprovisioned Store contains native route identity",
        ));
    }
    if configured == 1 && row_count != routes.len() {
        return Err(HostError::message_at(
            "validate retained replay state",
            path,
            "persisted replay route set does not match configuration",
        ));
    }
    if configured > 1 {
        return Err(HostError::message_at(
            "validate retained replay state",
            path,
            "persisted admission configuration marker is invalid",
        ));
    }
    if configured == 1 {
        validate_native_route_pins(connection, path, routes)?;
    }
    let states = routes
        .iter()
        .map(|route| {
            let identity = derive_replay_window_identity(
                deployment.as_str(),
                route.device_id.get(),
                route.key_epoch.get(),
                &route.key,
            )
            .map_err(|error| HostError::replay_identity(path, error))?;
            let persisted: Option<(Vec<u8>, u16, Vec<u8>)> = connection
                .query_row(
                    "SELECT identity, window_packets, state FROM replay_windows
                     WHERE device_id = ?1 AND key_epoch = ?2",
                    params![
                        route.device_id.get().to_be_bytes(),
                        route.key_epoch.get().to_be_bytes()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|error| HostError::database_at(path, error))?;
            let admission = match persisted {
                Some((stored_identity, stored_window, state)) => {
                    if configured == 0
                        || stored_identity.as_slice() != identity.as_bytes()
                        || stored_window != route.limits.replay_window_packets.get()
                    {
                        return Err(HostError::message_at(
                            "validate retained replay state",
                            path,
                            "persisted replay identity or window does not match configuration",
                        ));
                    }
                    let admission = ReplayAdmission::decode_state(&state)
                        .map_err(|error| HostError::replay_state(path, error))?;
                    if admission.window_packets() != stored_window {
                        return Err(HostError::message_at(
                            "validate retained replay state",
                            path,
                            "persisted replay state window does not match configuration",
                        ));
                    }
                    admission
                }
                None if configured == 0 => {
                    ReplayAdmission::new(route.limits.replay_window_packets.get())
                        .map_err(|error| HostError::replay_state(path, error))?
                }
                None => {
                    return Err(HostError::message_at(
                        "validate retained replay state",
                        path,
                        "configured replay route is missing",
                    ));
                }
            };
            Ok(ReplayWriterState { identity: *identity.as_bytes(), admission })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ReplayStartup { states, provision: configured == 0 })
}

pub(super) fn validate_native_route_pins(
    connection: &Connection,
    path: &Path,
    routes: &[NativeFrameRoute],
) -> Result<(), HostError> {
    let pin_count: usize = connection
        .query_row("SELECT count(*) FROM native_route_pins", [], |row| row.get(0))
        .map_err(|error| HostError::database_at(path, error))?;
    if pin_count != routes.len() {
        return Err(HostError::message_at(
            "validate retained native route identity",
            path,
            "persisted native route identity set does not match configuration",
        ));
    }
    for route in routes {
        let Some(stored) = load_native_route_pin(connection, path, route)? else {
            return Err(HostError::message_at(
                "validate retained native route identity",
                path,
                "configured native route is missing persisted identity",
            ));
        };
        if stored != NativeRoutePin::from_route(route) {
            return Err(HostError::message_at(
                "validate retained native route identity",
                path,
                "persisted native route identity does not match configuration",
            ));
        }
    }
    Ok(())
}

fn provision_replay_states(
    connection: &mut Connection,
    routes: &[NativeFrameRoute],
    states: &[ReplayWriterState],
) -> Result<(), rusqlite::Error> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (route, state) in routes.iter().zip(states) {
        let decoded = route.decoded();
        transaction.execute(
            "INSERT INTO native_route_pins (
                 device_id, key_epoch, sensor_id, source_mac, channel,
                 secondary, phy, bandwidth, stbc, rate, mcs, rx_antenna,
                 firmware_build_digest, capability_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                route.device_id.get().to_be_bytes(),
                route.key_epoch.get().to_be_bytes(),
                decoded.sensor().as_str(),
                decoded.source_mac().into_bytes(),
                decoded.channel().get(),
                secondary_byte(decoded.radio().secondary()),
                phy_byte(decoded.radio().phy()),
                bandwidth_byte(decoded.radio().bandwidth()),
                u8::from(decoded.radio().stbc()),
                decoded.radio().rate(),
                decoded.radio().mcs(),
                decoded.radio().rx_antenna(),
                decoded.firmware_build().into_bytes(),
                decoded.capability().into_bytes(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO replay_windows
                 (device_id, key_epoch, identity, window_packets, state)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                route.device_id.get().to_be_bytes(),
                route.key_epoch.get().to_be_bytes(),
                state.identity,
                route.limits.replay_window_packets.get(),
                state.admission.encode_state(),
            ],
        )?;
    }
    transaction
        .execute("UPDATE store_identity SET admission_configured = 1 WHERE singleton = 1", [])?;
    transaction.commit()
}

fn load_native_route_pin(
    connection: &Connection,
    path: &Path,
    route: &NativeFrameRoute,
) -> Result<Option<NativeRoutePin>, HostError> {
    let stored: Option<StoredNativeRoutePin> = connection
        .query_row(
            "SELECT sensor_id, source_mac, channel, secondary, phy, bandwidth,
                        stbc, rate, mcs, rx_antenna, firmware_build_digest, capability_digest
                 FROM native_route_pins
                 WHERE device_id = ?1 AND key_epoch = ?2",
            params![route.device_id.get().to_be_bytes(), route.key_epoch.get().to_be_bytes()],
            |row| {
                Ok(StoredNativeRoutePin {
                    sensor: row.get(0)?,
                    source_mac: row.get(1)?,
                    channel: row.get(2)?,
                    secondary: row.get(3)?,
                    phy: row.get(4)?,
                    bandwidth: row.get(5)?,
                    stbc: row.get(6)?,
                    rate: row.get(7)?,
                    mcs: row.get(8)?,
                    rx_antenna: row.get(9)?,
                    firmware_build: row.get(10)?,
                    capability: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(|error| HostError::database_at(path, error))?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let sensor = SensorId::try_from(stored.sensor.as_str()).map_err(|_| {
        HostError::message_at(
            "validate retained native route identity",
            path,
            "persisted native route sensor identity is invalid",
        )
    })?;
    let source_mac = SourceMac::try_from(stored.source_mac.as_slice()).map_err(|_| {
        HostError::message_at(
            "validate retained native route identity",
            path,
            "persisted native route source MAC is invalid",
        )
    })?;
    let channel = ChannelPolicy::try_from(native_route_u8(path, "channel", stored.channel)?)
        .map_err(|_| {
            HostError::message_at(
                "validate retained native route identity",
                path,
                "persisted native route channel is invalid",
            )
        })?;
    let secondary = native_route_secondary(path, stored.secondary)?;
    let phy = native_route_phy(path, stored.phy)?;
    let bandwidth = native_route_bandwidth(path, stored.bandwidth)?;
    let stbc = match stored.stbc {
        0 => false,
        1 => true,
        _ => {
            return Err(HostError::message_at(
                "validate retained native route identity",
                path,
                "persisted native route STBC flag is invalid",
            ));
        }
    };
    let rate = native_route_u8(path, "rate", stored.rate)?;
    let mcs = native_route_u8(path, "MCS", stored.mcs)?;
    let rx_antenna = native_route_u8(path, "receive antenna", stored.rx_antenna)?;
    let firmware_build = FirmwareBuildIdentity::try_from(stored.firmware_build.as_slice())
        .map_err(|_| {
            HostError::message_at(
                "validate retained native route identity",
                path,
                "persisted native route firmware-build identity is invalid",
            )
        })?;
    let capability = CapabilityIdentity::try_from(stored.capability.as_slice()).map_err(|_| {
        HostError::message_at(
            "validate retained native route identity",
            path,
            "persisted native route capability identity is invalid",
        )
    })?;
    Ok(Some(NativeRoutePin {
        sensor,
        source_mac,
        channel,
        radio: RadioRouteFacts { phy, bandwidth, secondary, stbc, rate, mcs, rx_antenna },
        firmware_build,
        capability,
    }))
}

fn native_route_u8(path: &Path, field: &'static str, value: i64) -> Result<u8, HostError> {
    u8::try_from(value).map_err(|_| {
        HostError::message_at(
            "validate retained native route identity",
            path,
            match field {
                "channel" => "persisted native route channel is invalid",
                "rate" => "persisted native route rate is invalid",
                "MCS" => "persisted native route MCS is invalid",
                "receive antenna" => "persisted native route receive antenna is invalid",
                _ => "persisted native route numeric identity is invalid",
            },
        )
    })
}

fn native_route_secondary(path: &Path, value: i64) -> Result<S3SecondaryKind, HostError> {
    match value {
        0 => Ok(S3SecondaryKind::None),
        1 => Ok(S3SecondaryKind::Above),
        2 => Ok(S3SecondaryKind::Below),
        _ => Err(HostError::message_at(
            "validate retained native route identity",
            path,
            "persisted native route secondary-channel identity is invalid",
        )),
    }
}

fn native_route_phy(path: &Path, value: i64) -> Result<S3PhyKind, HostError> {
    match value {
        1 => Ok(S3PhyKind::NonHt),
        2 => Ok(S3PhyKind::Ht),
        _ => Err(HostError::message_at(
            "validate retained native route identity",
            path,
            "persisted native route PHY identity is invalid",
        )),
    }
}

fn native_route_bandwidth(path: &Path, value: i64) -> Result<S3BandwidthKind, HostError> {
    match value {
        1 => Ok(S3BandwidthKind::TwentyMhz),
        2 => Ok(S3BandwidthKind::FortyMhz),
        _ => Err(HostError::message_at(
            "validate retained native route identity",
            path,
            "persisted native route bandwidth identity is invalid",
        )),
    }
}

fn persist_admitted(
    connection: &mut Connection,
    path: &Path,
    routes: &[NativeFrameRoute],
    replay: &mut [ReplayWriterState],
    assembler: &mut MeasurementAssembler,
    rejections: &Mutex<VecDeque<RejectedDatagram>>,
    item: AdmittedDatagram,
) -> Result<(), HostError> {
    let route = &routes[item.route_index];
    let state = &mut replay[item.route_index];
    let mut next = state.admission.clone();
    let previous =
        match (state.admission.boot_generation(), state.admission.maximum_message_sequence()) {
            (Some(boot), Some(sequence)) if boot == item.header.boot_generation() => Some(sequence),
            _ => None,
        };
    if next.admit(item.header.boot_generation(), item.header.message_seq())
        == ReplayDecision::Rejected
    {
        record_rejection(rejections, item.peer, RejectReason::Replay);
        return Ok(());
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| HostError::database_at(path, error))?;
    let digest: [u8; 32] = Sha256::digest(&item.bytes).into();
    transaction
        .execute(
            "INSERT INTO raw_facts (
                 digest, received_utc_ns, peer, device_id, key_epoch,
                 boot_generation, message_sequence, kind, datagram
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                digest,
                item.received_utc_ns,
                item.peer.to_string(),
                item.header.device_id().to_be_bytes(),
                item.header.key_epoch().to_be_bytes(),
                item.header.boot_generation().to_be_bytes(),
                item.header.message_seq().to_be_bytes(),
                item.header.kind_byte(),
                &item.bytes,
            ],
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let fact_id = transaction.last_insert_rowid();
    let semantic_rejection = match decode_authenticated(&item.authenticated) {
        Ok(decoded) => persist_typed_fact(
            &transaction,
            path,
            fact_id,
            digest,
            route,
            &item,
            decoded.message(),
            assembler,
        )?,
        Err(error) => Some(match error {
            crate::native_frame::WireError::UnknownKind { .. } => RejectReason::UnknownKind,
            crate::native_frame::WireError::MalformedBody { .. } => RejectReason::MalformedBody,
            _ => {
                return Err(HostError::message_at(
                    "decode authenticated native-frame",
                    path,
                    "authenticated datagram failed after ingress authentication",
                ));
            }
        }),
    };
    persist_sequence_discontinuity(&transaction, path, previous, &item)?;
    transaction
        .execute(
            "UPDATE replay_windows SET state = ?1
             WHERE device_id = ?2 AND key_epoch = ?3 AND identity = ?4 AND window_packets = ?5",
            params![
                next.encode_state(),
                route.device_id.get().to_be_bytes(),
                route.key_epoch.get().to_be_bytes(),
                state.identity,
                route.limits.replay_window_packets.get(),
            ],
        )
        .map_err(|error| HostError::database_at(path, error))?;
    transaction.commit().map_err(|error| HostError::database_at(path, error))?;
    state.admission = next;
    if let Some(reason) = semantic_rejection {
        record_rejection(rejections, item.peer, reason);
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "transaction-A validation keeps the immutable admitted datagram context explicit"
)]
fn persist_typed_fact(
    transaction: &rusqlite::Transaction<'_>,
    path: &Path,
    fact_id: i64,
    fact_digest: [u8; 32],
    route: &NativeFrameRoute,
    item: &AdmittedDatagram,
    message: &Message,
    assembler: &mut MeasurementAssembler,
) -> Result<Option<RejectReason>, HostError> {
    if let Some(reason) = route.semantic_rejection(message) {
        return Ok(Some(reason));
    }
    match message {
        Message::Capabilities(capability) => {
            if let Some(expected) =
                previous_capability_digest(transaction, path, &item.header, fact_id)?
                && expected != capability.capability_digest()
            {
                return Ok(Some(RejectReason::CapabilityConflict));
            }
            transaction
                .execute(
                    "INSERT INTO native_capability_facts (
                         fact_id, capability_digest, firmware_build_digest,
                         idf_wifi_abi_digest, datagram_budget_bytes
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        fact_id,
                        capability.capability_digest(),
                        capability.descriptor().firmware_build_digest(),
                        capability.descriptor().idf_wifi_abi_digest(),
                        capability.descriptor().datagram_budget_bytes(),
                    ],
                )
                .map_err(|error| HostError::database_at(path, error))?;
            Ok(None)
        }
        Message::CsiData(data) => {
            let Some(expected) =
                previous_capability_digest(transaction, path, &item.header, fact_id)?
            else {
                return Ok(Some(RejectReason::CapabilityUnavailable));
            };
            if expected != data.capability_digest() {
                return Ok(Some(RejectReason::CapabilityConflict));
            }
            if let Some(source_mac) = previous_csi_source(transaction, path, &item.header, fact_id)?
                && source_mac != data.source_mac()
            {
                return Ok(Some(RejectReason::SourceConflict));
            }
            if let Some(channel) = previous_csi_channel(transaction, path, &item.header, fact_id)?
                && channel != data.radio().channel()
            {
                return Ok(Some(RejectReason::RadioConflict));
            }
            let blocks = encode_blocks(data.blocks());
            transaction
                .execute(
                    "INSERT INTO native_csi_facts (
                         fact_id, capability_digest, capture_sequence,
                         driver_rx_timestamp_us, callback_tick_us, source_mac,
                         channel, secondary, phy, bandwidth, stbc, rssi_dbm,
                         noise_floor_dbm, rate, mcs, rx_antenna,
                         first_invalid_bytes, trailing_invalid_bytes,
                         complex_sample_count, blocks, raw_csi
                     ) VALUES (
                         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                         ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
                     )",
                    params![
                        fact_id,
                        data.capability_digest(),
                        data.capture_sequence().to_be_bytes(),
                        data.driver_rx_timestamp_us(),
                        data.callback_tick_us().to_be_bytes(),
                        data.source_mac(),
                        data.radio().channel(),
                        secondary_byte(data.radio().secondary()),
                        phy_byte(data.radio().phy()),
                        bandwidth_byte(data.radio().bandwidth()),
                        u8::from(data.radio().stbc()),
                        data.radio().rssi_dbm(),
                        data.radio().noise_floor_dbm(),
                        data.radio().rate(),
                        data.radio().mcs(),
                        data.radio().rx_antenna(),
                        data.first_invalid_bytes(),
                        data.trailing_invalid_bytes(),
                        data.complex_sample_count(),
                        blocks,
                        data.raw_csi(),
                    ],
                )
                .map_err(|error| HostError::database_at(path, error))?;
            let quality = if data.first_invalid_bytes() == 0 && data.trailing_invalid_bytes() == 0 {
                EvidenceQuality::Captured
            } else {
                EvidenceQuality::Invalid
            };
            let transmitter =
                identity_from_parts(b"esp32-s3-transmitter-v1", &[&data.source_mac()]);
            let event = identity_from_parts(
                b"esp32-s3-capture-sequence-v1",
                &[&data.capture_sequence().to_be_bytes()],
            );
            let radio = identity_from_parts(
                b"esp32-s3-radio-v1",
                &[&[
                    phy_byte(data.radio().phy()),
                    bandwidth_byte(data.radio().bandwidth()),
                    secondary_byte(data.radio().secondary()),
                    u8::from(data.radio().stbc()),
                    data.radio().rate(),
                    data.radio().mcs(),
                    data.radio().rx_antenna(),
                ]],
            );
            let channel = identity_from_parts(
                b"esp32-s3-channel-v1",
                &[&[
                    data.radio().channel(),
                    secondary_byte(data.radio().secondary()),
                    bandwidth_byte(data.radio().bandwidth()),
                ]],
            );
            let fragment = MeasurementFragment::new(
                AssemblyKey::new(
                    SourceInstance::new(
                        route.decoded().sensor().clone(),
                        DeviceId::new(item.header.device_id()),
                        KeyEpoch::new(item.header.key_epoch())
                            .expect("authenticated key epoch is nonzero"),
                        BootGeneration::new(item.header.boot_generation())
                            .expect("authenticated boot generation is nonzero"),
                    ),
                    EventIdentity::new(
                        TransmitterIdentity::new(transmitter),
                        NativeEventIdentity::new(event),
                        None,
                    ),
                    MeasurementContext::new(
                        ProfileIdentity::new(data.capability_digest()),
                        RadioIdentity::new(radio),
                        ChannelIdentity::new(channel),
                    ),
                ),
                FragmentPosition::new(0, 1).expect("ESP native CSI is one fragment"),
                FragmentFact::new(
                    fact_digest,
                    FragmentBytes::new(
                        u32::try_from(data.raw_csi().len()).expect("native CSI limit fits u32"),
                    )
                    .expect("native CSI is within the fragment byte ceiling"),
                    quality,
                ),
            );
            persist_fragment_in_transaction(
                transaction,
                path,
                assembler,
                fragment,
                SourceTick::new(data.callback_tick_us()),
            )?;
            Ok(None)
        }
        Message::Health(health) => {
            if let Some(expected) =
                previous_capability_digest(transaction, path, &item.header, fact_id)?
                && expected != health.capability_digest()
            {
                return Ok(Some(RejectReason::CapabilityConflict));
            }
            transaction
                .execute(
                    "INSERT INTO native_health_facts (
                         fact_id, capability_digest, callback_tick_us, capture_seen,
                         queue_drop_no_slot, queue_drop_full, oversize_reject,
                         encode_reject, send_failure, pool_high_water_slots,
                         callback_max_us, encoder_max_us
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    params![
                        fact_id,
                        health.capability_digest(),
                        health.callback_tick_us().to_be_bytes(),
                        health.capture_seen().to_be_bytes(),
                        health.queue_drop_no_slot().to_be_bytes(),
                        health.queue_drop_full().to_be_bytes(),
                        health.oversize_reject().to_be_bytes(),
                        health.encode_reject().to_be_bytes(),
                        health.send_failure().to_be_bytes(),
                        health.pool_high_water_slots(),
                        health.callback_max_us(),
                        health.encoder_max_us(),
                    ],
                )
                .map_err(|error| HostError::database_at(path, error))?;
            Ok(None)
        }
    }
}

fn previous_capability_digest(
    connection: &rusqlite::Transaction<'_>,
    path: &Path,
    header: &Header,
    fact_id: i64,
) -> Result<Option<[u8; 32]>, HostError> {
    let value: Option<Vec<u8>> = connection
        .query_row(
            "SELECT c.capability_digest
             FROM native_capability_facts AS c
             JOIN raw_facts AS f ON f.fact_id = c.fact_id
             WHERE f.device_id = ?1 AND f.key_epoch = ?2
               AND f.boot_generation = ?3 AND c.fact_id < ?4
             ORDER BY c.fact_id DESC LIMIT 1",
            params![
                header.device_id().to_be_bytes(),
                header.key_epoch().to_be_bytes(),
                header.boot_generation().to_be_bytes(),
                fact_id,
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| HostError::database_at(path, error))?;
    value
        .map(|bytes| {
            bytes.try_into().map_err(|_| {
                HostError::message_at(
                    "validate persisted native capability state",
                    path,
                    "persisted capability digest width is invalid",
                )
            })
        })
        .transpose()
}

fn previous_csi_source(
    connection: &rusqlite::Transaction<'_>,
    path: &Path,
    header: &Header,
    fact_id: i64,
) -> Result<Option<[u8; 6]>, HostError> {
    let value: Option<Vec<u8>> = connection
        .query_row(
            "SELECT c.source_mac
             FROM native_csi_facts AS c
             JOIN raw_facts AS f ON f.fact_id = c.fact_id
             WHERE f.device_id = ?1 AND f.key_epoch = ?2
               AND f.boot_generation = ?3 AND c.fact_id < ?4
             ORDER BY c.fact_id DESC LIMIT 1",
            params![
                header.device_id().to_be_bytes(),
                header.key_epoch().to_be_bytes(),
                header.boot_generation().to_be_bytes(),
                fact_id,
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| HostError::database_at(path, error))?;
    value
        .map(|bytes| {
            bytes.try_into().map_err(|_| {
                HostError::message_at(
                    "validate persisted native CSI state",
                    path,
                    "persisted CSI source MAC width is invalid",
                )
            })
        })
        .transpose()
}

fn previous_csi_channel(
    connection: &rusqlite::Transaction<'_>,
    path: &Path,
    header: &Header,
    fact_id: i64,
) -> Result<Option<u8>, HostError> {
    connection
        .query_row(
            "SELECT c.channel
             FROM native_csi_facts AS c
             JOIN raw_facts AS f ON f.fact_id = c.fact_id
             WHERE f.device_id = ?1 AND f.key_epoch = ?2
               AND f.boot_generation = ?3 AND c.fact_id < ?4
             ORDER BY c.fact_id DESC LIMIT 1",
            params![
                header.device_id().to_be_bytes(),
                header.key_epoch().to_be_bytes(),
                header.boot_generation().to_be_bytes(),
                fact_id,
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| HostError::database_at(path, error))
}

fn encode_blocks(blocks: &[LtfBlock]) -> Box<[u8]> {
    let mut encoded = Vec::with_capacity(blocks.len() * LTF_BLOCK_BYTES);
    for block in blocks {
        encoded.push(ltf_kind_byte(block.kind()));
        encoded.push(0);
        encoded.extend_from_slice(&block.sample_count().to_le_bytes());
        encoded.extend_from_slice(&block.raw_offset_bytes().to_le_bytes());
    }
    encoded.into_boxed_slice()
}

fn ltf_kind_byte(kind: LtfKind) -> u8 {
    match kind {
        LtfKind::Lltf => 1,
        LtfKind::HtLtf => 2,
        LtfKind::StbcHtLtf => 3,
    }
}

fn secondary_byte(kind: S3SecondaryKind) -> u8 {
    match kind {
        S3SecondaryKind::None => 0,
        S3SecondaryKind::Above => 1,
        S3SecondaryKind::Below => 2,
    }
}

fn phy_byte(kind: S3PhyKind) -> u8 {
    match kind {
        S3PhyKind::NonHt => 1,
        S3PhyKind::Ht => 2,
    }
}

fn bandwidth_byte(kind: S3BandwidthKind) -> u8 {
    match kind {
        S3BandwidthKind::TwentyMhz => 1,
        S3BandwidthKind::FortyMhz => 2,
    }
}

fn persist_sequence_discontinuity(
    connection: &Connection,
    path: &Path,
    previous: Option<u64>,
    item: &AdmittedDatagram,
) -> Result<(), HostError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    let current = item.header.message_seq();
    let (kind, first, last) = if current > previous.saturating_add(1) {
        ("sequence_gap_observed", previous + 1, current - 1)
    } else if current < previous {
        ("reordered_arrival", current, current)
    } else {
        return Ok(());
    };
    connection
        .execute(
            "INSERT INTO raw_losses (
                 observed_utc_ns, kind, count, device_id, boot_generation,
                 first_sequence, last_sequence
             ) VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6)",
            params![
                item.received_utc_ns,
                kind,
                item.header.device_id().to_be_bytes(),
                item.header.boot_generation().to_be_bytes(),
                first.to_be_bytes(),
                last.to_be_bytes(),
            ],
        )
        .map_err(|error| HostError::database_at(path, error))?;
    Ok(())
}

fn persist_overflow(
    connection: &mut Connection,
    path: &Path,
    overflow: &OverflowSummary,
    clock: &dyn Clock,
) -> Result<(), HostError> {
    let count = overflow.count.swap(0, Ordering::AcqRel);
    if count == 0 {
        return Ok(());
    }
    let count = i64::try_from(count).unwrap_or(i64::MAX);
    connection
        .execute(
            "INSERT INTO raw_losses (observed_utc_ns, kind, count)
             VALUES (?1, 'ingress_queue_overflow', ?2)",
            params![utc_now_ns(clock)?, count],
        )
        .map_err(|error| HostError::database_at(path, error))?;
    Ok(())
}
