//! Restricted local queries over committed raw facts and loss facts.

use super::*;
pub(super) fn query_raw(path: &Path, limit: usize) -> Result<Vec<RawFact>, HostError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| HostError::database_at(path, error))?;
    let mut statement = connection
        .prepare(
            "SELECT digest, peer, received_utc_ns, device_id, key_epoch,
                    boot_generation, message_sequence, kind, datagram
             FROM raw_facts
             ORDER BY fact_id DESC LIMIT ?1",
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let rows = statement
        .query_map([i64::try_from(limit).expect("query limit fits i64")], |row| {
            let digest: Vec<u8> = row.get(0)?;
            let peer: String = row.get(1)?;
            let received_utc_ns: i64 = row.get(2)?;
            let device_id: Vec<u8> = row.get(3)?;
            let key_epoch: Vec<u8> = row.get(4)?;
            let boot_generation: Vec<u8> = row.get(5)?;
            let message_sequence: Vec<u8> = row.get(6)?;
            let kind_byte: u8 = row.get(7)?;
            let datagram: Vec<u8> = row.get(8)?;
            Ok((
                digest,
                peer,
                received_utc_ns,
                device_id,
                key_epoch,
                boot_generation,
                message_sequence,
                kind_byte,
                datagram,
            ))
        })
        .map_err(|error| HostError::database_at(path, error))?;
    let mut facts = Vec::with_capacity(limit);
    for row in rows {
        let (
            digest,
            peer,
            received_utc_ns,
            device_id,
            key_epoch,
            boot_generation,
            message_sequence,
            kind_byte,
            datagram,
        ) = row.map_err(|error| HostError::database_at(path, error))?;
        let digest = digest
            .try_into()
            .map_err(|_| raw_fact_error(path, "persisted raw digest is invalid"))?;
        let peer =
            peer.parse().map_err(|_| raw_fact_error(path, "persisted raw peer is invalid"))?;
        let received_utc_ns = u64::try_from(received_utc_ns)
            .map_err(|_| raw_fact_error(path, "persisted receive time is invalid"))?;
        let received_at = UNIX_EPOCH
            .checked_add(Duration::from_nanos(received_utc_ns))
            .ok_or_else(|| raw_fact_error(path, "persisted receive time is out of range"))?;
        let device_id = u64::from_be_bytes(
            device_id
                .try_into()
                .map_err(|_| raw_fact_error(path, "persisted device identity is invalid"))?,
        );
        let key_epoch = u16::from_be_bytes(
            key_epoch
                .try_into()
                .map_err(|_| raw_fact_error(path, "persisted key epoch is invalid"))?,
        );
        let boot_generation = u32::from_be_bytes(
            boot_generation
                .try_into()
                .map_err(|_| raw_fact_error(path, "persisted boot generation is invalid"))?,
        );
        let message_sequence = u64::from_be_bytes(
            message_sequence
                .try_into()
                .map_err(|_| raw_fact_error(path, "persisted message sequence is invalid"))?,
        );
        facts.push(RawFact {
            digest,
            peer,
            received_at,
            device_id: DeviceId::new(device_id),
            key_epoch: KeyEpoch::new(key_epoch)
                .ok_or_else(|| raw_fact_error(path, "persisted key epoch is invalid"))?,
            boot_generation: BootGeneration::new(boot_generation)
                .ok_or_else(|| raw_fact_error(path, "persisted boot generation is invalid"))?,
            message_sequence: MessageSequence::new(message_sequence)
                .ok_or_else(|| raw_fact_error(path, "persisted message sequence is invalid"))?,
            kind: NativeFrameKind::new(kind_byte),
            datagram: datagram.into_boxed_slice(),
        });
    }
    facts.reverse();
    Ok(facts)
}

pub(super) fn query_raw_losses(path: &Path, limit: usize) -> Result<Vec<RawLoss>, HostError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| HostError::database_at(path, error))?;
    let mut statement = connection
        .prepare(
            "SELECT kind, count, observed_utc_ns, device_id, boot_generation,
                    first_sequence, last_sequence
             FROM raw_losses
             ORDER BY loss_id DESC LIMIT ?1",
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let rows = statement
        .query_map([i64::try_from(limit).expect("query limit fits i64")], |row| {
            let kind: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            let observed_utc_ns: i64 = row.get(2)?;
            let device_id: Option<Vec<u8>> = row.get(3)?;
            let boot_generation: Option<Vec<u8>> = row.get(4)?;
            let first: Option<Vec<u8>> = row.get(5)?;
            let last: Option<Vec<u8>> = row.get(6)?;
            Ok((kind, count, observed_utc_ns, device_id, boot_generation, first, last))
        })
        .map_err(|error| HostError::database_at(path, error))?;
    let mut losses = Vec::with_capacity(limit);
    for row in rows {
        let (kind, count, observed_utc_ns, device_id, boot_generation, first, last) =
            row.map_err(|error| HostError::database_at(path, error))?;
        let kind = match kind.as_str() {
            "sequence_gap_observed" => RawLossKind::SequenceGapObserved,
            "reordered_arrival" => RawLossKind::ReorderedArrival,
            "ingress_queue_overflow" => RawLossKind::IngressQueueOverflow,
            _ => return Err(raw_loss_error(path, "persisted raw-loss kind is invalid")),
        };
        let count = u64::try_from(count)
            .map_err(|_| raw_loss_error(path, "persisted loss count is invalid"))?;
        let observed_utc_ns = u64::try_from(observed_utc_ns)
            .map_err(|_| raw_loss_error(path, "persisted loss time is invalid"))?;
        let observed_at = UNIX_EPOCH
            .checked_add(Duration::from_nanos(observed_utc_ns))
            .ok_or_else(|| raw_loss_error(path, "persisted loss time is out of range"))?;
        losses.push(RawLoss {
            kind,
            count,
            observed_at,
            device_id: decode_optional_u64(path, device_id, "persisted loss device is invalid")?
                .map(DeviceId::new),
            boot_generation: decode_optional_u32(
                path,
                boot_generation,
                "persisted loss boot is invalid",
            )?
            .map(|boot| {
                BootGeneration::new(boot)
                    .ok_or_else(|| raw_loss_error(path, "persisted loss boot is invalid"))
            })
            .transpose()?,
            first_sequence: decode_optional_sequence(path, first)?.map(|sequence| {
                MessageSequence::new(sequence).expect("decoded sequence is nonzero")
            }),
            last_sequence: decode_optional_sequence(path, last)?.map(|sequence| {
                MessageSequence::new(sequence).expect("decoded sequence is nonzero")
            }),
        });
    }
    losses.reverse();
    Ok(losses)
}

fn decode_optional_u64(
    path: &Path,
    bytes: Option<Vec<u8>>,
    invalid: &'static str,
) -> Result<Option<u64>, HostError> {
    bytes
        .map(|bytes| {
            let bytes: [u8; 8] = bytes.try_into().map_err(|_| raw_loss_error(path, invalid))?;
            Ok(u64::from_be_bytes(bytes))
        })
        .transpose()
}

fn decode_optional_u32(
    path: &Path,
    bytes: Option<Vec<u8>>,
    invalid: &'static str,
) -> Result<Option<u32>, HostError> {
    bytes
        .map(|bytes| {
            let bytes: [u8; 4] = bytes.try_into().map_err(|_| raw_loss_error(path, invalid))?;
            Ok(u32::from_be_bytes(bytes))
        })
        .transpose()
}

fn decode_optional_sequence(path: &Path, bytes: Option<Vec<u8>>) -> Result<Option<u64>, HostError> {
    bytes
        .map(|bytes| {
            let bytes: [u8; 8] = bytes
                .try_into()
                .map_err(|_| raw_loss_error(path, "persisted loss sequence is invalid"))?;
            let sequence = u64::from_be_bytes(bytes);
            if sequence == 0 {
                return Err(raw_loss_error(path, "persisted loss sequence is invalid"));
            }
            Ok(sequence)
        })
        .transpose()
}

fn raw_fact_error(path: &Path, message: &'static str) -> HostError {
    HostError::message_at("decode persisted raw fact", path, message)
}

fn raw_loss_error(path: &Path, message: &'static str) -> HostError {
    HostError::message_at("decode persisted raw loss", path, message)
}
