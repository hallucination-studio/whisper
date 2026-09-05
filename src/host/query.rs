//! Restricted local queries over committed raw facts and loss facts.

use super::*;
use crate::native_csi::{
    CapabilityDescriptor, LtfBlock, LtfKind, NativeCapabilityFact, NativeCsiFact, NativeFact,
    NativeFactProvenance, NativeHealthFact, RadioRxS3, S3BandwidthKind, S3PhyKind, S3SecondaryKind,
};
use crate::native_frame::{CapabilitiesV1, CsiDataV1, HealthV1, LTF_BLOCK_BYTES};
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

pub(super) fn query_native_facts(path: &Path, limit: usize) -> Result<Vec<NativeFact>, HostError> {
    let connection = read_only_connection(path)?;
    let mut rows = query_capability_rows(&connection, path, limit)?;
    rows.extend(query_csi_rows(&connection, path, limit)?);
    rows.extend(query_health_rows(&connection, path, limit)?);
    rows.sort_by_key(|(fact_id, _)| *fact_id);
    Ok(rows
        .into_iter()
        .rev()
        .take(limit)
        .map(|(_, fact)| fact)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect())
}

pub(super) fn query_native_capabilities(
    path: &Path,
    limit: usize,
) -> Result<Vec<NativeCapabilityFact>, HostError> {
    let connection = read_only_connection(path)?;
    let rows = query_capability_rows(&connection, path, limit)?;
    let mut facts = rows
        .into_iter()
        .filter_map(|(_, fact)| match fact {
            NativeFact::Capabilities(fact) => Some(fact),
            _ => None,
        })
        .collect::<Vec<_>>();
    facts.reverse();
    Ok(facts)
}

pub(super) fn query_native_csi(path: &Path, limit: usize) -> Result<Vec<NativeCsiFact>, HostError> {
    let connection = read_only_connection(path)?;
    let rows = query_csi_rows(&connection, path, limit)?;
    let mut facts = rows
        .into_iter()
        .filter_map(|(_, fact)| match fact {
            NativeFact::Csi(fact) => Some(fact),
            _ => None,
        })
        .collect::<Vec<_>>();
    facts.reverse();
    Ok(facts)
}

pub(super) fn query_native_health(
    path: &Path,
    limit: usize,
) -> Result<Vec<NativeHealthFact>, HostError> {
    let connection = read_only_connection(path)?;
    let rows = query_health_rows(&connection, path, limit)?;
    let mut facts = rows
        .into_iter()
        .filter_map(|(_, fact)| match fact {
            NativeFact::Health(fact) => Some(fact),
            _ => None,
        })
        .collect::<Vec<_>>();
    facts.reverse();
    Ok(facts)
}

fn read_only_connection(path: &Path) -> Result<Connection, HostError> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| HostError::database_at(path, error))
}

fn query_capability_rows(
    connection: &Connection,
    path: &Path,
    limit: usize,
) -> Result<Vec<(i64, NativeFact)>, HostError> {
    let mut statement = connection
        .prepare(
            "SELECT f.fact_id, f.digest, f.peer, f.received_utc_ns, f.device_id,
                    f.key_epoch, f.boot_generation, f.message_sequence,
                    c.capability_digest, c.firmware_build_digest,
                    c.idf_wifi_abi_digest, c.datagram_budget_bytes
             FROM native_capability_facts AS c
             JOIN raw_facts AS f ON f.fact_id = c.fact_id
             ORDER BY f.fact_id DESC LIMIT ?1",
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let rows = statement
        .query_map([i64::try_from(limit).expect("native query limit fits i64")], |row| {
            Ok((
                row.get(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, u16>(11)?,
            ))
        })
        .map_err(|error| HostError::database_at(path, error))?;
    let mut facts = Vec::with_capacity(limit);
    for row in rows {
        let (
            fact_id,
            digest,
            peer,
            received_utc_ns,
            device_id,
            key_epoch,
            boot_generation,
            message_sequence,
            capability_digest,
            firmware_build_digest,
            idf_wifi_abi_digest,
            datagram_budget_bytes,
        ) = row.map_err(|error| HostError::database_at(path, error))?;
        let provenance = decode_provenance(
            path,
            digest,
            peer,
            received_utc_ns,
            device_id,
            key_epoch,
            boot_generation,
            message_sequence,
        )?;
        let capability_digest = decode_fixed::<32>(path, capability_digest, "capability digest")?;
        let firmware_build_digest =
            decode_fixed::<32>(path, firmware_build_digest, "firmware build digest")?;
        let idf_wifi_abi_digest =
            decode_fixed::<32>(path, idf_wifi_abi_digest, "Wi-Fi ABI digest")?;
        let descriptor = CapabilityDescriptor::try_new(
            firmware_build_digest,
            idf_wifi_abi_digest,
            datagram_budget_bytes,
        )
        .map_err(|_| native_fact_error(path, "persisted capability descriptor is invalid"))?;
        let body = CapabilitiesV1::new(descriptor);
        if body.capability_digest() != capability_digest {
            return Err(native_fact_error(
                path,
                "persisted capability digest does not match descriptor",
            ));
        }
        facts.push((
            fact_id,
            NativeFact::Capabilities(NativeCapabilityFact::from_body(provenance, &body)),
        ));
    }
    Ok(facts)
}

fn query_csi_rows(
    connection: &Connection,
    path: &Path,
    limit: usize,
) -> Result<Vec<(i64, NativeFact)>, HostError> {
    let mut statement = connection
        .prepare(
            "SELECT f.fact_id, f.digest, f.peer, f.received_utc_ns, f.device_id,
                    f.key_epoch, f.boot_generation, f.message_sequence,
                    c.capability_digest, c.capture_sequence,
                    c.driver_rx_timestamp_us, c.callback_tick_us, c.source_mac,
                    c.channel, c.secondary, c.phy, c.bandwidth, c.stbc,
                    c.rssi_dbm, c.noise_floor_dbm, c.rate, c.mcs, c.rx_antenna,
                    c.first_invalid_bytes, c.trailing_invalid_bytes,
                    c.complex_sample_count, c.blocks, c.raw_csi
             FROM native_csi_facts AS c
             JOIN raw_facts AS f ON f.fact_id = c.fact_id
             ORDER BY f.fact_id DESC LIMIT ?1",
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let rows = statement
        .query_map([i64::try_from(limit).expect("native query limit fits i64")], |row| {
            Ok((
                row.get(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, u32>(10)?,
                row.get::<_, Vec<u8>>(11)?,
                row.get::<_, Vec<u8>>(12)?,
                row.get::<_, u8>(13)?,
                row.get::<_, u8>(14)?,
                row.get::<_, u8>(15)?,
                row.get::<_, u8>(16)?,
                row.get::<_, u8>(17)?,
                row.get::<_, i8>(18)?,
                row.get::<_, i8>(19)?,
                row.get::<_, u8>(20)?,
                row.get::<_, u8>(21)?,
                row.get::<_, u8>(22)?,
                row.get::<_, u8>(23)?,
                row.get::<_, u8>(24)?,
                row.get::<_, u16>(25)?,
                row.get::<_, Vec<u8>>(26)?,
                row.get::<_, Vec<u8>>(27)?,
            ))
        })
        .map_err(|error| HostError::database_at(path, error))?;
    let mut facts = Vec::with_capacity(limit);
    for row in rows {
        let (
            fact_id,
            digest,
            peer,
            received_utc_ns,
            device_id,
            key_epoch,
            boot_generation,
            message_sequence,
            capability_digest,
            capture_sequence,
            driver_rx_timestamp_us,
            callback_tick_us,
            source_mac,
            channel,
            secondary,
            phy,
            bandwidth,
            stbc,
            rssi_dbm,
            noise_floor_dbm,
            rate,
            mcs,
            rx_antenna,
            first_invalid_bytes,
            trailing_invalid_bytes,
            complex_sample_count,
            blocks,
            raw_csi,
        ) = row.map_err(|error| HostError::database_at(path, error))?;
        let provenance = decode_provenance(
            path,
            digest,
            peer,
            received_utc_ns,
            device_id,
            key_epoch,
            boot_generation,
            message_sequence,
        )?;
        let capability_digest = decode_fixed::<32>(path, capability_digest, "capability digest")?;
        let capture_sequence = decode_u64(path, capture_sequence, "capture sequence")?;
        let callback_tick_us = decode_u64(path, callback_tick_us, "callback tick")?;
        let source_mac = decode_fixed::<6>(path, source_mac, "source MAC")?;
        let secondary = decode_secondary(path, secondary)?;
        let phy = decode_phy(path, phy)?;
        let bandwidth = decode_bandwidth(path, bandwidth)?;
        let radio = RadioRxS3::try_new(
            channel,
            secondary,
            phy,
            bandwidth,
            stbc != 0,
            rssi_dbm,
            noise_floor_dbm,
            rate,
            mcs,
            rx_antenna,
        )
        .map_err(|_| native_fact_error(path, "persisted native radio facts are invalid"))?;
        let blocks = decode_blocks(path, blocks)?;
        let body = CsiDataV1::try_new(
            capability_digest,
            capture_sequence,
            driver_rx_timestamp_us,
            callback_tick_us,
            source_mac,
            radio,
            first_invalid_bytes,
            trailing_invalid_bytes,
            blocks,
            raw_csi,
        )
        .map_err(|_| native_fact_error(path, "persisted native CSI facts are invalid"))?;
        if body.complex_sample_count() != complex_sample_count {
            return Err(native_fact_error(path, "persisted native CSI sample count is invalid"));
        }
        facts.push((fact_id, NativeFact::Csi(NativeCsiFact::from_body(provenance, &body))));
    }
    Ok(facts)
}

fn query_health_rows(
    connection: &Connection,
    path: &Path,
    limit: usize,
) -> Result<Vec<(i64, NativeFact)>, HostError> {
    let mut statement = connection
        .prepare(
            "SELECT f.fact_id, f.digest, f.peer, f.received_utc_ns, f.device_id,
                    f.key_epoch, f.boot_generation, f.message_sequence,
                    h.capability_digest, h.callback_tick_us, h.capture_seen,
                    h.queue_drop_no_slot, h.queue_drop_full, h.oversize_reject,
                    h.encode_reject, h.send_failure, h.pool_high_water_slots,
                    h.callback_max_us, h.encoder_max_us
             FROM native_health_facts AS h
             JOIN raw_facts AS f ON f.fact_id = h.fact_id
             ORDER BY f.fact_id DESC LIMIT ?1",
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let rows = statement
        .query_map([i64::try_from(limit).expect("native query limit fits i64")], |row| {
            Ok((
                row.get(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, Vec<u8>>(11)?,
                row.get::<_, Vec<u8>>(12)?,
                row.get::<_, Vec<u8>>(13)?,
                row.get::<_, Vec<u8>>(14)?,
                row.get::<_, Vec<u8>>(15)?,
                row.get::<_, u16>(16)?,
                row.get::<_, u32>(17)?,
                row.get::<_, u32>(18)?,
            ))
        })
        .map_err(|error| HostError::database_at(path, error))?;
    let mut facts = Vec::with_capacity(limit);
    for row in rows {
        let (
            fact_id,
            digest,
            peer,
            received_utc_ns,
            device_id,
            key_epoch,
            boot_generation,
            message_sequence,
            capability_digest,
            callback_tick_us,
            capture_seen,
            queue_drop_no_slot,
            queue_drop_full,
            oversize_reject,
            encode_reject,
            send_failure,
            pool_high_water_slots,
            callback_max_us,
            encoder_max_us,
        ) = row.map_err(|error| HostError::database_at(path, error))?;
        let provenance = decode_provenance(
            path,
            digest,
            peer,
            received_utc_ns,
            device_id,
            key_epoch,
            boot_generation,
            message_sequence,
        )?;
        let capability_digest = decode_fixed::<32>(path, capability_digest, "capability digest")?;
        let callback_tick_us = decode_u64(path, callback_tick_us, "health callback tick")?;
        let capture_seen = decode_u64(path, capture_seen, "capture count")?;
        let queue_drop_no_slot = decode_u64(path, queue_drop_no_slot, "no-slot drop count")?;
        let queue_drop_full = decode_u64(path, queue_drop_full, "full-queue drop count")?;
        let oversize_reject = decode_u64(path, oversize_reject, "oversize reject count")?;
        let encode_reject = decode_u64(path, encode_reject, "encode reject count")?;
        let send_failure = decode_u64(path, send_failure, "send failure count")?;
        let health = HealthV1::new(
            capability_digest,
            callback_tick_us,
            capture_seen,
            queue_drop_no_slot,
            queue_drop_full,
            oversize_reject,
            encode_reject,
            send_failure,
            pool_high_water_slots,
            callback_max_us,
            encoder_max_us,
        );
        facts.push((fact_id, NativeFact::Health(NativeHealthFact::from_body(provenance, &health))));
    }
    Ok(facts)
}

#[expect(clippy::too_many_arguments, reason = "one row supplies the complete raw-fact provenance")]
fn decode_provenance(
    path: &Path,
    digest: Vec<u8>,
    peer: String,
    received_utc_ns: i64,
    device_id: Vec<u8>,
    key_epoch: Vec<u8>,
    boot_generation: Vec<u8>,
    message_sequence: Vec<u8>,
) -> Result<NativeFactProvenance, HostError> {
    let digest = decode_fixed::<32>(path, digest, "provenance digest")?;
    let peer = peer
        .parse()
        .map_err(|_| native_fact_error(path, "persisted native-fact peer is invalid"))?;
    let received_utc_ns = u64::try_from(received_utc_ns)
        .map_err(|_| native_fact_error(path, "persisted native-fact receive time is invalid"))?;
    let received_at =
        UNIX_EPOCH.checked_add(Duration::from_nanos(received_utc_ns)).ok_or_else(|| {
            native_fact_error(path, "persisted native-fact receive time is out of range")
        })?;
    let device_id = decode_fixed::<8>(path, device_id, "device identity")?;
    let key_epoch = decode_fixed::<2>(path, key_epoch, "key epoch")?;
    let boot_generation = decode_fixed::<4>(path, boot_generation, "boot generation")?;
    let message_sequence = decode_fixed::<8>(path, message_sequence, "message sequence")?;
    let key_epoch = KeyEpoch::new(u16::from_be_bytes(key_epoch))
        .ok_or_else(|| native_fact_error(path, "persisted native-fact key epoch is invalid"))?;
    let boot_generation =
        BootGeneration::new(u32::from_be_bytes(boot_generation)).ok_or_else(|| {
            native_fact_error(path, "persisted native-fact boot generation is invalid")
        })?;
    let message_sequence =
        MessageSequence::new(u64::from_be_bytes(message_sequence)).ok_or_else(|| {
            native_fact_error(path, "persisted native-fact message sequence is invalid")
        })?;
    Ok(NativeFactProvenance::new(
        digest,
        peer,
        received_at,
        DeviceId::new(u64::from_be_bytes(device_id)),
        key_epoch,
        boot_generation,
        message_sequence,
    ))
}

fn decode_fixed<const N: usize>(
    path: &Path,
    bytes: Vec<u8>,
    name: &'static str,
) -> Result<[u8; N], HostError> {
    bytes.try_into().map_err(|_| native_fact_error(path, name))
}

fn decode_u64(path: &Path, bytes: Vec<u8>, name: &'static str) -> Result<u64, HostError> {
    Ok(u64::from_be_bytes(decode_fixed::<8>(path, bytes, name)?))
}

fn decode_blocks(path: &Path, bytes: Vec<u8>) -> Result<Box<[LtfBlock]>, HostError> {
    if bytes.len() < LTF_BLOCK_BYTES
        || bytes.len() > 3 * LTF_BLOCK_BYTES
        || !bytes.len().is_multiple_of(LTF_BLOCK_BYTES)
    {
        return Err(native_fact_error(path, "persisted native CSI block encoding is invalid"));
    }
    let mut blocks = Vec::with_capacity(bytes.len() / LTF_BLOCK_BYTES);
    for chunk in bytes.chunks_exact(LTF_BLOCK_BYTES) {
        if chunk[1] != 0 {
            return Err(native_fact_error(
                path,
                "persisted native CSI block reserved byte is invalid",
            ));
        }
        let kind = match chunk[0] {
            1 => LtfKind::Lltf,
            2 => LtfKind::HtLtf,
            3 => LtfKind::StbcHtLtf,
            _ => return Err(native_fact_error(path, "persisted native CSI block kind is invalid")),
        };
        blocks.push(LtfBlock::new(
            kind,
            u16::from_le_bytes([chunk[2], chunk[3]]),
            u16::from_le_bytes([chunk[4], chunk[5]]),
        ));
    }
    Ok(blocks.into_boxed_slice())
}

fn decode_secondary(path: &Path, value: u8) -> Result<S3SecondaryKind, HostError> {
    match value {
        0 => Ok(S3SecondaryKind::None),
        1 => Ok(S3SecondaryKind::Above),
        2 => Ok(S3SecondaryKind::Below),
        _ => Err(native_fact_error(path, "persisted native CSI secondary is invalid")),
    }
}

fn decode_phy(path: &Path, value: u8) -> Result<S3PhyKind, HostError> {
    match value {
        1 => Ok(S3PhyKind::NonHt),
        2 => Ok(S3PhyKind::Ht),
        _ => Err(native_fact_error(path, "persisted native CSI PHY is invalid")),
    }
}

fn decode_bandwidth(path: &Path, value: u8) -> Result<S3BandwidthKind, HostError> {
    match value {
        1 => Ok(S3BandwidthKind::TwentyMhz),
        2 => Ok(S3BandwidthKind::FortyMhz),
        _ => Err(native_fact_error(path, "persisted native CSI bandwidth is invalid")),
    }
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

fn native_fact_error(path: &Path, message: &'static str) -> HostError {
    HostError::message_at("decode persisted native fact", path, message)
}

fn raw_loss_error(path: &Path, message: &'static str) -> HostError {
    HostError::message_at("decode persisted raw loss", path, message)
}
