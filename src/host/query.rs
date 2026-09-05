//! Restricted local queries over committed raw facts and loss facts.

use super::*;
use crate::measurement::{
    AssemblyClose, AssemblyCloseReason, AssemblyKey, AssemblyMember, AssociationUncertainty,
    EvidenceQuality, Geometry, PhaseRelation, PortMapping, QualificationRelation, RelationValidity,
    TimeRelation,
};
use crate::native_csi::{
    CapabilityDescriptor, LtfBlock, LtfKind, NativeCapabilityFact, NativeCsiFact, NativeFact,
    NativeFactProvenance, NativeHealthFact, RadioRxS3, S3BandwidthKind, S3PhyKind, S3SecondaryKind,
};
use crate::native_frame::{
    CapabilitiesV1, CsiDataV1, HealthV1, LTF_BLOCK_BYTES, Message, MessageKind,
    authenticate_datagram, decode_authenticated,
};
use rusqlite::{Row, types::FromSql};
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

pub(super) fn query_native_facts(
    path: &Path,
    routes: &[NativeFrameRoute],
    limit: usize,
) -> Result<Vec<NativeFact>, HostError> {
    let connection = read_only_connection(path)?;
    validate_native_route_pins(&connection, path, routes)?;
    let mut rows = query_capability_rows(&connection, path, routes, limit)?;
    rows.extend(query_csi_rows(&connection, path, routes, limit)?);
    rows.extend(query_health_rows(&connection, path, routes, limit)?);
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
    routes: &[NativeFrameRoute],
    limit: usize,
) -> Result<Vec<NativeCapabilityFact>, HostError> {
    let connection = read_only_connection(path)?;
    validate_native_route_pins(&connection, path, routes)?;
    let rows = query_capability_rows(&connection, path, routes, limit)?;
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

pub(super) fn query_native_csi(
    path: &Path,
    routes: &[NativeFrameRoute],
    limit: usize,
) -> Result<Vec<NativeCsiFact>, HostError> {
    let connection = read_only_connection(path)?;
    validate_native_route_pins(&connection, path, routes)?;
    let rows = query_csi_rows(&connection, path, routes, limit)?;
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
    routes: &[NativeFrameRoute],
    limit: usize,
) -> Result<Vec<NativeHealthFact>, HostError> {
    let connection = read_only_connection(path)?;
    validate_native_route_pins(&connection, path, routes)?;
    let rows = query_health_rows(&connection, path, routes, limit)?;
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
    routes: &[NativeFrameRoute],
    limit: usize,
) -> Result<Vec<(i64, NativeFact)>, HostError> {
    query_native_rows(
        connection,
        path,
        routes,
        limit,
        MessageKind::Capabilities,
        "SELECT f.fact_id, f.digest, f.peer, f.received_utc_ns, f.device_id,
                f.key_epoch, f.boot_generation, f.message_sequence, f.kind, f.datagram,
                c.capability_digest, c.firmware_build_digest,
                c.idf_wifi_abi_digest, c.datagram_budget_bytes
         FROM native_capability_facts AS c
         JOIN raw_facts AS f ON f.fact_id = c.fact_id
         ORDER BY f.fact_id DESC LIMIT ?1",
        |row, provenance, decoded| {
            let capability_digest =
                decode_fixed::<32>(path, row_value(row, 10, path)?, "capability digest")?;
            let firmware_build_digest =
                decode_fixed::<32>(path, row_value(row, 11, path)?, "firmware build digest")?;
            let idf_wifi_abi_digest =
                decode_fixed::<32>(path, row_value(row, 12, path)?, "Wi-Fi ABI digest")?;
            let datagram_budget_bytes: u16 = row_value(row, 13, path)?;
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
            let fact = NativeCapabilityFact::from_body(provenance.clone(), &body);
            let Message::Capabilities(expected) = decoded else {
                return Err(native_fact_error(
                    path,
                    "persisted capability row is not bound to a capability datagram",
                ));
            };
            if fact != NativeCapabilityFact::from_body(provenance, expected) {
                return Err(native_fact_error(
                    path,
                    "persisted capability row does not match its authenticated raw datagram",
                ));
            }
            Ok(NativeFact::Capabilities(fact))
        },
    )
}

fn query_csi_rows(
    connection: &Connection,
    path: &Path,
    routes: &[NativeFrameRoute],
    limit: usize,
) -> Result<Vec<(i64, NativeFact)>, HostError> {
    query_native_rows(
        connection,
        path,
        routes,
        limit,
        MessageKind::CsiData,
        "SELECT f.fact_id, f.digest, f.peer, f.received_utc_ns, f.device_id,
                f.key_epoch, f.boot_generation, f.message_sequence, f.kind, f.datagram,
                c.capability_digest, c.capture_sequence,
                c.driver_rx_timestamp_us, c.callback_tick_us, c.source_mac,
                c.channel, c.secondary, c.phy, c.bandwidth, c.stbc,
                c.rssi_dbm, c.noise_floor_dbm, c.rate, c.mcs, c.rx_antenna,
                c.first_invalid_bytes, c.trailing_invalid_bytes,
                c.complex_sample_count, c.blocks, c.raw_csi
         FROM native_csi_facts AS c
         JOIN raw_facts AS f ON f.fact_id = c.fact_id
         ORDER BY f.fact_id DESC LIMIT ?1",
        |row, provenance, decoded| {
            let capability_digest =
                decode_fixed::<32>(path, row_value(row, 10, path)?, "capability digest")?;
            let capture_sequence = decode_u64(path, row_value(row, 11, path)?, "capture sequence")?;
            let driver_rx_timestamp_us: u32 = row_value(row, 12, path)?;
            let callback_tick_us = decode_u64(path, row_value(row, 13, path)?, "callback tick")?;
            let source_mac = decode_fixed::<6>(path, row_value(row, 14, path)?, "source MAC")?;
            let channel: u8 = row_value(row, 15, path)?;
            let secondary = decode_secondary(path, row_value(row, 16, path)?)?;
            let phy = decode_phy(path, row_value(row, 17, path)?)?;
            let bandwidth = decode_bandwidth(path, row_value(row, 18, path)?)?;
            let stbc: u8 = row_value(row, 19, path)?;
            if stbc > 1 {
                return Err(native_fact_error(path, "persisted native CSI STBC value is invalid"));
            }
            let rssi_dbm: i8 = row_value(row, 20, path)?;
            let noise_floor_dbm: i8 = row_value(row, 21, path)?;
            let rate: u8 = row_value(row, 22, path)?;
            let mcs: u8 = row_value(row, 23, path)?;
            let rx_antenna: u8 = row_value(row, 24, path)?;
            let first_invalid_bytes: u8 = row_value(row, 25, path)?;
            let trailing_invalid_bytes: u8 = row_value(row, 26, path)?;
            let complex_sample_count: u16 = row_value(row, 27, path)?;
            let blocks = decode_blocks(path, row_value(row, 28, path)?)?;
            let raw_csi: Vec<u8> = row_value(row, 29, path)?;
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
                return Err(native_fact_error(
                    path,
                    "persisted native CSI sample count is invalid",
                ));
            }
            let fact = NativeCsiFact::from_body(provenance.clone(), &body);
            let Message::CsiData(expected) = decoded else {
                return Err(native_fact_error(
                    path,
                    "persisted CSI row is not bound to a CSI datagram",
                ));
            };
            if fact != NativeCsiFact::from_body(provenance, expected) {
                return Err(native_fact_error(
                    path,
                    "persisted CSI row does not match its authenticated raw datagram",
                ));
            }
            Ok(NativeFact::Csi(fact))
        },
    )
}

fn query_health_rows(
    connection: &Connection,
    path: &Path,
    routes: &[NativeFrameRoute],
    limit: usize,
) -> Result<Vec<(i64, NativeFact)>, HostError> {
    query_native_rows(
        connection,
        path,
        routes,
        limit,
        MessageKind::Health,
        "SELECT f.fact_id, f.digest, f.peer, f.received_utc_ns, f.device_id,
                f.key_epoch, f.boot_generation, f.message_sequence, f.kind, f.datagram,
                h.capability_digest, h.callback_tick_us, h.capture_seen,
                h.queue_drop_no_slot, h.queue_drop_full, h.oversize_reject,
                h.encode_reject, h.send_failure, h.pool_high_water_slots,
                h.callback_max_us, h.encoder_max_us
         FROM native_health_facts AS h
         JOIN raw_facts AS f ON f.fact_id = h.fact_id
         ORDER BY f.fact_id DESC LIMIT ?1",
        |row, provenance, decoded| {
            let capability_digest =
                decode_fixed::<32>(path, row_value(row, 10, path)?, "capability digest")?;
            let callback_tick_us =
                decode_u64(path, row_value(row, 11, path)?, "health callback tick")?;
            let capture_seen = decode_u64(path, row_value(row, 12, path)?, "capture count")?;
            let queue_drop_no_slot =
                decode_u64(path, row_value(row, 13, path)?, "no-slot drop count")?;
            let queue_drop_full =
                decode_u64(path, row_value(row, 14, path)?, "full-queue drop count")?;
            let oversize_reject =
                decode_u64(path, row_value(row, 15, path)?, "oversize reject count")?;
            let encode_reject = decode_u64(path, row_value(row, 16, path)?, "encode reject count")?;
            let send_failure = decode_u64(path, row_value(row, 17, path)?, "send failure count")?;
            let pool_high_water_slots: u16 = row_value(row, 18, path)?;
            let callback_max_us: u32 = row_value(row, 19, path)?;
            let encoder_max_us: u32 = row_value(row, 20, path)?;
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
            let fact = NativeHealthFact::from_body(provenance.clone(), &health);
            let Message::Health(expected) = decoded else {
                return Err(native_fact_error(
                    path,
                    "persisted health row is not bound to a health datagram",
                ));
            };
            if fact != NativeHealthFact::from_body(provenance, expected) {
                return Err(native_fact_error(
                    path,
                    "persisted health row does not match its authenticated raw datagram",
                ));
            }
            Ok(NativeFact::Health(fact))
        },
    )
}

struct NativeRawRow {
    provenance: NativeFactProvenance,
    decoded: crate::native_frame::DecodedDatagram,
}

fn query_native_rows<T>(
    connection: &Connection,
    path: &Path,
    routes: &[NativeFrameRoute],
    limit: usize,
    expected_kind: MessageKind,
    sql: &str,
    mut decode: impl FnMut(&Row<'_>, NativeFactProvenance, &Message) -> Result<T, HostError>,
) -> Result<Vec<(i64, T)>, HostError> {
    let mut statement =
        connection.prepare(sql).map_err(|error| HostError::database_at(path, error))?;
    let limit = i64::try_from(limit)
        .map_err(|_| native_fact_error(path, "native query limit exceeds SQLite range"))?;
    let mut rows = statement.query([limit]).map_err(|error| HostError::database_at(path, error))?;
    let mut facts = Vec::with_capacity(usize::try_from(limit).unwrap_or(0));
    while let Some(row) = rows.next().map_err(|error| HostError::database_at(path, error))? {
        let fact_id: i64 = row_value(row, 0, path)?;
        let raw = decode_native_raw_row(row, path, routes, expected_kind)?;
        let fact = decode(row, raw.provenance, raw.decoded.message())?;
        facts.push((fact_id, fact));
    }
    facts.reverse();
    Ok(facts)
}

fn decode_native_raw_row(
    row: &Row<'_>,
    path: &Path,
    routes: &[NativeFrameRoute],
    expected_kind: MessageKind,
) -> Result<NativeRawRow, HostError> {
    let digest: Vec<u8> = row_value(row, 1, path)?;
    let peer: String = row_value(row, 2, path)?;
    let received_utc_ns: i64 = row_value(row, 3, path)?;
    let device_id: Vec<u8> = row_value(row, 4, path)?;
    let key_epoch: Vec<u8> = row_value(row, 5, path)?;
    let boot_generation: Vec<u8> = row_value(row, 6, path)?;
    let message_sequence: Vec<u8> = row_value(row, 7, path)?;
    let kind: u8 = row_value(row, 8, path)?;
    let datagram: Vec<u8> = row_value(row, 9, path)?;
    let peer_address = peer
        .parse::<SocketAddr>()
        .map_err(|_| native_fact_error(path, "persisted native-fact peer is invalid"))?;
    let device_id =
        DeviceId::new(u64::from_be_bytes(decode_fixed::<8>(path, device_id, "device identity")?));
    let key_epoch =
        KeyEpoch::new(u16::from_be_bytes(decode_fixed::<2>(path, key_epoch, "key epoch")?))
            .ok_or_else(|| native_fact_error(path, "persisted native-fact key epoch is invalid"))?;
    let boot_generation = BootGeneration::new(u32::from_be_bytes(decode_fixed::<4>(
        path,
        boot_generation,
        "boot generation",
    )?))
    .ok_or_else(|| native_fact_error(path, "persisted native-fact boot generation is invalid"))?;
    let message_sequence = MessageSequence::new(u64::from_be_bytes(decode_fixed::<8>(
        path,
        message_sequence,
        "message sequence",
    )?))
    .ok_or_else(|| native_fact_error(path, "persisted native-fact message sequence is invalid"))?;
    let digest = decode_fixed::<32>(path, digest, "provenance digest")?;
    let computed_digest: [u8; 32] = Sha256::digest(&datagram).into();
    if digest != computed_digest {
        return Err(native_fact_error(
            path,
            "persisted raw datagram does not match its provenance digest",
        ));
    }
    let route = routes
        .iter()
        .find(|route| {
            route.peer == peer_address.ip()
                && route.device_id == device_id
                && route.key_epoch == key_epoch
        })
        .ok_or_else(|| native_fact_error(path, "persisted native fact has no configured route"))?;
    let authenticated = authenticate_datagram(route.key.as_bytes(), &datagram).map_err(|_| {
        native_fact_error(path, "persisted raw datagram failed canonical authentication")
    })?;
    let header = authenticated.header();
    if header.kind() != Some(expected_kind)
        || header.kind_byte() != kind
        || header.device_id() != device_id.get()
        || header.key_epoch() != key_epoch.get()
        || header.boot_generation() != boot_generation.get()
        || header.message_seq() != message_sequence.get()
    {
        return Err(native_fact_error(
            path,
            "persisted native-fact provenance does not match its authenticated header",
        ));
    }
    let decoded = decode_authenticated(&authenticated).map_err(|_| {
        native_fact_error(path, "persisted raw datagram failed canonical native decoding")
    })?;
    if route.semantic_rejection(decoded.message()).is_some() {
        return Err(native_fact_error(
            path,
            "persisted native fact no longer satisfies the configured decoded route",
        ));
    }
    let provenance = NativeFactProvenance::new(
        digest,
        route.decoded.sensor().clone(),
        peer_address,
        UNIX_EPOCH
            .checked_add(Duration::from_nanos(u64::try_from(received_utc_ns).map_err(|_| {
                native_fact_error(path, "persisted native-fact receive time is invalid")
            })?))
            .ok_or_else(|| {
                native_fact_error(path, "persisted native-fact receive time is out of range")
            })?,
        device_id,
        key_epoch,
        boot_generation,
        message_sequence,
    );
    Ok(NativeRawRow { provenance, decoded })
}

fn row_value<T: FromSql>(row: &Row<'_>, index: usize, path: &Path) -> Result<T, HostError> {
    row.get(index).map_err(|error| HostError::database_at(path, error))
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

pub(super) fn query_measurement_closes(
    path: &Path,
    limit: usize,
) -> Result<Vec<AssemblyClose>, HostError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| HostError::database_at(path, error))?;
    let mut statement = connection
        .prepare(
            "SELECT assembly_id, source_fact_id, device_id, boot_generation, transmitter, native_event,
                    retransmission, missing_ordinals, close_reason,
                    association_uncertainty, total_bytes
             FROM measurement_assemblies ORDER BY assembly_id DESC LIMIT ?1",
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let rows = statement
        .query_map([i64::try_from(limit).expect("query limit fits i64")], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, u64>(10)?,
            ))
        })
        .map_err(|error| HostError::database_at(path, error))?;
    let mut closes = Vec::with_capacity(limit);
    for row in rows {
        let (
            id,
            source_fact_id,
            device,
            boot,
            transmitter,
            event,
            retransmission,
            missing,
            reason,
            uncertainty,
            total,
        ) = row.map_err(|error| HostError::database_at(path, error))?;
        let device = decode_be_u64(path, device, "measurement device")?;
        let boot = decode_be_u32(path, boot, "measurement boot")?;
        let transmitter: [u8; 6] = transmitter.try_into().map_err(|_| measurement_error(path))?;
        let event = decode_be_u64(path, event, "measurement event")?;
        let retransmission = retransmission
            .map(|bytes| decode_be_u64(path, bytes, "measurement retransmission"))
            .transpose()?;
        let missing = decode_ordinals(path, &missing)?;
        let reason = decode_close_reason(path, &reason)?;
        let uncertainty = decode_uncertainty(path, &uncertainty)?;
        let members = query_assembly_members(&connection, path, id)?;
        validate_native_assembly(
            &connection,
            path,
            source_fact_id,
            device,
            boot,
            transmitter,
            event,
            retransmission,
            &missing,
            reason,
            uncertainty,
            total,
            &members,
        )?;
        closes.push(AssemblyClose::persisted(
            AssemblyKey::new(
                DeviceId::new(device),
                BootGeneration::new(boot).ok_or_else(|| measurement_error(path))?,
                transmitter,
                event,
                retransmission,
            ),
            members.into_boxed_slice(),
            missing.into_boxed_slice(),
            reason,
            uncertainty,
            total,
        ));
    }
    closes.reverse();
    Ok(closes)
}

#[expect(
    clippy::too_many_arguments,
    reason = "validation compares every persisted assembly field with its sole native source"
)]
fn validate_native_assembly(
    connection: &Connection,
    path: &Path,
    source_fact_id: i64,
    device: u64,
    boot: u32,
    transmitter: [u8; 6],
    event: u64,
    retransmission: Option<u64>,
    missing: &[u16],
    reason: AssemblyCloseReason,
    uncertainty: AssociationUncertainty,
    total: u64,
    members: &[AssemblyMember],
) -> Result<(), HostError> {
    let source = connection
        .query_row(
            "SELECT f.digest, f.device_id, f.boot_generation, f.message_sequence,
                    c.source_mac, c.capture_sequence, c.first_invalid_bytes,
                    c.trailing_invalid_bytes, length(c.raw_csi)
             FROM native_csi_facts AS c
             JOIN raw_facts AS f ON f.fact_id = c.fact_id
             WHERE c.fact_id = ?1",
            [source_fact_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, u8>(6)?,
                    row.get::<_, u8>(7)?,
                    row.get::<_, u64>(8)?,
                ))
            },
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let digest: [u8; 32] = source.0.try_into().map_err(|_| measurement_error(path))?;
    let source_device = decode_be_u64(path, source.1, "source device")?;
    let source_boot = decode_be_u32(path, source.2, "source boot")?;
    let source_retransmission = decode_be_u64(path, source.3, "source sequence")?;
    let source_transmitter: [u8; 6] = source.4.try_into().map_err(|_| measurement_error(path))?;
    let source_event = decode_be_u64(path, source.5, "source event")?;
    let source_quality = if source.6 == 0 && source.7 == 0 {
        EvidenceQuality::Captured
    } else {
        EvidenceQuality::Invalid
    };
    if source_device != device
        || source_boot != boot
        || source_transmitter != transmitter
        || source_event != event
        || retransmission != Some(source_retransmission)
        || !missing.is_empty()
        || reason != AssemblyCloseReason::Complete
        || uncertainty != AssociationUncertainty::ExactNativeIdentity
        || total != source.8
        || members.len() != 1
        || members[0].ordinal() != 0
        || members[0].fact_digest() != digest
        || u64::from(members[0].payload_bytes()) != source.8
        || members[0].quality() != source_quality
    {
        return Err(measurement_error(path));
    }
    Ok(())
}

fn query_assembly_members(
    connection: &Connection,
    path: &Path,
    assembly_id: i64,
) -> Result<Vec<AssemblyMember>, HostError> {
    let mut statement = connection
        .prepare(
            "SELECT ordinal, fact_digest, payload_bytes, quality
             FROM measurement_members WHERE assembly_id = ?1 ORDER BY ordinal",
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let rows = statement
        .query_map([assembly_id], |row| {
            Ok((
                row.get::<_, u16>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|error| HostError::database_at(path, error))?;
    rows.map(|row| {
        let (ordinal, digest, bytes, quality) =
            row.map_err(|error| HostError::database_at(path, error))?;
        let digest = digest.try_into().map_err(|_| measurement_error(path))?;
        Ok(AssemblyMember::persisted(ordinal, digest, bytes, decode_quality(path, &quality)?))
    })
    .collect()
}

pub(super) fn query_qualifications(
    path: &Path,
    limit: usize,
) -> Result<Vec<QualificationRelation>, HostError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| HostError::database_at(path, error))?;
    let mut statement = connection
        .prepare(
            "SELECT kind, source, error_bound, valid_from_tick, valid_until_tick,
                    epoch, tx_geometry_known
             FROM qualification_relations ORDER BY relation_id DESC LIMIT ?1",
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let rows = statement
        .query_map([i64::try_from(limit).expect("query limit fits i64")], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Option<u8>>(6)?,
            ))
        })
        .map_err(|error| HostError::database_at(path, error))?;
    let mut relations = Vec::with_capacity(limit);
    for row in rows {
        let (kind, source, error, from, until, epoch, tx_geometry) =
            row.map_err(|error| HostError::database_at(path, error))?;
        let validity = RelationValidity::new(
            source,
            decode_be_u64(path, error, "relation error")?,
            decode_be_u64(path, from, "relation start")?,
            decode_be_u64(path, until, "relation end")?,
            decode_be_u64(path, epoch, "relation epoch")?,
        )
        .map_err(|_| measurement_error(path))?;
        relations.push(match (kind.as_str(), tx_geometry) {
            ("time", None) => QualificationRelation::Time(TimeRelation::new(validity)),
            ("phase", None) => QualificationRelation::Phase(PhaseRelation::new(validity)),
            ("port", Some(known @ 0..=1)) => {
                QualificationRelation::Port(PortMapping::new(validity, known == 1))
            }
            ("geometry", None) => QualificationRelation::Geometry(Geometry::new(validity)),
            _ => return Err(measurement_error(path)),
        });
    }
    relations.reverse();
    Ok(relations)
}

fn decode_be_u64(path: &Path, bytes: Vec<u8>, _field: &'static str) -> Result<u64, HostError> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| measurement_error(path))?;
    Ok(u64::from_be_bytes(bytes))
}

fn decode_be_u32(path: &Path, bytes: Vec<u8>, _field: &'static str) -> Result<u32, HostError> {
    let bytes: [u8; 4] = bytes.try_into().map_err(|_| measurement_error(path))?;
    Ok(u32::from_be_bytes(bytes))
}

fn decode_ordinals(path: &Path, bytes: &[u8]) -> Result<Vec<u16>, HostError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(measurement_error(path));
    }
    Ok(bytes.chunks_exact(2).map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]])).collect())
}

fn decode_close_reason(path: &Path, value: &str) -> Result<AssemblyCloseReason, HostError> {
    match value {
        "complete" => Ok(AssemblyCloseReason::Complete),
        "wait_limit" => Ok(AssemblyCloseReason::WaitLimit),
        "count_limit" => Ok(AssemblyCloseReason::CountLimit),
        "byte_limit" => Ok(AssemblyCloseReason::ByteLimit),
        "late_fragment" => Ok(AssemblyCloseReason::LateFragment),
        "conflicting_duplicate" => Ok(AssemblyCloseReason::ConflictingDuplicate),
        _ => Err(measurement_error(path)),
    }
}

fn decode_uncertainty(path: &Path, value: &str) -> Result<AssociationUncertainty, HostError> {
    match value {
        "exact_native_identity" => Ok(AssociationUncertainty::ExactNativeIdentity),
        "late_after_close" => Ok(AssociationUncertainty::LateAfterClose),
        "conflicting_facts" => Ok(AssociationUncertainty::ConflictingFacts),
        _ => Err(measurement_error(path)),
    }
}

fn decode_quality(path: &Path, value: &str) -> Result<EvidenceQuality, HostError> {
    match value {
        "captured" => Ok(EvidenceQuality::Captured),
        "not_captured" => Ok(EvidenceQuality::NotCaptured),
        "lost" => Ok(EvidenceQuality::Lost),
        "invalid" => Ok(EvidenceQuality::Invalid),
        "interpolated" => Ok(EvidenceQuality::Interpolated),
        "training_masked" => Ok(EvidenceQuality::TrainingMasked),
        _ => Err(measurement_error(path)),
    }
}

fn measurement_error(path: &Path) -> HostError {
    HostError::message_at(
        "decode persisted measurement",
        path,
        "persisted measurement or qualification is invalid",
    )
}
