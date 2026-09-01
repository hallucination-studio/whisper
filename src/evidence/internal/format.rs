use super::package::*;
use super::*;
use std::net::Ipv6Addr;

pub(super) fn validate_physical_root(physical: &PhysicalInput) -> Result<(), EvidenceError> {
    if physical.schema_version != 1
        || physical.fixture.kind != "development_fixture"
        || physical.fixture.sensor_id.is_empty()
        || sensitive_string(&physical.fixture.sensor_id)
        || !is_sha256(&physical.fixture.capability_sha256)
        || !is_sha256(&physical.fixture.firmware_image_sha256)
        || !is_sha256(&physical.fixture.provisioning_sha256)
        || physical.datagrams.is_empty()
    {
        return Err(EvidenceError::Json("physical-input.json".to_owned()));
    }
    let device_id = &physical.datagrams[0].device_id;
    for (index, datagram) in physical.datagrams.iter().enumerate() {
        let expected_path = format!("datagrams/{index:06}.bin");
        if datagram.path != expected_path
            || datagram.receive_order != index.to_string()
            || parse_decimal(&datagram.device_id).is_none()
            || datagram.device_id != *device_id
            || parse_decimal(&datagram.key_epoch).is_none()
            || parse_decimal(&datagram.received_monotonic_ns).is_none()
            || parse_decimal(&datagram.received_utc_ns).is_none()
            || !is_sha256(&datagram.body_binding_sha256)
            || !is_sha256(&datagram.sha256)
            || datagram.context.transport != "udp"
            || datagram.context.wire_format != "native_frame_v1"
            || datagram.context.capture_session_id.is_empty()
            || sensitive_string(&datagram.context.capture_session_id)
            || parse_decimal(&datagram.context.capture_record_seq).is_none()
            || parse_decimal(&datagram.context.capture_session_time).is_none()
            || parse_decimal(&datagram.context.semantic_record_seq).is_none()
            || parse_decimal(&datagram.context.semantic_session_time).is_none()
        {
            return Err(EvidenceError::Manifest("physical-input.json".to_owned()));
        }
    }
    Ok(())
}

pub(super) fn producer_paths(physical: &PhysicalInput) -> Vec<(&str, &str)> {
    let mut paths = vec![
        ("host-commit-trace.json", JSON_MEDIA_TYPE),
        ("physical-input.json", JSON_MEDIA_TYPE),
        ("restart-trace.json", JSON_MEDIA_TYPE),
        ("store-post-continuation.cbor", CBOR_MEDIA_TYPE),
        ("store-post-rebuild.cbor", CBOR_MEDIA_TYPE),
        ("store-pre-stop.cbor", CBOR_MEDIA_TYPE),
    ];
    paths.extend(physical.datagrams.iter().map(|entry| (entry.path.as_str(), BYTES_MEDIA_TYPE)));
    paths.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    paths
}

pub(super) fn observer_paths() -> Vec<(&'static str, &'static str)> {
    let mut paths = vec![
        ("chrome-trace.json", JSON_MEDIA_TYPE),
        ("http/stable-post-restart.json", JSON_MEDIA_TYPE),
        ("http/stable-pre-restart.json", JSON_MEDIA_TYPE),
        ("http/unknown.json", JSON_MEDIA_TYPE),
        ("screenshots/stable-post-restart.png", PNG_MEDIA_TYPE),
        ("screenshots/stable-pre-restart.png", PNG_MEDIA_TYPE),
        ("screenshots/unknown.png", PNG_MEDIA_TYPE),
        ("websocket.json", JSON_MEDIA_TYPE),
    ];
    paths.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    paths
}

pub(super) fn expected_tree(physical: &PhysicalInput) -> Result<BTreeSet<String>, EvidenceError> {
    let mut paths = BTreeSet::from(["run.json".to_owned(), "observer.json".to_owned()]);
    for (path, _) in producer_paths(physical).into_iter().chain(observer_paths()) {
        validate_relative_path(path)?;
        paths.insert(path.to_owned());
    }
    Ok(paths)
}

pub(super) fn validate_manifest(
    owner: &str,
    artifacts: &[Artifact],
    expected: Vec<(&str, &str)>,
    files: &BTreeMap<String, ReadArtifact>,
) -> Result<(), EvidenceError> {
    if artifacts.len() != expected.len() {
        return Err(EvidenceError::Manifest(owner.to_owned()));
    }
    let mut previous: Option<&str> = None;
    for (artifact, (expected_path, expected_type)) in artifacts.iter().zip(expected) {
        validate_relative_path(&artifact.path)?;
        if artifact.path != expected_path
            || artifact.media_type != expected_type
            || !is_sha256(&artifact.sha256)
            || previous.is_some_and(|path| path.as_bytes() >= artifact.path.as_bytes())
        {
            return Err(EvidenceError::Manifest(owner.to_owned()));
        }
        previous = Some(&artifact.path);
        if files.get(&artifact.path).map(|file| file.digest.as_str()) != Some(&artifact.sha256) {
            return Err(EvidenceError::Digest(artifact.path.clone()));
        }
    }
    Ok(())
}

pub(super) fn validate_formats(
    files: &BTreeMap<String, ReadArtifact>,
) -> Result<(), EvidenceError> {
    for (path, artifact) in files {
        if path.ends_with(".json") {
            let _: JsonValue = parse_canonical_json(path, &artifact.bytes)?;
        } else if path.ends_with(".cbor") {
            validate_canonical_cbor(path, &artifact.bytes)?;
        } else if path.ends_with(".png") {
            validate_png(path, &artifact.bytes)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct PngDimensions {
    pub(super) height: u32,
    pub(super) width: u32,
}

#[derive(Clone, Copy)]
pub(super) struct PngHeader {
    bytes_per_pixel: usize,
    dimensions: PngDimensions,
}

pub(super) struct PngImage {
    pub(super) dimensions: PngDimensions,
    pub(super) pixels: Vec<u8>,
}

pub(super) fn validate_png(path: &str, bytes: &[u8]) -> Result<PngImage, EvidenceError> {
    if !bytes.starts_with(PNG_SIGNATURE) {
        return Err(EvidenceError::Png(path.to_owned()));
    }
    let mut offset = PNG_SIGNATURE.len();
    let mut saw_header = false;
    let mut saw_image_data = false;
    let mut saw_end = false;
    let mut png_header = None;
    let mut compressed = Vec::new();
    while offset < bytes.len() {
        let header_end =
            offset.checked_add(8).ok_or_else(|| EvidenceError::Png(path.to_owned()))?;
        let header =
            bytes.get(offset..header_end).ok_or_else(|| EvidenceError::Png(path.to_owned()))?;
        let length = usize::try_from(u32::from_be_bytes(
            header[..4].try_into().map_err(|_| EvidenceError::Png(path.to_owned()))?,
        ))
        .map_err(|_| EvidenceError::Png(path.to_owned()))?;
        let chunk_type: [u8; 4] =
            header[4..].try_into().map_err(|_| EvidenceError::Png(path.to_owned()))?;
        if !chunk_type.iter().all(u8::is_ascii_alphabetic) {
            return Err(EvidenceError::Png(path.to_owned()));
        }
        let data_end =
            header_end.checked_add(length).ok_or_else(|| EvidenceError::Png(path.to_owned()))?;
        let chunk_end =
            data_end.checked_add(4).ok_or_else(|| EvidenceError::Png(path.to_owned()))?;
        let data =
            bytes.get(header_end..data_end).ok_or_else(|| EvidenceError::Png(path.to_owned()))?;
        let expected_crc = u32::from_be_bytes(
            bytes
                .get(data_end..chunk_end)
                .ok_or_else(|| EvidenceError::Png(path.to_owned()))?
                .try_into()
                .map_err(|_| EvidenceError::Png(path.to_owned()))?,
        );
        if png_crc(&bytes[offset + 4..data_end]) != expected_crc {
            return Err(EvidenceError::Png(path.to_owned()));
        }
        match &chunk_type {
            b"IHDR" => {
                if saw_header || offset != PNG_SIGNATURE.len() {
                    return Err(EvidenceError::Png(path.to_owned()));
                }
                png_header = valid_png_header(data);
                if png_header.is_none() {
                    return Err(EvidenceError::Png(path.to_owned()));
                }
                saw_header = true;
            }
            b"IDAT" => {
                if !saw_header || saw_end || data.is_empty() {
                    return Err(EvidenceError::Png(path.to_owned()));
                }
                compressed.extend_from_slice(data);
                saw_image_data = true;
            }
            b"IEND" => {
                if !saw_header || !saw_image_data || saw_end || !data.is_empty() {
                    return Err(EvidenceError::Png(path.to_owned()));
                }
                saw_end = true;
            }
            _ => return Err(EvidenceError::Png(path.to_owned())),
        }
        offset = chunk_end;
    }
    if !saw_header || !saw_image_data || !saw_end {
        return Err(EvidenceError::Png(path.to_owned()));
    }
    let png_header = png_header.ok_or_else(|| EvidenceError::Png(path.to_owned()))?;
    let dimensions = png_header.dimensions;
    let pixels = validate_png_pixels(path, png_header, &compressed)?;
    Ok(PngImage { dimensions, pixels })
}

pub(super) fn valid_png_header(data: &[u8]) -> Option<PngHeader> {
    if data.len() != 13 {
        return None;
    }
    let width = u32::from_be_bytes(data[..4].try_into().expect("checked IHDR width"));
    let height = u32::from_be_bytes(data[4..8].try_into().expect("checked IHDR height"));
    if width == 0
        || height == 0
        || data[8] != 8
        || !matches!(data[9], 2 | 6)
        || data[10] != 0
        || data[11] != 0
        || data[12] != 0
    {
        return None;
    }
    let bytes_per_pixel = if data[9] == 2 { 3 } else { 4 };
    Some(PngHeader { bytes_per_pixel, dimensions: PngDimensions { height, width } })
}

pub(super) fn validate_png_pixels(
    path: &str,
    header: PngHeader,
    compressed: &[u8],
) -> Result<Vec<u8>, EvidenceError> {
    let dimensions = header.dimensions;
    let row_bytes = usize::try_from(dimensions.width)
        .ok()
        .and_then(|width| width.checked_mul(header.bytes_per_pixel))
        .ok_or_else(|| EvidenceError::Png(path.to_owned()))?;
    let row_size = row_bytes.checked_add(1).ok_or_else(|| EvidenceError::Png(path.to_owned()))?;
    let expected = usize::try_from(dimensions.height)
        .ok()
        .and_then(|height| height.checked_mul(row_size))
        .ok_or_else(|| EvidenceError::Png(path.to_owned()))?;
    let rgba_len = usize::try_from(dimensions.width)
        .ok()
        .and_then(|width| {
            usize::try_from(dimensions.height).ok().and_then(|height| width.checked_mul(height))
        })
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| EvidenceError::Png(path.to_owned()))?;
    if expected > MAX_SCREENSHOT_DECODED_BYTES || rgba_len > MAX_SCREENSHOT_DECODED_BYTES {
        return Err(EvidenceError::Png(path.to_owned()));
    }
    let limit = u64::try_from(expected)
        .ok()
        .and_then(|expected| expected.checked_add(1))
        .ok_or_else(|| EvidenceError::Png(path.to_owned()))?;
    let mut pixels = Vec::new();
    pixels.try_reserve_exact(expected).map_err(|_| EvidenceError::Png(path.to_owned()))?;
    ZlibDecoder::new(compressed)
        .take(limit)
        .read_to_end(&mut pixels)
        .map_err(|_| EvidenceError::Png(path.to_owned()))?;
    if pixels.len() != expected || pixels.chunks_exact(row_size).any(|row| row[0] > 4) {
        return Err(EvidenceError::Png(path.to_owned()));
    }
    let decoded_len = row_bytes
        .checked_mul(
            usize::try_from(dimensions.height).map_err(|_| EvidenceError::Png(path.to_owned()))?,
        )
        .ok_or_else(|| EvidenceError::Png(path.to_owned()))?;
    let mut decoded = Vec::new();
    decoded.try_reserve_exact(decoded_len).map_err(|_| EvidenceError::Png(path.to_owned()))?;
    decoded.resize(decoded_len, 0);
    for (row_index, encoded) in pixels.chunks_exact(row_size).enumerate() {
        let filter = encoded[0];
        let source = &encoded[1..];
        let row_start = row_index * row_bytes;
        for (column, value) in source.iter().copied().enumerate() {
            let left = if column >= header.bytes_per_pixel {
                decoded[row_start + column - header.bytes_per_pixel]
            } else {
                0
            };
            let above = if row_index > 0 { decoded[row_start + column - row_bytes] } else { 0 };
            let upper_left = if row_index > 0 && column >= header.bytes_per_pixel {
                decoded[row_start + column - row_bytes - header.bytes_per_pixel]
            } else {
                0
            };
            let predictor = match filter {
                0 => 0,
                1 => left,
                2 => above,
                3 => ((u16::from(left) + u16::from(above)) / 2) as u8,
                4 => paeth_predictor(left, above, upper_left),
                _ => return Err(EvidenceError::Png(path.to_owned())),
            };
            decoded[row_start + column] = value.wrapping_add(predictor);
        }
    }
    drop(pixels);
    if header.bytes_per_pixel == 3 {
        let pixel_count = rgba_len / 4;
        decoded.try_reserve_exact(pixel_count).map_err(|_| EvidenceError::Png(path.to_owned()))?;
        decoded.resize(rgba_len, 0);
        for index in (0..pixel_count).rev() {
            let red = decoded[index * 3];
            let green = decoded[index * 3 + 1];
            let blue = decoded[index * 3 + 2];
            decoded[index * 4] = red;
            decoded[index * 4 + 1] = green;
            decoded[index * 4 + 2] = blue;
            decoded[index * 4 + 3] = 255;
        }
    }
    Ok(decoded)
}

pub(super) fn paeth_predictor(left: u8, above: u8, upper_left: u8) -> u8 {
    let left = i32::from(left);
    let above = i32::from(above);
    let upper_left = i32::from(upper_left);
    let prediction = left + above - upper_left;
    let left_distance = (prediction - left).abs();
    let above_distance = (prediction - above).abs();
    let upper_left_distance = (prediction - upper_left).abs();
    if left_distance <= above_distance && left_distance <= upper_left_distance {
        left as u8
    } else if above_distance <= upper_left_distance {
        above as u8
    } else {
        upper_left as u8
    }
}

pub(super) fn png_crc(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

pub(super) fn validate_sensitive_cleartext(
    files: &BTreeMap<String, ReadArtifact>,
) -> Result<(), EvidenceError> {
    for (path, artifact) in files {
        if path.starts_with("datagrams/") {
            continue;
        }
        if path.ends_with(".json") {
            let value: JsonValue = serde_json::from_slice(&artifact.bytes)
                .map_err(|_| EvidenceError::Json(path.clone()))?;
            inspect_json_cleartext(path, &value)?;
        } else if path.ends_with(".cbor") {
            let value: CborValue = ciborium::from_reader(artifact.bytes.as_slice())
                .map_err(|_| EvidenceError::Cbor(path.clone()))?;
            inspect_cbor_cleartext(path, &value)?;
        }
    }
    Ok(())
}

pub(super) fn inspect_cbor_cleartext(path: &str, value: &CborValue) -> Result<(), EvidenceError> {
    match value {
        CborValue::Map(fields) => {
            for (key, value) in fields {
                if let CborValue::Text(key) = key
                    && forbidden_sensitive_key(key)
                {
                    return Err(EvidenceError::Sensitive(path.to_owned()));
                }
                inspect_cbor_cleartext(path, key)?;
                inspect_cbor_cleartext(path, value)?;
            }
        }
        CborValue::Array(values) => {
            for value in values {
                inspect_cbor_cleartext(path, value)?;
            }
        }
        CborValue::Text(value) if sensitive_string(value) => {
            return Err(EvidenceError::Sensitive(path.to_owned()));
        }
        CborValue::Tag(_, value) => inspect_cbor_cleartext(path, value)?,
        _ => {}
    }
    Ok(())
}

pub(super) fn inspect_json_cleartext(path: &str, value: &JsonValue) -> Result<(), EvidenceError> {
    match value {
        JsonValue::Object(fields) => {
            for (key, value) in fields {
                if forbidden_sensitive_key(key) {
                    return Err(EvidenceError::Sensitive(path.to_owned()));
                }
                inspect_json_cleartext(path, value)?;
            }
        }
        JsonValue::Array(values) => {
            for value in values {
                inspect_json_cleartext(path, value)?;
            }
        }
        JsonValue::String(value) if sensitive_string(value) => {
            return Err(EvidenceError::Sensitive(path.to_owned()));
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn forbidden_sensitive_key(key: &str) -> bool {
    matches!(
        key,
        "ssid"
            | "password"
            | "credential"
            | "credentials"
            | "key_bytes"
            | "peer"
            | "peer_address"
            | "private_address"
            | "secret_path"
            | "source_mac"
            | "wifi_password"
    )
}

pub(super) fn sensitive_string(value: &str) -> bool {
    value.starts_with("/Users/")
        || value.starts_with("/private/")
        || value.starts_with("/var/")
        || contains_mac(value)
        || contains_private_ipv4(value)
        || contains_private_ipv6(value)
}

pub(super) fn contains_mac(value: &str) -> bool {
    value
        .split(|character: char| {
            !character.is_ascii_hexdigit() && !matches!(character, ':' | '-' | '.')
        })
        .any(|token| {
            if token.len() == 12 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return true;
            }
            if token.len() == 14 {
                let parts = token.split('.').collect::<Vec<_>>();
                if parts.len() == 3
                    && parts.iter().all(|part| {
                        part.len() == 4 && part.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                {
                    return true;
                }
            }
            let separator = if token.contains(':') {
                ':'
            } else if token.contains('-') {
                '-'
            } else {
                return false;
            };
            let parts = token.split(separator).collect::<Vec<_>>();
            parts.len() == 6
                && parts.iter().all(|part| {
                    part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        })
}

pub(super) fn contains_private_ipv6(value: &str) -> bool {
    value
        .split(|character: char| {
            !character.is_ascii_hexdigit() && character != ':' && character != '.'
        })
        .filter(|token| token.contains(':'))
        .filter_map(|token| token.parse::<Ipv6Addr>().ok())
        .any(|address| {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address.to_ipv4_mapped().is_some_and(|ipv4| {
                    let octets = ipv4.octets();
                    private_ipv4_octets(&octets)
                })
        })
}

pub(super) fn contains_private_ipv4(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .filter(|token| token.matches('.').count() == 3)
        .filter_map(|token| {
            let octets =
                token.split('.').map(str::parse::<u8>).collect::<Result<Vec<_>, _>>().ok()?;
            (octets.len() == 4).then_some(octets)
        })
        .any(|octets| private_ipv4_octets(&octets))
}

fn private_ipv4_octets(octets: &[u8]) -> bool {
    octets[0] == 10
        || octets[0] == 127
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
}
