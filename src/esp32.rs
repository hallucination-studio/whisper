//! Deterministic ADR-018/ADR-110 decoding and registry resolution.

use crate::capture::{CapturedPacket, WireFormat};
use crate::config::{FirmwareDialect, Registry, RouteError};
use crate::domain::csi::{
    AcquisitionCapabilities, CaptureProfile, CsiCapture, CsiCaptureError, CsiLayout,
    CsiObservation, CsiPath, CsiSampleAxis, IqSample, LayoutError, PhaseState, PpduKind,
    ProfileCatalog, ProfileDescriptor, ProfileError, RadioMetadata, RadioMetadataError,
    SampleEncoding, ValidityDialect,
};
use crate::domain::identity::{DecoderVersion, HardwareKind, IdError, RadioLinkId, SensorId};
use crate::domain::time::{EventTimeSource, FrameTiming, SessionTime, TimeError, TimeQuality};

/// ADR-018 raw CSI magic in little-endian wire order.
const ADR018_MAGIC: u32 = 0xC511_0001;
/// ADR-110 clock-anchor magic in little-endian wire order.
const ADR110_MAGIC: u32 = 0xC511_A110;
/// ADR-018 header length before complex I/Q pairs, in bytes.
const ADR018_HEADER_BYTES: usize = 20;
/// ADR-110 clock-anchor length, in bytes.
const ADR110_PACKET_BYTES: usize = 32;
/// Two signed bytes encode one ESP-IDF complex pair.
const BYTES_PER_COMPLEX_PAIR: usize = 2;
/// The decoder identity included in every profile and input receipt.
const DECODER_VERSION: &str = "world-esp32-adr-v1";
/// One megahertz expressed in hertz for checked wire conversion.
const HZ_PER_MHZ: u64 = 1_000_000;

/// Errors found while validating a complete ESP32 datagram.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum DecodeError {
    /// The input ended before the specified number of bytes was available.
    #[error("ESP32 datagram is truncated: needed {needed} bytes, received {actual}")]
    Truncated {
        /// Minimum bytes required by the current wire structure.
        needed: usize,
        /// Bytes supplied by the capture boundary.
        actual: usize,
    },
    /// The input contained bytes after an exact wire structure.
    #[error("ESP32 datagram has trailing bytes: expected {expected}, received {actual}")]
    Trailing {
        /// Exact bytes consumed by the declared packet.
        expected: usize,
        /// Bytes supplied by the capture boundary.
        actual: usize,
    },
    /// No supported ESP32 protocol owns this magic.
    #[error("unknown ESP32 datagram magic {magic:#010x}")]
    UnknownMagic {
        /// Four-byte little-endian magic value.
        magic: u32,
    },
    /// A known protocol field violated a structural invariant.
    #[error("malformed ESP32 datagram: {0}")]
    Malformed(#[from] MalformedPacket),
    /// ADR-110's protocol version is not supported by this decoder.
    #[error("unsupported {protocol} protocol version {version}")]
    UnsupportedProtocolVersion {
        /// Protocol whose version field was rejected.
        protocol: &'static str,
        /// Version found on the wire.
        version: u8,
    },
    /// The supplied frequency could not be represented in hertz.
    #[error("frequency {mhz} MHz overflows hertz conversion")]
    FrequencyOverflow {
        /// Frequency in the wire's MHz unit.
        mhz: u64,
    },
}

/// Structural reasons for rejecting an otherwise recognized ESP32 packet.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum MalformedPacket {
    /// ADR-018 declared no paths.
    #[error("ADR-018 path count must be non-zero")]
    ZeroPathCount,
    /// ADR-018 declared no complex pairs per path.
    #[error("ADR-018 sample count per path must be non-zero")]
    ZeroSampleCount,
    /// ADR-018 path/sample arithmetic overflowed the host representation.
    #[error("ADR-018 path/sample payload size overflows usize")]
    PayloadSizeOverflow,
    /// An ADR-110 reserved byte was non-zero.
    #[error("ADR-110 reserved byte at offset {offset} is {value:#04x}")]
    NonZeroReserved {
        /// Byte offset in the wire packet.
        offset: usize,
        /// Unexpected reserved value.
        value: u8,
    },
    /// ADR-110 contained flags outside its declared bit set.
    #[error("ADR-110 contains unsupported flags {flags:#04x}")]
    UnsupportedFlags {
        /// Raw ADR-110 flags byte.
        flags: u8,
    },
}

/// Reasons a structurally valid CSI frame cannot enter inference.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum InferenceIneligible {
    /// The route cannot prove one transmitter/source for this packet.
    #[error("route for link {link} has an unresolved source contract")]
    UnresolvedSource {
        /// Physical link selected by route resolution.
        link: RadioLinkId,
    },
    /// The first-slice firmware has no verified path ordering for this count.
    #[error("ADR-018 path count {path_count} has an unknown wire layout")]
    UnknownPathLayout {
        /// Number of paths declared by the frame.
        path_count: u8,
    },
    /// The wire does not carry the validity signal needed by this dialect.
    #[error("ADR-018 frame-validity information is missing for {dialect:?}")]
    MissingFrameValidity {
        /// Configured validity dialect that cannot be satisfied by this wire.
        dialect: ValidityDialect,
    },
}

/// A typed failure while applying configuration to an ESP32 datagram.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum IngestError {
    /// Wire parsing failed before route resolution.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// The captured transport family is not handled by this decoder.
    #[error("unsupported ESP32 wire format {0:?}")]
    UnsupportedWireFormat(WireFormat),
    /// The capture-wide datagram bound was exceeded.
    #[error("datagram length {actual} exceeds global limit {maximum}")]
    GlobalDatagramTooLarge {
        /// Captured byte length.
        actual: usize,
        /// Configured global maximum.
        maximum: usize,
    },
    /// The route-specific datagram bound was exceeded.
    #[error("datagram length {actual} exceeds route limit {maximum}")]
    RouteDatagramTooLarge {
        /// Captured byte length.
        actual: usize,
        /// Configured route maximum.
        maximum: usize,
    },
    /// Route lookup failed for the packet's peer IP and node.
    #[error(transparent)]
    Route(#[from] RouteError),
    /// A configured Intel route reached the ESP32-only dispatcher.
    #[error("hardware {0} has no ESP32 decoder")]
    UnsupportedHardware(HardwareKind),
    /// The route's source contract was not sufficient for inference.
    #[error(transparent)]
    Inference(#[from] InferenceIneligible),
    /// Wire frequency/channel facts conflict with the selected route.
    #[error(
        "radio facts do not match route: frequency {frequency_mhz} MHz, observed channel {observed_channel:?}, route channel {route_channel:?}"
    )]
    RouteRadioMismatch {
        /// Frequency supplied by ADR-018 in MHz.
        frequency_mhz: u32,
        /// Inverted channel, when the frequency is a known Wi-Fi channel.
        observed_channel: Option<u16>,
        /// Explicit route channel, if configured.
        route_channel: Option<u16>,
    },
    /// The generated profile could not be validated or interned.
    #[error(transparent)]
    Profile(#[from] ProfileError),
    /// The dynamic CSI capture violated domain cardinality.
    #[error(transparent)]
    CsiCapture(#[from] CsiCaptureError),
    /// The generated dynamic layout violated a domain invariant.
    #[error(transparent)]
    Layout(#[from] LayoutError),
    /// Typed radio metadata could not be constructed.
    #[error(transparent)]
    RadioMetadata(#[from] RadioMetadataError),
    /// Receive-only timing construction failed.
    #[error(transparent)]
    Time(#[from] TimeError),
    /// The fixed decoder identity could not be represented as a validated ID.
    #[error(transparent)]
    Identity(#[from] IdError),
}

/// An ADR-018 packet after exact wire parsing, before route/profile resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Adr018Csi {
    node_id: u8,
    path_count: u8,
    sample_count: u16,
    frequency_mhz: u32,
    sequence: u32,
    rssi_dbm: i8,
    noise_floor_dbm: i8,
    extension: Adr018Extension,
    samples: Box<[IqSample]>,
}

/// Decoder-private ADR-018 bytes 18 and 19; unknown bits remain opaque.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Adr018Extension {
    ppdu_raw: u8,
    flags_raw: u8,
}

/// An exact ADR-110 synchronization/clock-anchor packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Adr110Sync {
    node_id: u8,
    protocol_version: u8,
    flags: u8,
    local_us: u64,
    epoch_us: u64,
    high_water_sequence: u32,
}

/// One decoder output before timeline/conditioning consumes it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum DecodedInput {
    /// A route-resolved dynamic CSI observation.
    Csi(CsiObservation),
    /// A route-resolved ADR-110 anchor for diagnostics only.
    ClockAnchor(ClockAnchorObservation),
    /// A known sibling packet intentionally left unsupported.
    Unsupported {
        /// Known magic value owned by a sibling protocol.
        magic: u32,
    },
}

/// A route-resolved ADR-110 observation that never supplies CSI/profile data.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ClockAnchorObservation {
    input: crate::domain::csi::InputReceipt,
    sensor: SensorId,
    hardware: HardwareKind,
    link: RadioLinkId,
    node_id: u8,
    protocol_version: u8,
    flags: u8,
    local_us: u64,
    epoch_us: u64,
    high_water_sequence: u32,
    timing: FrameTiming,
}

impl ClockAnchorObservation {
    /// Returns the session ordering and decoder identity.
    #[must_use]
    pub(crate) const fn input(&self) -> &crate::domain::csi::InputReceipt {
        &self.input
    }

    /// Returns the route-resolved receiving sensor.
    #[must_use]
    pub(crate) const fn sensor(&self) -> &SensorId {
        &self.sensor
    }

    /// Returns the route-resolved hardware family.
    #[must_use]
    pub(crate) const fn hardware(&self) -> HardwareKind {
        self.hardware
    }

    /// Returns the route-resolved physical link.
    #[must_use]
    pub(crate) const fn link(&self) -> &RadioLinkId {
        &self.link
    }

    /// Returns the wire node identifier.
    #[must_use]
    pub(crate) const fn node_id(&self) -> u8 {
        self.node_id
    }

    /// Returns the validated ADR-110 protocol version.
    #[must_use]
    pub(crate) const fn protocol_version(&self) -> u8 {
        self.protocol_version
    }

    /// Returns the validated ADR-110 flags.
    #[must_use]
    pub(crate) const fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the device-local anchor time in microseconds.
    #[must_use]
    pub(crate) const fn local_us(&self) -> u64 {
        self.local_us
    }

    /// Returns the device epoch anchor time in microseconds.
    #[must_use]
    pub(crate) const fn epoch_us(&self) -> u64 {
        self.epoch_us
    }

    /// Returns the node-global sequence paired with the anchor.
    #[must_use]
    pub(crate) const fn high_water_sequence(&self) -> u32 {
        self.high_water_sequence
    }

    /// Returns receive-only frame timing; ADR-110 never corrects it.
    #[must_use]
    pub(crate) const fn timing(&self) -> &FrameTiming {
        &self.timing
    }
}

/// The sole ESP32 wire dispatcher and route/profile resolver.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Esp32Decoder;

impl Esp32Decoder {
    /// Constructs the stateless decoder.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self
    }

    /// Decodes and resolves one captured packet without reading external state.
    pub(crate) fn decode_and_resolve(
        &self,
        packet: &CapturedPacket,
        registry: &Registry,
        global_max_datagram_bytes: u32,
        profiles: &mut ProfileCatalog,
    ) -> Result<DecodedInput, IngestError> {
        let actual = packet.bytes().len();
        let maximum = global_max_datagram_bytes as usize;
        if actual > maximum {
            return Err(IngestError::GlobalDatagramTooLarge { actual, maximum });
        }
        if packet.wire_format() != WireFormat::Esp32Udp {
            return Err(IngestError::UnsupportedWireFormat(packet.wire_format()));
        }

        match decode_esp32_datagram(packet.bytes())? {
            Esp32Packet::Unsupported { magic } => Ok(DecodedInput::Unsupported { magic }),
            Esp32Packet::Csi(frame) => self.resolve_csi(packet, registry, profiles, frame),
            Esp32Packet::ClockAnchor(anchor) => self.resolve_clock_anchor(packet, registry, anchor),
        }
    }

    fn resolve_csi(
        &self,
        packet: &CapturedPacket,
        registry: &Registry,
        profiles: &mut ProfileCatalog,
        frame: Adr018Csi,
    ) -> Result<DecodedInput, IngestError> {
        let resolved = registry.resolve_route(packet.peer().ip(), frame.node_id)?;
        let actual = packet.bytes().len();
        let maximum = resolved.route.maximum_valid_datagram_bytes() as usize;
        if actual > maximum {
            return Err(IngestError::RouteDatagramTooLarge { actual, maximum });
        }

        let hardware = resolved.sensor.hardware_kind();
        if hardware == HardwareKind::Intel5300 {
            return Err(IngestError::UnsupportedHardware(hardware));
        }
        if !resolved.link.source_contract().inference_eligible() {
            return Err(
                InferenceIneligible::UnresolvedSource { link: resolved.link.id().clone() }.into()
            );
        }

        let (channel, centre_frequency_hz) = radio_frequency_and_channel(
            frame.frequency_mhz,
            resolved.link.channel_policy().allowed(),
            resolved.route.channel(),
        )?;
        let (ppdu, bandwidth_hz) =
            extension_metadata(frame.extension, resolved.sensor.adr018().he_tagging());

        if frame.path_count != 1 {
            return Err(
                InferenceIneligible::UnknownPathLayout { path_count: frame.path_count }.into()
            );
        }

        let validity_dialect = resolved.sensor.adr018().validity_dialect();
        if !matches!(validity_dialect, ValidityDialect::FirstWordInvalid) {
            return Err(
                InferenceIneligible::MissingFrameValidity { dialect: validity_dialect }.into()
            );
        }

        let layout = CsiLayout::try_new(
            vec![CsiPath::RawPathOrdinal(0)],
            CsiSampleAxis::try_opaque(frame.sample_count)?,
            crate::domain::csi::SampleOrder::PathThenSample,
        )?;
        let profile = CaptureProfile::try_new(ProfileDescriptor {
            hardware,
            firmware: resolved.sensor.firmware().to_owned().into_boxed_str(),
            decoder_version: DECODER_VERSION.into(),
            capability_id: capability_id(
                resolved.sensor.adr018().firmware_dialect(),
                resolved.sensor.adr018().he_tagging(),
            )
            .into(),
            acquisition: AcquisitionCapabilities {
                mode: resolved.sensor.adr018().csi_acquire(),
                ltf_selection: resolved.sensor.adr018().ltf_selection(),
                ltf_merge: resolved.sensor.adr018().ltf_merge(),
                validity_dialect,
            },
            channel,
            centre_frequency_hz,
            bandwidth_hz,
            ppdu,
            layout,
            encoding: SampleEncoding::try_new(
                8,
                1,
                1,
                crate::domain::csi::ComplexOrder::ImaginaryReal,
            )
            .expect("fixed ESP-IDF byte encoding is valid"),
            phase_state: PhaseState::Unavailable,
            time_quality: TimeQuality::ReceiveOnly,
            clock_domain: None,
        })?;
        let profile_id = profiles.intern(profile)?;

        let mut samples = frame.samples.into_vec();
        for sample in samples.iter_mut().take(2) {
            sample.valid = false;
        }
        let csi = CsiCapture::try_new(
            CsiLayout::try_new(
                vec![CsiPath::RawPathOrdinal(0)],
                CsiSampleAxis::try_opaque(frame.sample_count)?,
                crate::domain::csi::SampleOrder::PathThenSample,
            )?,
            samples.into_boxed_slice(),
            SampleEncoding::try_new(8, 1, 1, crate::domain::csi::ComplexOrder::ImaginaryReal)
                .expect("fixed ESP-IDF byte encoding is valid"),
            PhaseState::Unavailable,
        )?;
        let timing = receive_only_timing(packet)?;
        let radio = RadioMetadata::try_new(
            channel,
            centre_frequency_hz,
            bandwidth_hz,
            ppdu,
            frame.rssi_dbm,
            frame.noise_floor_dbm,
        )?;
        let input = input_receipt(packet)?;
        let observation = CsiObservation::new(
            input,
            resolved.sensor.id().clone(),
            hardware,
            resolved.link.id().clone(),
            frame.sequence,
            timing,
            radio,
            profile_id,
            csi,
        );
        Ok(DecodedInput::Csi(observation))
    }

    fn resolve_clock_anchor(
        &self,
        packet: &CapturedPacket,
        registry: &Registry,
        anchor: Adr110Sync,
    ) -> Result<DecodedInput, IngestError> {
        let resolved = registry.resolve_route(packet.peer().ip(), anchor.node_id)?;
        let actual = packet.bytes().len();
        let maximum = resolved.route.maximum_valid_datagram_bytes() as usize;
        if actual > maximum {
            return Err(IngestError::RouteDatagramTooLarge { actual, maximum });
        }
        if resolved.sensor.hardware_kind() == HardwareKind::Intel5300 {
            return Err(IngestError::UnsupportedHardware(HardwareKind::Intel5300));
        }
        let timing = receive_only_timing(packet)?;
        let input = input_receipt(packet)?;
        Ok(DecodedInput::ClockAnchor(ClockAnchorObservation {
            input,
            sensor: resolved.sensor.id().clone(),
            hardware: resolved.sensor.hardware_kind(),
            link: resolved.link.id().clone(),
            node_id: anchor.node_id,
            protocol_version: anchor.protocol_version,
            flags: anchor.flags,
            local_us: anchor.local_us,
            epoch_us: anchor.epoch_us,
            high_water_sequence: anchor.high_water_sequence,
            timing,
        }))
    }
}

/// Parses the dispatcher-owned protocol magic and then validates its exact structure.
fn decode_esp32_datagram(bytes: &[u8]) -> Result<Esp32Packet, DecodeError> {
    if bytes.len() < std::mem::size_of::<u32>() {
        return Err(DecodeError::Truncated { needed: 4, actual: bytes.len() });
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    match magic {
        ADR018_MAGIC => decode_adr018(bytes).map(Esp32Packet::Csi),
        ADR110_MAGIC => decode_adr110(bytes).map(Esp32Packet::ClockAnchor),
        0xC511_0002..=0xC511_0007 => Ok(Esp32Packet::Unsupported { magic }),
        _ => Err(DecodeError::UnknownMagic { magic }),
    }
}

/// Parses an ADR-018 frame with exact header/payload accounting.
fn decode_adr018(bytes: &[u8]) -> Result<Adr018Csi, DecodeError> {
    if bytes.len() < ADR018_HEADER_BYTES {
        return Err(DecodeError::Truncated { needed: ADR018_HEADER_BYTES, actual: bytes.len() });
    }
    let path_count = bytes[5];
    if path_count == 0 {
        return Err(MalformedPacket::ZeroPathCount.into());
    }
    let sample_count = u16::from_le_bytes([bytes[6], bytes[7]]);
    if sample_count == 0 {
        return Err(MalformedPacket::ZeroSampleCount.into());
    }
    let pair_count = checked_pair_count(path_count as usize, sample_count as usize)?;
    let payload_bytes = pair_count
        .checked_mul(BYTES_PER_COMPLEX_PAIR)
        .ok_or(MalformedPacket::PayloadSizeOverflow)?;
    let expected = ADR018_HEADER_BYTES
        .checked_add(payload_bytes)
        .ok_or(MalformedPacket::PayloadSizeOverflow)?;
    if bytes.len() < expected {
        return Err(DecodeError::Truncated { needed: expected, actual: bytes.len() });
    }
    if bytes.len() > expected {
        return Err(DecodeError::Trailing { expected, actual: bytes.len() });
    }

    let mut samples = Vec::with_capacity(pair_count);
    for pair in bytes[ADR018_HEADER_BYTES..expected].chunks_exact(BYTES_PER_COMPLEX_PAIR) {
        let q = i32::from(i8::from_ne_bytes([pair[0]]));
        let i = i32::from(i8::from_ne_bytes([pair[1]]));
        samples.push(IqSample::new(i, q));
    }
    Ok(Adr018Csi {
        node_id: bytes[4],
        path_count,
        sample_count,
        frequency_mhz: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        sequence: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        rssi_dbm: i8::from_ne_bytes([bytes[16]]),
        noise_floor_dbm: i8::from_ne_bytes([bytes[17]]),
        extension: Adr018Extension { ppdu_raw: bytes[18], flags_raw: bytes[19] },
        samples: samples.into_boxed_slice(),
    })
}

/// Parses ADR-110's exact 32-byte clock-anchor structure.
fn decode_adr110(bytes: &[u8]) -> Result<Adr110Sync, DecodeError> {
    if bytes.len() < ADR110_PACKET_BYTES {
        return Err(DecodeError::Truncated { needed: ADR110_PACKET_BYTES, actual: bytes.len() });
    }
    if bytes.len() > ADR110_PACKET_BYTES {
        return Err(DecodeError::Trailing { expected: ADR110_PACKET_BYTES, actual: bytes.len() });
    }
    let protocol_version = bytes[5];
    if protocol_version != 1 {
        return Err(DecodeError::UnsupportedProtocolVersion {
            protocol: "ADR-110",
            version: protocol_version,
        });
    }
    let flags = bytes[6];
    if flags & !0x07 != 0 {
        return Err(MalformedPacket::UnsupportedFlags { flags }.into());
    }
    if bytes[7] != 0 {
        return Err(MalformedPacket::NonZeroReserved { offset: 7, value: bytes[7] }.into());
    }
    for (offset, value) in bytes[28..32].iter().copied().enumerate() {
        if value != 0 {
            return Err(MalformedPacket::NonZeroReserved { offset: 28 + offset, value }.into());
        }
    }
    Ok(Adr110Sync {
        node_id: bytes[4],
        protocol_version,
        flags,
        local_us: u64::from_le_bytes(bytes[8..16].try_into().expect("checked ADR-110 length")),
        epoch_us: u64::from_le_bytes(bytes[16..24].try_into().expect("checked ADR-110 length")),
        high_water_sequence: u32::from_le_bytes(
            bytes[24..28].try_into().expect("checked ADR-110 length"),
        ),
    })
}

/// Converts a wire MHz value to hertz without wrapping.
fn checked_mhz_to_hz(mhz: u64) -> Result<u64, DecodeError> {
    mhz.checked_mul(HZ_PER_MHZ).ok_or(DecodeError::FrequencyOverflow { mhz })
}

/// Inverts the exact Wi-Fi channel formula used by the wire contract.
fn channel_for_frequency_mhz(mhz: u64) -> Option<u16> {
    if (2412..=2472).contains(&mhz) && (mhz - 2412).is_multiple_of(5) {
        return Some(((mhz - 2412) / 5 + 1) as u16);
    }
    if mhz == 2484 {
        return Some(14);
    }
    if (5180..=5885).contains(&mhz) && mhz.is_multiple_of(5) {
        let channel = (mhz - 5000) / 5;
        if (36..=177).contains(&channel) && 5000 + 5 * channel == mhz {
            return Some(channel as u16);
        }
    }
    None
}

/// Resolves the observed radio facts and checks only the allowed/route channel contract.
fn radio_frequency_and_channel(
    frequency_mhz: u32,
    allowed_channels: &[u16],
    route_channel: Option<u16>,
) -> Result<(Option<u16>, Option<u64>), IngestError> {
    if frequency_mhz == 0 {
        return Ok((None, None));
    }
    let frequency_hz = checked_mhz_to_hz(u64::from(frequency_mhz))?;
    let observed_channel = channel_for_frequency_mhz(u64::from(frequency_mhz));
    if observed_channel.is_none()
        || !observed_channel.is_some_and(|channel| allowed_channels.contains(&channel))
        || route_channel.is_some_and(|channel| observed_channel != Some(channel))
    {
        return Err(IngestError::RouteRadioMismatch {
            frequency_mhz,
            observed_channel,
            route_channel,
        });
    }
    Ok((observed_channel, Some(frequency_hz)))
}

/// Interprets extension bytes only when the configured route explicitly enables tagging.
fn extension_metadata(
    extension: Adr018Extension,
    he_tagging: bool,
) -> (Option<PpduKind>, Option<u64>) {
    if !he_tagging {
        return (None, None);
    }
    let ppdu = matches!(extension.ppdu_raw, 1..=3).then_some(PpduKind::He);
    let bandwidth_hz = Some(if extension.flags_raw & 0x01 == 0 { 20_000_000 } else { 40_000_000 });
    (ppdu, bandwidth_hz)
}

/// Gives profiles an explicit stable capability identity without inferring wire semantics.
fn checked_pair_count(path_count: usize, sample_count: usize) -> Result<usize, DecodeError> {
    path_count.checked_mul(sample_count).ok_or(MalformedPacket::PayloadSizeOverflow.into())
}

fn capability_id(dialect: FirmwareDialect, he_tagging: bool) -> &'static str {
    match (dialect, he_tagging) {
        (FirmwareDialect::EspIdf, false) => "adr018/esp-idf/untagged",
        (FirmwareDialect::EspIdf, true) => "adr018/esp-idf/tagged",
        (FirmwareDialect::EspIdfHe, false) => "adr018/esp-idf-he/untagged",
        (FirmwareDialect::EspIdfHe, true) => "adr018/esp-idf-he/tagged",
    }
}

fn input_receipt(packet: &CapturedPacket) -> Result<crate::domain::csi::InputReceipt, IngestError> {
    Ok(crate::domain::csi::InputReceipt::new(
        packet.session_id().clone(),
        packet.record_seq(),
        DecoderVersion::new(DECODER_VERSION)?,
    ))
}

fn receive_only_timing(packet: &CapturedPacket) -> Result<FrameTiming, IngestError> {
    let received = SessionTime::from_nanos(packet.receive_monotonic_ns());
    Ok(FrameTiming::try_new(received, None, received, EventTimeSource::ReceiveOnly, None, 0)?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Esp32Packet {
    Csi(Adr018Csi),
    ClockAnchor(Adr110Sync),
    Unsupported { magic: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CapturedPacket;
    use crate::config::{EffectiveConfig, parse_config};
    use crate::domain::csi::{ComplexOrder, LtfMerge, LtfSelection};
    use crate::domain::identity::SessionId;
    use sha2::{Digest, Sha256};

    const VALID_CONFIG: &str = include_str!("../tests/fixtures/config/valid-two-esp32.toml");
    const HE_FIXTURE: &str = include_str!("../tests/fixtures/esp32/adr018_c6_node12_he_su_256.hex");
    const HT_FIXTURE: &str = include_str!("../tests/fixtures/esp32/adr018_c6_node12_ht_64.hex");
    const HE_SHA256: &str = "e788d4c585dbcf33677cfbfe30fb186b8274faefea6ec0bf20a6c31ba1190b61";
    const HT_SHA256: &str = "0bb2b09e62e7603f8c4a5c82a38a42df445393a41f1ac0ca120b8329bca3df2d";

    fn unhex(source: &str) -> Vec<u8> {
        let source = source.trim();
        assert!(source.len().is_multiple_of(2));
        source
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).expect("hex high nibble");
                let low = (pair[1] as char).to_digit(16).expect("hex low nibble");
                ((high << 4) | low) as u8
            })
            .collect()
    }

    fn session() -> SessionId {
        SessionId::new("test-session").expect("valid session")
    }

    fn packet(bytes: Vec<u8>, peer: &str) -> CapturedPacket {
        CapturedPacket::new(
            session(),
            7,
            123_456,
            1_700_000_000_000_000_000,
            peer.parse().expect("peer"),
            WireFormat::Esp32Udp,
            bytes.into_boxed_slice(),
        )
    }

    fn config() -> EffectiveConfig {
        parse_config(VALID_CONFIG).expect("valid config")
    }

    fn decoder() -> Esp32Decoder {
        Esp32Decoder::new()
    }

    fn make_adr018(
        node: u8,
        path_count: u8,
        samples: u16,
        frequency_mhz: u32,
        ppdu: u8,
        flags: u8,
    ) -> Vec<u8> {
        let pair_count = usize::from(path_count) * usize::from(samples);
        let mut bytes = vec![0; ADR018_HEADER_BYTES + pair_count * 2];
        bytes[0..4].copy_from_slice(&ADR018_MAGIC.to_le_bytes());
        bytes[4] = node;
        bytes[5] = path_count;
        bytes[6..8].copy_from_slice(&samples.to_le_bytes());
        bytes[8..12].copy_from_slice(&frequency_mhz.to_le_bytes());
        bytes[12..16].copy_from_slice(&42_u32.to_le_bytes());
        bytes[16] = (-40_i8) as u8;
        bytes[17] = (-90_i8) as u8;
        bytes[18] = ppdu;
        bytes[19] = flags;
        for (index, pair) in bytes[ADR018_HEADER_BYTES..].chunks_exact_mut(2).enumerate() {
            pair[0] = index as u8;
            pair[1] = (index as i8).wrapping_neg() as u8;
        }
        bytes
    }

    fn make_adr110(node: u8) -> Vec<u8> {
        let mut bytes = vec![0; ADR110_PACKET_BYTES];
        bytes[0..4].copy_from_slice(&ADR110_MAGIC.to_le_bytes());
        bytes[4] = node;
        bytes[5] = 1;
        bytes[6] = 0x07;
        bytes[8..16].copy_from_slice(&123_u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&456_u64.to_le_bytes());
        bytes[24..28].copy_from_slice(&42_u32.to_le_bytes());
        bytes
    }

    fn csi_from(decoded: &DecodedInput) -> &CsiObservation {
        match decoded {
            DecodedInput::Csi(observation) => observation,
            other => panic!("expected CSI, received {other:?}"),
        }
    }

    #[test]
    fn real_live_fixtures_have_pinned_sha_and_dynamic_lengths() {
        let he = unhex(HE_FIXTURE);
        let ht = unhex(HT_FIXTURE);
        assert_eq!(he.len(), 532);
        assert_eq!(ht.len(), 148);
        let he_digest = format_digest(Sha256::digest(&he));
        let ht_digest = format_digest(Sha256::digest(&ht));
        assert_eq!(he_digest, HE_SHA256);
        assert_eq!(ht_digest, HT_SHA256);

        let Esp32Packet::Csi(he_frame) = decode_esp32_datagram(&he).expect("real HE fixture")
        else {
            panic!("fixture is not ADR-018 CSI");
        };
        let Esp32Packet::Csi(ht_frame) = decode_esp32_datagram(&ht).expect("real HT fixture")
        else {
            panic!("fixture is not ADR-018 CSI");
        };
        assert_eq!(he_frame.sample_count, 256);
        assert_eq!(ht_frame.sample_count, 64);
        assert_eq!(he_frame.node_id, 12);
        assert_eq!(ht_frame.node_id, 12);
        assert_eq!(he_frame.frequency_mhz, 2432);
        assert_eq!(ht_frame.frequency_mhz, 2432);
        assert_eq!(he_frame.samples.len(), 256);
        assert_eq!(ht_frame.samples.len(), 64);
        assert_eq!(he_frame.samples[0], IqSample::new(0, 0));
        assert_eq!(ht_frame.samples[0], IqSample::new(0, 0));
    }

    #[test]
    fn every_truncated_prefix_of_real_fixtures_is_an_error() {
        for source in [HE_FIXTURE, HT_FIXTURE] {
            let bytes = unhex(source);
            for length in 0..bytes.len() {
                assert!(
                    decode_esp32_datagram(&bytes[..length]).is_err(),
                    "prefix {length} accepted"
                );
            }
        }
    }

    #[test]
    fn dispatcher_classifies_sibling_and_unknown_magic_without_route_lookup() {
        for suffix in 2_u8..=7 {
            let bytes = (0xC511_0000 + u32::from(suffix)).to_le_bytes().to_vec();
            assert_eq!(
                decode_esp32_datagram(&bytes),
                Ok(Esp32Packet::Unsupported { magic: 0xC511_0000 + u32::from(suffix) })
            );
        }
        assert_eq!(
            decode_esp32_datagram(&0xDEAD_BEEFu32.to_le_bytes()),
            Err(DecodeError::UnknownMagic { magic: 0xDEAD_BEEF })
        );
        assert_eq!(
            decode_esp32_datagram(&[1, 2, 3]),
            Err(DecodeError::Truncated { needed: 4, actual: 3 })
        );
    }

    #[test]
    fn adr018_rejects_zero_counts_length_and_trailing_bytes() {
        let mut zero_path = make_adr018(1, 1, 1, 2412, 0, 0);
        zero_path[5] = 0;
        assert_eq!(decode_esp32_datagram(&zero_path), Err(MalformedPacket::ZeroPathCount.into()));
        let mut zero_samples = make_adr018(1, 1, 1, 2412, 0, 0);
        zero_samples[6..8].copy_from_slice(&0_u16.to_le_bytes());
        assert_eq!(
            decode_esp32_datagram(&zero_samples),
            Err(MalformedPacket::ZeroSampleCount.into())
        );

        let valid = make_adr018(1, 1, 2, 2412, 0, 0);
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(matches!(decode_esp32_datagram(&trailing), Err(DecodeError::Trailing { .. })));
        assert!(matches!(
            decode_esp32_datagram(&valid[..valid.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn checked_frequency_helper_and_channel_inverse_are_bounded() {
        assert_eq!(checked_mhz_to_hz(2412), Ok(2_412_000_000));
        assert!(matches!(checked_mhz_to_hz(u64::MAX), Err(DecodeError::FrequencyOverflow { .. })));
        assert!(matches!(
            checked_pair_count(usize::MAX, 2),
            Err(DecodeError::Malformed(MalformedPacket::PayloadSizeOverflow))
        ));
        assert_eq!(channel_for_frequency_mhz(2412), Some(1));
        assert_eq!(channel_for_frequency_mhz(2472), Some(13));
        assert_eq!(channel_for_frequency_mhz(2484), Some(14));
        assert_eq!(channel_for_frequency_mhz(5180), Some(36));
        assert_eq!(channel_for_frequency_mhz(5885), Some(177));
        assert_eq!(channel_for_frequency_mhz(2433), None);
    }

    #[test]
    fn q_first_i_second_and_legacy_first_two_pairs_are_preserved() {
        let bytes = make_adr018(1, 1, 3, 2412, 0, 0);
        let frame = match decode_esp32_datagram(&bytes).expect("valid") {
            Esp32Packet::Csi(frame) => frame,
            _ => panic!("expected CSI"),
        };
        assert_eq!(frame.samples[0], IqSample::new(0, 0));
        assert_eq!(frame.samples[1], IqSample::new(-1, 1));
        assert_eq!(frame.extension.ppdu_raw, 0);
        assert_eq!(frame.extension.flags_raw, 0);
    }

    #[test]
    fn resolve_uses_peer_ip_not_source_port_and_keeps_receive_only_timing() {
        let config = config();
        let bytes = make_adr018(1, 1, 3, 2412, 0, 0);
        let received_packet = packet(bytes, "192.0.2.10:6000");
        let mut profiles = ProfileCatalog::default();
        let decoded = decoder()
            .decode_and_resolve(
                &received_packet,
                config.registry(),
                config.capture().max_datagram_bytes(),
                &mut profiles,
            )
            .expect("route-resolved CSI");
        let observation = csi_from(&decoded);
        assert_eq!(observation.sensor().as_str(), "sensor-a");
        assert_eq!(observation.link().as_str(), "link-a");
        assert_eq!(observation.timing().received(), SessionTime::from_nanos(123_456));
        assert_eq!(observation.timing().event(), observation.timing().received());
        assert_eq!(observation.timing().source(), EventTimeSource::ReceiveOnly);
        assert!(observation.timing().device().is_none());
        assert_eq!(observation.timing().mapping_version(), None);
        assert!(!observation.csi().samples()[0].valid);
        assert!(!observation.csi().samples()[1].valid);
        assert!(observation.csi().samples()[2].valid);
        assert_eq!(observation.radio().channel(), Some(1));
        assert_eq!(observation.radio().centre_frequency_hz(), Some(2_412_000_000));

        let zero_frequency_packet = packet(make_adr018(1, 1, 3, 0, 0, 0), "192.0.2.10:6000");
        let mut zero_frequency_profiles = ProfileCatalog::default();
        let zero_frequency = decoder()
            .decode_and_resolve(
                &zero_frequency_packet,
                config.registry(),
                config.capture().max_datagram_bytes(),
                &mut zero_frequency_profiles,
            )
            .expect("zero frequency is an unknown radio fact, not a route mismatch");
        let zero_radio = csi_from(&zero_frequency).radio();
        assert_eq!(zero_radio.channel(), None);
        assert_eq!(zero_radio.centre_frequency_hz(), None);
    }

    #[test]
    fn resolver_rejects_global_route_source_and_radio_contracts_in_order() {
        let config = config();
        let bytes = make_adr018(1, 1, 3, 2412, 0, 0);
        let packet_a = packet(bytes.clone(), "192.0.2.10:5005");
        let mut profiles = ProfileCatalog::default();
        assert!(matches!(
            decoder().decode_and_resolve(&packet_a, config.registry(), 2, &mut profiles),
            Err(IngestError::GlobalDatagramTooLarge { .. })
        ));

        let route_limited =
            parse_config(&VALID_CONFIG.replace(
                "maximum_valid_datagram_bytes = 2048",
                "maximum_valid_datagram_bytes = 20",
            ))
            .expect("route limit remains within global limit");
        assert!(matches!(
            decoder().decode_and_resolve(
                &packet_a,
                route_limited.registry(),
                route_limited.capture().max_datagram_bytes(),
                &mut profiles,
            ),
            Err(IngestError::RouteDatagramTooLarge { .. })
        ));

        let unknown = packet(bytes.clone(), "192.0.2.99:5005");
        assert!(matches!(
            decoder().decode_and_resolve(
                &unknown,
                config.registry(),
                config.capture().max_datagram_bytes(),
                &mut profiles,
            ),
            Err(IngestError::Route(RouteError::Unknown { .. }))
        ));

        let unprovisioned =
            parse_config(&VALID_CONFIG.replace("provisioned = true", "provisioned = false"))
                .expect("source contract remains loadable");
        assert!(matches!(
            decoder().decode_and_resolve(
                &packet_a,
                unprovisioned.registry(),
                unprovisioned.capture().max_datagram_bytes(),
                &mut profiles,
            ),
            Err(IngestError::Inference(InferenceIneligible::UnresolvedSource { .. }))
        ));

        let mismatch = packet(make_adr018(1, 1, 3, 2437, 0, 0), "192.0.2.10:5005");
        assert!(matches!(
            decoder().decode_and_resolve(
                &mismatch,
                config.registry(),
                config.capture().max_datagram_bytes(),
                &mut profiles,
            ),
            Err(IngestError::RouteRadioMismatch { .. })
        ));
    }

    #[test]
    fn path_count_other_than_one_is_ineligible_without_assuming_order() {
        let config = config();
        let packet = packet(make_adr018(1, 2, 2, 2412, 0, 0), "192.0.2.10:5005");
        let mut profiles = ProfileCatalog::default();
        assert!(matches!(
            decoder().decode_and_resolve(
                &packet,
                config.registry(),
                config.capture().max_datagram_bytes(),
                &mut profiles,
            ),
            Err(IngestError::Inference(InferenceIneligible::UnknownPathLayout { path_count: 2 }))
        ));
    }

    #[test]
    fn he_extension_requires_tagging_and_unknown_raw_values_stay_unknown() {
        let untagged = make_adr018(1, 1, 1, 2412, 1, 1);
        let frame = match decode_esp32_datagram(&untagged).expect("valid") {
            Esp32Packet::Csi(frame) => frame,
            _ => panic!("expected CSI"),
        };
        assert_eq!(extension_metadata(frame.extension, false), (None, None));
        assert_eq!(
            extension_metadata(Adr018Extension { ppdu_raw: 0xff, flags_raw: 0xff }, true),
            (None, Some(40_000_000))
        );
    }

    #[test]
    fn c6_missing_validity_is_ineligible_and_profile_identity_includes_capabilities() {
        let config = config();
        let packet = packet(make_adr018(2, 1, 3, 2437, 1, 0), "192.0.2.11:5005");
        let mut profiles = ProfileCatalog::default();
        assert!(matches!(
            decoder().decode_and_resolve(
                &packet,
                config.registry(),
                config.capture().max_datagram_bytes(),
                &mut profiles,
            ),
            Err(IngestError::Inference(InferenceIneligible::MissingFrameValidity {
                dialect: ValidityDialect::MissingFrameValidity
            }))
        ));

        let legacy = CaptureProfile::try_new(ProfileDescriptor {
            hardware: HardwareKind::Esp32S3,
            firmware: "test".into(),
            decoder_version: DECODER_VERSION.into(),
            capability_id: "a".into(),
            acquisition: AcquisitionCapabilities {
                mode: crate::domain::csi::AcquisitionMode::WifiCsi,
                ltf_selection: LtfSelection::Legacy,
                ltf_merge: LtfMerge::None,
                validity_dialect: ValidityDialect::FirstWordInvalid,
            },
            channel: Some(1),
            centre_frequency_hz: Some(2_412_000_000),
            bandwidth_hz: None,
            ppdu: None,
            layout: CsiLayout::try_new(
                vec![CsiPath::RawPathOrdinal(0)],
                CsiSampleAxis::try_opaque(3).expect("axis"),
                crate::domain::csi::SampleOrder::PathThenSample,
            )
            .expect("layout"),
            encoding: SampleEncoding::try_new(8, 1, 1, ComplexOrder::ImaginaryReal)
                .expect("encoding"),
            phase_state: PhaseState::Unavailable,
            time_quality: TimeQuality::ReceiveOnly,
            clock_domain: None,
        })
        .expect("profile");
        let mut changed = legacy.descriptor().clone();
        changed.acquisition.ltf_selection = LtfSelection::Ht;
        let changed = CaptureProfile::try_new(changed).expect("profile");
        assert_ne!(legacy.id(), changed.id());
        let mut changed_validity = legacy.descriptor().clone();
        changed_validity.acquisition.validity_dialect = ValidityDialect::Unknown;
        let changed_validity = CaptureProfile::try_new(changed_validity).expect("profile");
        assert_ne!(legacy.id(), changed_validity.id());
    }

    #[test]
    fn adr110_is_exact_strict_receive_only_anchor() {
        let config = config();
        let bytes = make_adr110(1);
        let packet = packet(bytes.clone(), "192.0.2.10:5005");
        let mut profiles = ProfileCatalog::default();
        let decoded = decoder()
            .decode_and_resolve(
                &packet,
                config.registry(),
                config.capture().max_datagram_bytes(),
                &mut profiles,
            )
            .expect("anchor");
        let DecodedInput::ClockAnchor(anchor) = decoded else {
            panic!("expected anchor");
        };
        assert_eq!(anchor.input().record_seq(), 7);
        assert_eq!(anchor.sensor().as_str(), "sensor-a");
        assert_eq!(anchor.hardware(), HardwareKind::Esp32S3);
        assert_eq!(anchor.link().as_str(), "link-a");
        assert_eq!(anchor.node_id(), 1);
        assert_eq!(anchor.protocol_version(), 1);
        assert_eq!(anchor.flags(), 0x07);
        assert_eq!(anchor.local_us(), 123);
        assert_eq!(anchor.epoch_us(), 456);
        assert_eq!(anchor.high_water_sequence(), 42);
        assert_eq!(anchor.timing().source(), EventTimeSource::ReceiveOnly);
        assert_eq!(anchor.timing().device(), None);
        assert_eq!(profiles.snapshot().iter().count(), 0);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(decode_esp32_datagram(&trailing), Err(DecodeError::Trailing { .. })));
        for length in 0..bytes.len() {
            assert!(decode_esp32_datagram(&bytes[..length]).is_err());
        }
        let mut wrong_version = bytes.clone();
        wrong_version[5] = 2;
        assert_eq!(
            decode_esp32_datagram(&wrong_version),
            Err(DecodeError::UnsupportedProtocolVersion { protocol: "ADR-110", version: 2 })
        );
        let mut wrong_flags = bytes.clone();
        wrong_flags[6] = 0x08;
        assert!(matches!(
            decode_esp32_datagram(&wrong_flags),
            Err(DecodeError::Malformed(MalformedPacket::UnsupportedFlags { .. }))
        ));
        let mut reserved = bytes;
        reserved[31] = 1;
        assert!(matches!(
            decode_esp32_datagram(&reserved),
            Err(DecodeError::Malformed(MalformedPacket::NonZeroReserved { offset: 31, .. }))
        ));
    }

    #[test]
    fn repeated_decode_is_semantically_stable_and_devices_do_not_share_state() {
        let config = config();
        let bytes = make_adr018(1, 1, 2, 2412, 0, 0);
        let first_raw_bytes = bytes.clone();
        let first_packet = packet(bytes.clone(), "192.0.2.10:5005");
        let mut profiles = ProfileCatalog::default();
        let first = decoder()
            .decode_and_resolve(
                &first_packet,
                config.registry(),
                config.capture().max_datagram_bytes(),
                &mut profiles,
            )
            .expect("first");
        let first_again = decoder()
            .decode_and_resolve(
                &first_packet,
                config.registry(),
                config.capture().max_datagram_bytes(),
                &mut profiles,
            )
            .expect("repeat");
        assert_eq!(first, first_again);
        assert_eq!(first_packet.bytes(), first_raw_bytes.as_slice());
        let two_s3_config = parse_config(
            &VALID_CONFIG
                .replace("hardware_kind = \"esp32-c6\"", "hardware_kind = \"esp32-s3\"")
                .replace("firmware = \"adr018-c6-1\"", "firmware = \"adr018-s3-2\"")
                .replace("firmware_dialect = \"esp-idf-he\"", "firmware_dialect = \"esp-idf\"")
                .replace("he_tagging = true", "he_tagging = false")
                .replace("ltf_selection = \"he\"", "ltf_selection = \"legacy\"")
                .replace("ltf_merge = \"firmware-defined\"", "ltf_merge = \"none\"")
                .replace(
                    "validity_dialect = \"missing-frame-validity\"",
                    "validity_dialect = \"first-word-invalid\"",
                ),
        )
        .expect("two configured legacy-compatible devices");
        let second_raw_bytes = make_adr018(2, 1, 2, 2437, 0, 0);
        let second_packet = CapturedPacket::new(
            session(),
            8,
            123_457,
            1,
            "192.0.2.11:5006".parse().expect("peer"),
            WireFormat::Esp32Udp,
            second_raw_bytes.clone().into_boxed_slice(),
        );
        let second = decoder()
            .decode_and_resolve(
                &second_packet,
                two_s3_config.registry(),
                two_s3_config.capture().max_datagram_bytes(),
                &mut profiles,
            )
            .expect("second device sequence domain remains decoder-stateless");
        assert_eq!(second_packet.bytes(), second_raw_bytes.as_slice());
        assert_eq!(csi_from(&first).device_sequence(), csi_from(&second).device_sequence());
        assert_eq!(csi_from(&first).hardware(), HardwareKind::Esp32S3);
        assert_eq!(csi_from(&second).hardware(), HardwareKind::Esp32S3);
        assert_ne!(csi_from(&first).sensor(), csi_from(&second).sensor());
        assert_ne!(csi_from(&first).input().record_seq(), csi_from(&second).input().record_seq());
        assert_eq!(profiles.snapshot().iter().count(), 2);
    }

    fn format_digest<D: AsRef<[u8]>>(digest: D) -> String {
        digest.as_ref().iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
