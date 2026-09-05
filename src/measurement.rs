//! Bounded RF measurement assembly and explicit physical-input qualification.

use std::backtrace::Backtrace;
use std::collections::BTreeMap;
use std::fmt;

use crate::{BootGeneration, DeviceId, KeyEpoch, SensorId};

const MAX_OPEN_ASSEMBLIES: usize = 1_024;
const MAX_FRAGMENTS: u16 = 1_024;
const MAX_ASSEMBLY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 256;
const MAX_EVIDENCE_MEMBERS: usize = 1_024;
const MAX_PORT_ENTRIES: usize = 256;
/// Host default residence limit in source-native ticks. Changing this alters
/// when unattended partial assemblies become eligible for explicit expiry.
const HOST_ASSEMBLY_WAIT_TICKS: u64 = 1_000_000;

macro_rules! opaque_digest {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Preserves an already established opaque identity.
            #[must_use]
            pub const fn new(value: [u8; 32]) -> Self {
                Self(value)
            }

            /// Returns the preserved identity bytes.
            #[must_use]
            pub const fn bytes(self) -> [u8; 32] {
                self.0
            }
        }
    };
}

opaque_digest!(TransmitterIdentity, "Opaque transmitter identity in its native namespace.");
opaque_digest!(NativeEventIdentity, "Opaque identity assigned by the native capture source.");
opaque_digest!(RetransmissionIdentity, "Genuine native retransmission identity, when available.");
opaque_digest!(ProfileIdentity, "Exact capture and interpretation profile identity.");
opaque_digest!(RadioIdentity, "Exact native radio-mode identity.");
opaque_digest!(ChannelIdentity, "Exact native channel configuration identity.");
opaque_digest!(FitIdentity, "Identity of an independently established clock fit.");
opaque_digest!(PhaseReferenceIdentity, "Identity of an independently established phase reference.");
opaque_digest!(EvidenceMemberIdentity, "Identity of one immutable evidence member.");

/// One exact sensor process and authenticated source generation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceInstance {
    sensor: SensorId,
    device: DeviceId,
    key_epoch: KeyEpoch,
    boot: BootGeneration,
}

impl SourceInstance {
    /// Groups every boundary at which a source identity may change.
    #[must_use]
    pub const fn new(
        sensor: SensorId,
        device: DeviceId,
        key_epoch: KeyEpoch,
        boot: BootGeneration,
    ) -> Self {
        Self { sensor, device, key_epoch, boot }
    }

    /// Returns the configured sensor identity.
    #[must_use]
    pub const fn sensor(&self) -> &SensorId {
        &self.sensor
    }
    /// Returns the opaque device identity.
    #[must_use]
    pub const fn device(&self) -> DeviceId {
        self.device
    }
    /// Returns the authentication-key epoch.
    #[must_use]
    pub const fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }
    /// Returns the persistent boot generation.
    #[must_use]
    pub const fn boot(&self) -> BootGeneration {
        self.boot
    }
}

/// Native identities that denote one physical capture event.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventIdentity {
    transmitter: TransmitterIdentity,
    native_event: NativeEventIdentity,
    retransmission: Option<RetransmissionIdentity>,
}

impl EventIdentity {
    /// Groups a native event with genuine retransmission information only.
    #[must_use]
    pub const fn new(
        transmitter: TransmitterIdentity,
        native_event: NativeEventIdentity,
        retransmission: Option<RetransmissionIdentity>,
    ) -> Self {
        Self { transmitter, native_event, retransmission }
    }

    /// Returns the transmitter identity.
    #[must_use]
    pub const fn transmitter(self) -> TransmitterIdentity {
        self.transmitter
    }
    /// Returns the source-native event identity.
    #[must_use]
    pub const fn native_event(self) -> NativeEventIdentity {
        self.native_event
    }
    /// Returns genuine retransmission identity, if the source supplied one.
    #[must_use]
    pub const fn retransmission(self) -> Option<RetransmissionIdentity> {
        self.retransmission
    }
}

/// Capture boundaries under which fragments may be assembled.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MeasurementContext {
    profile: ProfileIdentity,
    radio: RadioIdentity,
    channel: ChannelIdentity,
}

impl MeasurementContext {
    /// Groups exact capture profile, radio, and channel identities.
    #[must_use]
    pub const fn new(
        profile: ProfileIdentity,
        radio: RadioIdentity,
        channel: ChannelIdentity,
    ) -> Self {
        Self { profile, radio, channel }
    }

    /// Returns the profile identity.
    #[must_use]
    pub const fn profile(self) -> ProfileIdentity {
        self.profile
    }
    /// Returns the radio identity.
    #[must_use]
    pub const fn radio(self) -> RadioIdentity {
        self.radio
    }
    /// Returns the channel identity.
    #[must_use]
    pub const fn channel(self) -> ChannelIdentity {
        self.channel
    }
}

/// Immutable identity shared by fragments from one native RF event.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AssemblyKey {
    source: SourceInstance,
    event: EventIdentity,
    context: MeasurementContext,
}

impl AssemblyKey {
    /// Joins the source, native event, and capture-boundary groups.
    #[must_use]
    pub const fn new(
        source: SourceInstance,
        event: EventIdentity,
        context: MeasurementContext,
    ) -> Self {
        Self { source, event, context }
    }

    /// Returns the complete source instance.
    #[must_use]
    pub const fn source(&self) -> &SourceInstance {
        &self.source
    }
    /// Returns the native event group.
    #[must_use]
    pub const fn event(&self) -> EventIdentity {
        self.event
    }
    /// Returns the capture-boundary group.
    #[must_use]
    pub const fn context(&self) -> MeasurementContext {
        self.context
    }
}

/// A source-native monotonic tick; ticks from different source instances never mix.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceTick(u64);

impl SourceTick {
    /// Preserves a source-native tick.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    /// Returns the native value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A nonzero residence-time limit measured in source ticks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitTicks(u64);

impl WaitTicks {
    /// Constructs a nonzero wait bound.
    pub fn new(value: u64) -> Result<Self, MeasurementError> {
        (value != 0)
            .then_some(Self(value))
            .ok_or_else(|| MeasurementError::new("wait bound must be nonzero"))
    }
}

/// An inclusive source-native tick interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TickRange {
    start: SourceTick,
    end: SourceTick,
}

impl TickRange {
    /// Constructs an ordered inclusive interval.
    pub fn new(start: SourceTick, end: SourceTick) -> Result<Self, MeasurementError> {
        (start <= end)
            .then_some(Self { start, end })
            .ok_or_else(|| MeasurementError::new("tick range is reversed"))
    }
    /// Returns the first included tick.
    #[must_use]
    pub const fn start(self) -> SourceTick {
        self.start
    }
    /// Returns the last included tick.
    #[must_use]
    pub const fn end(self) -> SourceTick {
        self.end
    }
    fn covers(self, other: Self) -> bool {
        self.start <= other.start && self.end >= other.end
    }
}

/// Identity of one independently established qualification revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationEpoch(u64);

impl QualificationEpoch {
    /// Preserves an external revision identity.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    /// Returns the external value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Unit attached to a conservative relation error bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorUnit {
    /// Nanoseconds.
    Nanoseconds,
    /// Milliradians.
    Milliradians,
    /// Millimetres.
    Millimetres,
    /// Parts per million.
    PartsPerMillion,
}

/// Conservative nonnegative error with an explicit unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorBound {
    value: u64,
    unit: ErrorUnit,
}

impl ErrorBound {
    /// Groups the magnitude with its non-interchangeable unit.
    #[must_use]
    pub const fn new(value: u64, unit: ErrorUnit) -> Self {
        Self { value, unit }
    }
    /// Returns the magnitude.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }
    /// Returns the unit.
    #[must_use]
    pub const fn unit(self) -> ErrorUnit {
        self.unit
    }
}

/// Explicit state of an observation used by quality and eligibility decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceQuality {
    /// Captured and source-valid.
    Captured,
    /// Capture was not attempted.
    NotCaptured,
    /// An expected capture was lost.
    Lost,
    /// Bytes were present but invalid as physical evidence.
    Invalid,
    /// Values were interpolated rather than captured.
    Interpolated,
    /// Training deliberately masked this observation.
    TrainingMasked,
}

/// Ordinal and declared member count for one fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentPosition {
    ordinal: u16,
    expected: u16,
}

impl FragmentPosition {
    /// Constructs a position inside a nonempty declared member set.
    pub fn new(ordinal: u16, expected: u16) -> Result<Self, MeasurementError> {
        (expected != 0 && ordinal < expected)
            .then_some(Self { ordinal, expected })
            .ok_or_else(|| MeasurementError::new("fragment ordinal must be inside a non-empty set"))
    }
    /// Returns the zero-based ordinal.
    #[must_use]
    pub const fn ordinal(self) -> u16 {
        self.ordinal
    }
    /// Returns the declared member count.
    #[must_use]
    pub const fn expected(self) -> u16 {
        self.expected
    }
}

/// A fragment byte contribution within the finite assembly ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentBytes(u32);

impl FragmentBytes {
    /// Constructs a byte count within the finite assembly ceiling.
    pub fn new(value: u32) -> Result<Self, MeasurementError> {
        (u64::from(value) <= MAX_ASSEMBLY_BYTES)
            .then_some(Self(value))
            .ok_or_else(|| MeasurementError::new("fragment bytes exceed the assembly ceiling"))
    }
    /// Returns the byte count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Immutable source-fact identity, size, and quality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentFact {
    digest: [u8; 32],
    bytes: FragmentBytes,
    quality: EvidenceQuality,
}

impl FragmentFact {
    /// Groups the immutable source-fact properties.
    #[must_use]
    pub const fn new(digest: [u8; 32], bytes: FragmentBytes, quality: EvidenceQuality) -> Self {
        Self { digest, bytes, quality }
    }
    /// Returns source-fact digest.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
    /// Returns the declared payload size.
    #[must_use]
    pub const fn bytes(self) -> FragmentBytes {
        self.bytes
    }
    /// Returns the explicit quality state.
    #[must_use]
    pub const fn quality(self) -> EvidenceQuality {
        self.quality
    }
}

/// One immutable fragment offered to measurement assembly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasurementFragment {
    key: AssemblyKey,
    position: FragmentPosition,
    fact: FragmentFact,
}

impl MeasurementFragment {
    /// Constructs a fragment from its three semantic groups.
    #[must_use]
    pub const fn new(key: AssemblyKey, position: FragmentPosition, fact: FragmentFact) -> Self {
        Self { key, position, fact }
    }
    /// Returns the assembly identity.
    #[must_use]
    pub const fn key(&self) -> &AssemblyKey {
        &self.key
    }
    /// Returns the fragment position.
    #[must_use]
    pub const fn position(&self) -> FragmentPosition {
        self.position
    }
    /// Returns the fragment fact.
    #[must_use]
    pub const fn fact(&self) -> FragmentFact {
        self.fact
    }
}

/// Simultaneous-open, per-assembly fragment, and per-assembly byte ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssemblyCapacity {
    open: usize,
    fragments: u16,
    bytes: u64,
}

impl AssemblyCapacity {
    /// Constructs capacity values within the implementation's finite ceilings.
    pub fn new(open: usize, fragments: u16, bytes: u64) -> Result<Self, MeasurementError> {
        if open == 0
            || open > MAX_OPEN_ASSEMBLIES
            || fragments == 0
            || fragments > MAX_FRAGMENTS
            || bytes == 0
            || bytes > MAX_ASSEMBLY_BYTES
        {
            return Err(MeasurementError::new("assembly capacity is outside finite bounds"));
        }
        Ok(Self { open, fragments, bytes })
    }
}

/// Fixed resource ceilings for one in-memory assembler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssemblyLimits {
    capacity: AssemblyCapacity,
    wait: WaitTicks,
}

impl AssemblyLimits {
    /// Groups capacity and residence-time bounds.
    #[must_use]
    pub const fn new(capacity: AssemblyCapacity, wait: WaitTicks) -> Self {
        Self { capacity, wait }
    }

    pub(crate) fn host_default() -> Self {
        Self::new(
            AssemblyCapacity::new(MAX_OPEN_ASSEMBLIES, MAX_FRAGMENTS, MAX_ASSEMBLY_BYTES)
                .expect("host assembly capacity constants are valid"),
            WaitTicks::new(HOST_ASSEMBLY_WAIT_TICKS).expect("host assembly wait constant is valid"),
        )
    }
}

/// Why membership in a measurement became immutable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssemblyCloseReason {
    /// Every declared fragment was present.
    Complete,
    /// Residence time reached its bound.
    WaitLimit,
    /// Declared membership exceeded its bound.
    CountLimit,
    /// Retained member bytes exceeded their bound.
    ByteLimit,
    /// Simultaneous open assemblies reached their bound.
    ResourceLimit,
    /// The event already had a durable primary close.
    LateFragment,
    /// The same ordinal and immutable fact were observed again.
    DuplicateFragment,
    /// The same ordinal named different immutable facts.
    ConflictingDuplicate,
}

/// Association confidence retained with every close decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationUncertainty {
    /// Native identities establish exact association.
    ExactNativeIdentity,
    /// The fact is known only to follow a durable close.
    LateAfterClose,
    /// Conflicting facts prevent unique association.
    ConflictingFacts,
}

/// One member fixed by an assembly close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssemblyMember {
    ordinal: u16,
    fact_digest: [u8; 32],
    payload_bytes: u32,
    quality: EvidenceQuality,
}

impl AssemblyMember {
    pub(crate) const fn persisted(
        ordinal: u16,
        fact_digest: [u8; 32],
        payload_bytes: u32,
        quality: EvidenceQuality,
    ) -> Self {
        Self { ordinal, fact_digest, payload_bytes, quality }
    }
    /// Returns the fragment ordinal.
    #[must_use]
    pub const fn ordinal(self) -> u16 {
        self.ordinal
    }
    /// Returns the source-fact digest.
    #[must_use]
    pub const fn fact_digest(self) -> [u8; 32] {
        self.fact_digest
    }
    /// Returns the byte contribution.
    #[must_use]
    pub const fn payload_bytes(self) -> u32 {
        self.payload_bytes
    }
    /// Returns the explicit quality state.
    #[must_use]
    pub const fn quality(self) -> EvidenceQuality {
        self.quality
    }
}

impl From<MeasurementFragment> for AssemblyMember {
    fn from(value: MeasurementFragment) -> Self {
        Self {
            ordinal: value.position.ordinal,
            fact_digest: value.fact.digest,
            payload_bytes: value.fact.bytes.get(),
            quality: value.fact.quality,
        }
    }
}

/// Durable decision fixing one measurement's members, gaps, and uncertainty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssemblyClose {
    key: AssemblyKey,
    expected_fragments: u16,
    members: Box<[AssemblyMember]>,
    missing_ordinals: Box<[u16]>,
    reason: AssemblyCloseReason,
    uncertainty: AssociationUncertainty,
    total_bytes: u64,
}

impl AssemblyClose {
    pub(crate) fn persisted(
        key: AssemblyKey,
        expected_fragments: u16,
        members: Box<[AssemblyMember]>,
        missing_ordinals: Box<[u16]>,
        reason: AssemblyCloseReason,
        uncertainty: AssociationUncertainty,
        total_bytes: u64,
    ) -> Self {
        Self {
            key,
            expected_fragments,
            members,
            missing_ordinals,
            reason,
            uncertainty,
            total_bytes,
        }
    }
    /// Returns the immutable event identity.
    #[must_use]
    pub const fn key(&self) -> &AssemblyKey {
        &self.key
    }
    /// Returns the originally declared member count.
    #[must_use]
    pub const fn expected_fragments(&self) -> u16 {
        self.expected_fragments
    }
    /// Returns members in ordinal order.
    #[must_use]
    pub fn members(&self) -> &[AssemblyMember] {
        &self.members
    }
    /// Returns explicitly absent ordinals.
    #[must_use]
    pub fn missing_ordinals(&self) -> &[u16] {
        &self.missing_ordinals
    }
    /// Returns the explicit close reason.
    #[must_use]
    pub const fn reason(&self) -> AssemblyCloseReason {
        self.reason
    }
    /// Returns association uncertainty.
    #[must_use]
    pub const fn uncertainty(&self) -> AssociationUncertainty {
        self.uncertainty
    }
    /// Returns retained bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

#[derive(Debug)]
struct OpenAssembly {
    first_tick: SourceTick,
    expected: u16,
    members: BTreeMap<u16, AssemblyMember>,
    total_bytes: u64,
}

/// Deterministic bounded assembler keyed only by native event facts.
#[derive(Debug)]
pub struct MeasurementAssembler {
    limits: AssemblyLimits,
    open: BTreeMap<AssemblyKey, OpenAssembly>,
}

impl MeasurementAssembler {
    /// Creates an empty assembler with fixed resource bounds.
    #[must_use]
    pub fn new(limits: AssemblyLimits) -> Self {
        Self { limits, open: BTreeMap::new() }
    }

    /// Incorporates one fragment and emits every immutable decision caused by it.
    pub fn ingest(
        &mut self,
        fragment: MeasurementFragment,
        arrival: SourceTick,
    ) -> Result<Vec<AssemblyClose>, MeasurementError> {
        self.ingest_inner(fragment, arrival, true)
    }

    pub(crate) fn restore(
        &mut self,
        fragment: MeasurementFragment,
        arrival: SourceTick,
    ) -> Result<(), MeasurementError> {
        let closes = self.ingest_inner(fragment, arrival, false)?;
        if closes.is_empty() {
            Ok(())
        } else {
            Err(MeasurementError::new("persisted open fragment closes during restore"))
        }
    }

    fn ingest_inner(
        &mut self,
        fragment: MeasurementFragment,
        arrival: SourceTick,
        enforce_resources: bool,
    ) -> Result<Vec<AssemblyClose>, MeasurementError> {
        let key = fragment.key.clone();
        if !self.open.contains_key(&key) && self.open.len() == self.limits.capacity.open {
            return Ok(vec![Self::isolated_close(fragment, AssemblyCloseReason::ResourceLimit)]);
        }
        let open = self.open.entry(key.clone()).or_insert_with(|| OpenAssembly {
            first_tick: arrival,
            expected: fragment.position.expected,
            members: BTreeMap::new(),
            total_bytes: 0,
        });
        if open.expected != fragment.position.expected {
            return Ok(vec![self.close_with(&key, AssemblyCloseReason::ConflictingDuplicate)]);
        }
        if let Some(existing) = open.members.get(&fragment.position.ordinal) {
            if existing.fact_digest == fragment.fact.digest {
                return Ok(vec![Self::isolated_close(
                    fragment,
                    AssemblyCloseReason::DuplicateFragment,
                )]);
            }
            return Ok(vec![self.close_with(&key, AssemblyCloseReason::ConflictingDuplicate)]);
        }
        open.total_bytes = open
            .total_bytes
            .checked_add(u64::from(fragment.fact.bytes.get()))
            .ok_or_else(|| MeasurementError::new("assembly byte count overflowed"))?;
        open.members.insert(fragment.position.ordinal, fragment.into());
        let reason = if enforce_resources && open.expected > self.limits.capacity.fragments {
            Some(AssemblyCloseReason::CountLimit)
        } else if enforce_resources && open.total_bytes > self.limits.capacity.bytes {
            Some(AssemblyCloseReason::ByteLimit)
        } else if open.members.len() == usize::from(open.expected) {
            Some(AssemblyCloseReason::Complete)
        } else {
            None
        };
        Ok(reason.map(|reason| vec![self.close_with(&key, reason)]).unwrap_or_default())
    }

    /// Closes assemblies from one source whose bounded wait elapsed.
    #[must_use]
    pub fn expire(&mut self, source: &SourceInstance, now: SourceTick) -> Vec<AssemblyClose> {
        let keys = self
            .open
            .iter()
            .filter_map(|(key, open)| {
                (key.source() == source
                    && now.get().saturating_sub(open.first_tick.get()) >= self.limits.wait.0)
                    .then_some(key.clone())
            })
            .collect::<Vec<_>>();
        keys.into_iter().map(|key| self.close_with(&key, AssemblyCloseReason::WaitLimit)).collect()
    }

    /// Creates a separate late-arrival fact after durable storage proves an earlier close.
    #[must_use]
    pub fn late(fragment: MeasurementFragment) -> AssemblyClose {
        Self::isolated_close(fragment, AssemblyCloseReason::LateFragment)
    }

    fn isolated_close(fragment: MeasurementFragment, reason: AssemblyCloseReason) -> AssemblyClose {
        let expected = fragment.position.expected;
        let ordinal = fragment.position.ordinal;
        let total_bytes = u64::from(fragment.fact.bytes.get());
        let uncertainty = if reason == AssemblyCloseReason::LateFragment {
            AssociationUncertainty::LateAfterClose
        } else {
            AssociationUncertainty::ExactNativeIdentity
        };
        AssemblyClose {
            key: fragment.key.clone(),
            expected_fragments: expected,
            members: vec![fragment.into()].into_boxed_slice(),
            missing_ordinals: (0..expected).filter(|value| *value != ordinal).collect(),
            reason,
            uncertainty,
            total_bytes,
        }
    }

    fn close_with(&mut self, key: &AssemblyKey, reason: AssemblyCloseReason) -> AssemblyClose {
        let open = self.open.remove(key).expect("close key must identify an open assembly");
        let missing =
            (0..open.expected).filter(|ordinal| !open.members.contains_key(ordinal)).collect();
        let uncertainty = if reason == AssemblyCloseReason::ConflictingDuplicate {
            AssociationUncertainty::ConflictingFacts
        } else {
            AssociationUncertainty::ExactNativeIdentity
        };
        AssemblyClose {
            key: key.clone(),
            expected_fragments: open.expected,
            members: open.members.into_values().collect::<Vec<_>>().into_boxed_slice(),
            missing_ordinals: missing,
            reason,
            uncertainty,
            total_bytes: open.total_bytes,
        }
    }
}

/// Common source instance, provenance, error, validity, and epoch boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationValidity {
    provenance: Box<str>,
    source: SourceInstance,
    error: ErrorBound,
    validity: TickRange,
    epoch: QualificationEpoch,
}

impl RelationValidity {
    /// Constructs a bounded nonempty provenance record.
    pub fn new(
        provenance: impl Into<Box<str>>,
        source: SourceInstance,
        error: ErrorBound,
        validity: TickRange,
        epoch: QualificationEpoch,
    ) -> Result<Self, MeasurementError> {
        let provenance = provenance.into();
        if provenance.is_empty() || provenance.len() > MAX_SOURCE_BYTES {
            return Err(MeasurementError::new("relation provenance is invalid"));
        }
        Ok(Self { provenance, source, error, validity, epoch })
    }
    /// Returns provenance.
    #[must_use]
    pub fn provenance(&self) -> &str {
        &self.provenance
    }
    /// Returns the scoped source instance.
    #[must_use]
    pub const fn source(&self) -> &SourceInstance {
        &self.source
    }
    /// Returns the conservative error.
    #[must_use]
    pub const fn error(&self) -> ErrorBound {
        self.error
    }
    /// Returns the inclusive validity interval.
    #[must_use]
    pub const fn validity(&self) -> TickRange {
        self.validity
    }
    /// Returns the qualification epoch.
    #[must_use]
    pub const fn epoch(&self) -> QualificationEpoch {
        self.epoch
    }
}

/// Explicit relation between two named clock domains and one fit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeRelation {
    common: RelationValidity,
    source_clock: Box<str>,
    target_clock: Box<str>,
    fit: FitIdentity,
}

impl TimeRelation {
    /// Constructs a clock-domain and fit-scoped relation.
    pub fn new(
        common: RelationValidity,
        source_clock: impl Into<Box<str>>,
        target_clock: impl Into<Box<str>>,
        fit: FitIdentity,
    ) -> Result<Self, MeasurementError> {
        let source_clock = source_clock.into();
        let target_clock = target_clock.into();
        if source_clock.is_empty()
            || target_clock.is_empty()
            || source_clock.len() > MAX_SOURCE_BYTES
            || target_clock.len() > MAX_SOURCE_BYTES
        {
            return Err(MeasurementError::new("clock domains must be nonempty"));
        }
        Ok(Self { common, source_clock, target_clock, fit })
    }
    /// Returns common validity.
    #[must_use]
    pub const fn common(&self) -> &RelationValidity {
        &self.common
    }
    /// Returns source clock domain.
    #[must_use]
    pub fn source_clock(&self) -> &str {
        &self.source_clock
    }
    /// Returns target clock domain.
    #[must_use]
    pub fn target_clock(&self) -> &str {
        &self.target_clock
    }
    /// Returns fit identity.
    #[must_use]
    pub const fn fit(&self) -> FitIdentity {
        self.fit
    }
}

/// Coherent phase relation with an explicit reference and coherence interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhaseRelation {
    common: RelationValidity,
    reference: PhaseReferenceIdentity,
    coherence: TickRange,
}

impl PhaseRelation {
    /// Constructs a reference- and coherence-scoped phase relation.
    pub fn new(
        common: RelationValidity,
        reference: PhaseReferenceIdentity,
        coherence: TickRange,
    ) -> Result<Self, MeasurementError> {
        if !common.validity.covers(coherence) {
            return Err(MeasurementError::new("phase coherence lies outside relation validity"));
        }
        Ok(Self { common, reference, coherence })
    }
    /// Returns common validity.
    #[must_use]
    pub const fn common(&self) -> &RelationValidity {
        &self.common
    }
    /// Returns phase reference identity.
    #[must_use]
    pub const fn reference(&self) -> PhaseReferenceIdentity {
        self.reference
    }
    /// Returns coherence interval.
    #[must_use]
    pub const fn coherence(&self) -> TickRange {
        self.coherence
    }
}

/// Explicit protocol-stream and receive-chain mapping to physical antennas.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortMapEntry {
    tx_stream: u16,
    rx_chain: u16,
    tx_antenna: Option<u16>,
    rx_antenna: u16,
}

impl PortMapEntry {
    /// Constructs one explicit mapping. `None` records unknown transmitter precoding.
    #[must_use]
    pub const fn new(
        tx_stream: u16,
        rx_chain: u16,
        tx_antenna: Option<u16>,
        rx_antenna: u16,
    ) -> Self {
        Self { tx_stream, rx_chain, tx_antenna, rx_antenna }
    }
    /// Returns transmitter stream.
    #[must_use]
    pub const fn tx_stream(self) -> u16 {
        self.tx_stream
    }
    /// Returns receive chain.
    #[must_use]
    pub const fn rx_chain(self) -> u16 {
        self.rx_chain
    }
    /// Returns physical transmitter antenna when independently known.
    #[must_use]
    pub const fn tx_antenna(self) -> Option<u16> {
        self.tx_antenna
    }
    /// Returns physical receive antenna.
    #[must_use]
    pub const fn rx_antenna(self) -> u16 {
        self.rx_antenna
    }
}

/// Scoped protocol-to-physical port mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortMapping {
    common: RelationValidity,
    entries: Box<[PortMapEntry]>,
}

impl PortMapping {
    /// Constructs a nonempty finite mapping.
    pub fn new(
        common: RelationValidity,
        entries: impl IntoIterator<Item = PortMapEntry>,
    ) -> Result<Self, MeasurementError> {
        let entries = entries.into_iter().collect::<Vec<_>>();
        if entries.is_empty()
            || entries.len() > MAX_PORT_ENTRIES
            || entries.iter().enumerate().any(|(index, entry)| {
                entries[..index].iter().any(|earlier| {
                    earlier.tx_stream == entry.tx_stream && earlier.rx_chain == entry.rx_chain
                })
            })
        {
            return Err(MeasurementError::new("port mapping count is outside finite bounds"));
        }
        Ok(Self { common, entries: entries.into_boxed_slice() })
    }
    /// Returns common validity.
    #[must_use]
    pub const fn common(&self) -> &RelationValidity {
        &self.common
    }
    /// Returns mapping entries.
    #[must_use]
    pub fn entries(&self) -> &[PortMapEntry] {
        &self.entries
    }
    /// Reports whether every transmitter stream has a physical antenna.
    #[must_use]
    pub fn tx_geometry_known(&self) -> bool {
        self.entries.iter().all(|entry| entry.tx_antenna.is_some())
    }
}

/// Integer pose: translation millimetres followed by quaternion parts per million.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pose([i64; 7]);
impl Pose {
    /// Preserves an independently established pose without inferring axes.
    #[must_use]
    pub const fn new(value: [i64; 7]) -> Self {
        Self(value)
    }
    /// Returns the preserved components.
    #[must_use]
    pub const fn components(self) -> [i64; 7] {
        self.0
    }
}

/// Scoped physical geometry relation between named coordinate frames.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Geometry {
    common: RelationValidity,
    source_frame: Box<str>,
    target_frame: Box<str>,
    pose: Pose,
}

impl Geometry {
    /// Constructs an explicit frame-to-frame pose.
    pub fn new(
        common: RelationValidity,
        source_frame: impl Into<Box<str>>,
        target_frame: impl Into<Box<str>>,
        pose: Pose,
    ) -> Result<Self, MeasurementError> {
        let source_frame = source_frame.into();
        let target_frame = target_frame.into();
        if source_frame.is_empty()
            || target_frame.is_empty()
            || source_frame.len() > MAX_SOURCE_BYTES
            || target_frame.len() > MAX_SOURCE_BYTES
        {
            return Err(MeasurementError::new("coordinate frames must be nonempty"));
        }
        Ok(Self { common, source_frame, target_frame, pose })
    }
    /// Returns common validity.
    #[must_use]
    pub const fn common(&self) -> &RelationValidity {
        &self.common
    }
    /// Returns source coordinate frame.
    #[must_use]
    pub fn source_frame(&self) -> &str {
        &self.source_frame
    }
    /// Returns target coordinate frame.
    #[must_use]
    pub fn target_frame(&self) -> &str {
        &self.target_frame
    }
    /// Returns pose.
    #[must_use]
    pub const fn pose(&self) -> Pose {
        self.pose
    }
}

/// One independently persisted time, phase, port, or geometry qualification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualificationRelation {
    /// A clock-domain relation.
    Time(TimeRelation),
    /// A coherent phase-reference relation.
    Phase(PhaseRelation),
    /// A protocol-to-physical port relation.
    Port(PortMapping),
    /// A coordinate-frame pose relation.
    Geometry(Geometry),
}
impl QualificationRelation {
    /// Returns common provenance and validity.
    #[must_use]
    pub const fn common(&self) -> &RelationValidity {
        match self {
            Self::Time(v) => v.common(),
            Self::Phase(v) => v.common(),
            Self::Port(v) => v.common(),
            Self::Geometry(v) => v.common(),
        }
    }
}

/// Identity and exact time window of one causal evidence block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceBlockIdentity {
    source: SourceInstance,
    members: Box<[EvidenceMemberIdentity]>,
    window: TickRange,
    epoch: QualificationEpoch,
}

impl EvidenceBlockIdentity {
    /// Constructs a nonempty finite member set.
    pub fn new(
        source: SourceInstance,
        members: impl IntoIterator<Item = EvidenceMemberIdentity>,
        window: TickRange,
        epoch: QualificationEpoch,
    ) -> Result<Self, MeasurementError> {
        let members = members.into_iter().collect::<Vec<_>>();
        if members.is_empty()
            || members.len() > MAX_EVIDENCE_MEMBERS
            || members.iter().enumerate().any(|(index, member)| members[..index].contains(member))
        {
            return Err(MeasurementError::new("evidence member count is outside finite bounds"));
        }
        Ok(Self { source, members: members.into_boxed_slice(), window, epoch })
    }
}

/// One causal evidence block with per-member quality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceBlock {
    identity: EvidenceBlockIdentity,
    quality: Box<[EvidenceQuality]>,
}

impl EvidenceBlock {
    /// Constructs a block only when each named member has one quality state.
    pub fn new(
        identity: EvidenceBlockIdentity,
        quality: impl IntoIterator<Item = EvidenceQuality>,
    ) -> Result<Self, MeasurementError> {
        let quality = quality.into_iter().collect::<Vec<_>>();
        if quality.len() != identity.members.len() {
            return Err(MeasurementError::new("evidence quality count does not match members"));
        }
        Ok(Self { identity, quality: quality.into_boxed_slice() })
    }
}

/// A physical operation whose inputs are qualified independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalOperator {
    /// Absolute slow-response features.
    AbsoluteResponse,
    /// Causal fast-change features.
    FastChange,
    /// Coherent array angle-delay estimation.
    AngleDelay,
}

/// Artifact activation boundary used by eligibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelRequirements {
    activation: TickRange,
    epoch: QualificationEpoch,
}

impl ModelRequirements {
    /// Constructs exact artifact activation boundaries.
    #[must_use]
    pub const fn new(activation: TickRange, epoch: QualificationEpoch) -> Self {
        Self { activation, epoch }
    }
}

/// Independently established relation snapshot for an evidence block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Qualification {
    time: Option<TimeRelation>,
    phase: Option<PhaseRelation>,
    port: Option<PortMapping>,
    geometry: Option<Geometry>,
}

impl Qualification {
    /// Groups independently persisted relations without deriving any relation.
    #[must_use]
    pub const fn new(
        time: Option<TimeRelation>,
        phase: Option<PhaseRelation>,
        port: Option<PortMapping>,
        geometry: Option<Geometry>,
    ) -> Self {
        Self { time, phase, port, geometry }
    }

    /// Evaluates exact operator requirements plus artifact activation and block scope.
    #[must_use]
    pub fn eligibility(
        &self,
        operator: PhysicalOperator,
        block: &EvidenceBlock,
        artifact: ModelRequirements,
    ) -> Eligibility {
        let mut gaps = Vec::new();
        for quality in &block.quality {
            let gap = match quality {
                EvidenceQuality::Captured => None,
                EvidenceQuality::NotCaptured => Some(QualificationGap::NotCaptured),
                EvidenceQuality::Lost => Some(QualificationGap::Lost),
                EvidenceQuality::Invalid => Some(QualificationGap::Invalid),
                EvidenceQuality::Interpolated => Some(QualificationGap::Interpolated),
                EvidenceQuality::TrainingMasked => Some(QualificationGap::TrainingMasked),
            };
            if let Some(gap) = gap.filter(|gap| !gaps.contains(gap)) {
                gaps.push(gap);
            }
        }
        if artifact.epoch != block.identity.epoch
            || !artifact.activation.covers(block.identity.window)
        {
            gaps.push(QualificationGap::ArtifactActivation);
        }
        let mut require = |common: Option<&RelationValidity>, gap| {
            if !common.is_some_and(|validity| {
                validity.source == block.identity.source
                    && validity.epoch == block.identity.epoch
                    && validity.validity.covers(block.identity.window)
            }) {
                gaps.push(gap);
            }
        };
        require(self.time.as_ref().map(TimeRelation::common), QualificationGap::TimeRelation);
        if operator == PhysicalOperator::AngleDelay {
            require(
                self.phase.as_ref().map(PhaseRelation::common).filter(|_| {
                    self.phase
                        .as_ref()
                        .is_some_and(|relation| relation.coherence.covers(block.identity.window))
                }),
                QualificationGap::PhaseRelation,
            );
            require(self.port.as_ref().map(PortMapping::common), QualificationGap::PortMapping);
            require(self.geometry.as_ref().map(Geometry::common), QualificationGap::Geometry);
            if self.port.as_ref().is_some_and(|mapping| !mapping.tx_geometry_known()) {
                gaps.push(QualificationGap::TxGeometry);
            }
        }
        Eligibility { gaps: gaps.into_boxed_slice() }
    }
}

/// One explicit reason an operator cannot consume an evidence block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationGap {
    /// No capture was attempted.
    NotCaptured,
    /// An expected capture was lost.
    Lost,
    /// Captured bytes were invalid.
    Invalid,
    /// Values were interpolated.
    Interpolated,
    /// Training masked the values.
    TrainingMasked,
    /// The block lies outside artifact activation or epoch.
    ArtifactActivation,
    /// No exactly scoped time relation covers the block.
    TimeRelation,
    /// No exactly scoped coherent phase relation covers the block.
    PhaseRelation,
    /// No exactly scoped port mapping covers the block.
    PortMapping,
    /// No exactly scoped geometry covers the block.
    Geometry,
    /// Transmitter precoding leaves physical antenna geometry unknown.
    TxGeometry,
}

/// Queryable per-operator eligibility result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eligibility {
    gaps: Box<[QualificationGap]>,
}
impl Eligibility {
    /// Reports whether the operator may produce physical evidence.
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        self.gaps.is_empty()
    }
    /// Returns every explicit gap.
    #[must_use]
    pub fn gaps(&self) -> &[QualificationGap] {
        &self.gaps
    }
}

/// Invalid fragment, resource limit, or qualification input.
#[derive(Debug)]
pub struct MeasurementError {
    message: &'static str,
    backtrace: Box<Backtrace>,
}
impl MeasurementError {
    fn new(message: &'static str) -> Self {
        Self { message, backtrace: Box::new(Backtrace::capture()) }
    }
    /// Returns the captured backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}
impl fmt::Display for MeasurementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for MeasurementError {}
