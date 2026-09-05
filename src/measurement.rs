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
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is zero.
    pub fn new(value: u64) -> Result<Self, MeasurementError> {
        (value != 0)
            .then_some(Self(value))
            .ok_or_else(|| MeasurementError::new("wait bound must be nonzero"))
    }
    /// Returns the source-tick count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
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
    ///
    /// # Errors
    ///
    /// Returns an error when `end` precedes `start`.
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
    ///
    /// # Errors
    ///
    /// Returns an error for an empty set or an ordinal outside the declared set.
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
    ///
    /// # Errors
    ///
    /// Returns an error when the byte count exceeds the implementation ceiling.
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
    ///
    /// # Errors
    ///
    /// Returns an error when any bound is zero or exceeds the implementation ceiling.
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
    /// Returns the simultaneous-open ceiling.
    #[must_use]
    pub const fn open(self) -> usize {
        self.open
    }
    /// Returns the per-assembly fragment ceiling.
    #[must_use]
    pub const fn fragments(self) -> u16 {
        self.fragments
    }
    /// Returns the per-assembly byte ceiling.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
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
    /// Returns count and byte ceilings.
    #[must_use]
    pub const fn capacity(self) -> AssemblyCapacity {
        self.capacity
    }
    /// Returns the residence-time ceiling.
    #[must_use]
    pub const fn wait(self) -> WaitTicks {
        self.wait
    }

    pub(crate) fn host_default() -> Self {
        Self::new(
            AssemblyCapacity::new(MAX_OPEN_ASSEMBLIES, MAX_FRAGMENTS, MAX_ASSEMBLY_BYTES)
                .expect("host assembly capacity constants are valid"),
            WaitTicks::new(HOST_ASSEMBLY_WAIT_TICKS).expect("host assembly wait constant is valid"),
        )
    }
}

/// Persisted counters and limits that justify an immutable close reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssemblyCloseMetrics {
    first_tick: SourceTick,
    close_tick: SourceTick,
    limits: AssemblyLimits,
    attempted_fragments: u32,
    attempted_bytes: u64,
    open_assemblies: u32,
}

impl AssemblyCloseMetrics {
    pub(crate) const fn new(
        first_tick: SourceTick,
        close_tick: SourceTick,
        limits: AssemblyLimits,
        attempted_fragments: u32,
        attempted_bytes: u64,
        open_assemblies: u32,
    ) -> Self {
        Self {
            first_tick,
            close_tick,
            limits,
            attempted_fragments,
            attempted_bytes,
            open_assemblies,
        }
    }
    /// Returns the first fragment tick.
    #[must_use]
    pub const fn first_tick(self) -> SourceTick {
        self.first_tick
    }
    /// Returns the decision tick.
    #[must_use]
    pub const fn close_tick(self) -> SourceTick {
        self.close_tick
    }
    /// Returns the configured limits used by the decision.
    #[must_use]
    pub const fn limits(self) -> AssemblyLimits {
        self.limits
    }
    /// Returns the fragment count including the triggering attempt.
    #[must_use]
    pub const fn attempted_fragments(self) -> u32 {
        self.attempted_fragments
    }
    /// Returns bytes including the triggering attempt.
    #[must_use]
    pub const fn attempted_bytes(self) -> u64 {
        self.attempted_bytes
    }
    /// Returns simultaneous open assemblies observed at the decision.
    #[must_use]
    pub const fn open_assemblies(self) -> u32 {
        self.open_assemblies
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
    metrics: AssemblyCloseMetrics,
}

pub(crate) struct PersistedAssemblyClose {
    pub(crate) key: AssemblyKey,
    pub(crate) expected_fragments: u16,
    pub(crate) members: Box<[AssemblyMember]>,
    pub(crate) missing_ordinals: Box<[u16]>,
    pub(crate) reason: AssemblyCloseReason,
    pub(crate) uncertainty: AssociationUncertainty,
    pub(crate) total_bytes: u64,
    pub(crate) metrics: AssemblyCloseMetrics,
}

impl AssemblyClose {
    pub(crate) fn persisted(value: PersistedAssemblyClose) -> Self {
        let PersistedAssemblyClose {
            key,
            expected_fragments,
            members,
            missing_ordinals,
            reason,
            uncertainty,
            total_bytes,
            metrics,
        } = value;
        Self {
            key,
            expected_fragments,
            members,
            missing_ordinals,
            reason,
            uncertainty,
            total_bytes,
            metrics,
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
    /// Returns persisted decision counters and configured limits.
    #[must_use]
    pub const fn metrics(&self) -> AssemblyCloseMetrics {
        self.metrics
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
    ///
    /// # Errors
    ///
    /// Returns an error when arithmetic overflows or the fragment cannot be represented
    /// under the configured limits.
    pub fn ingest(
        &mut self,
        fragment: MeasurementFragment,
        arrival: SourceTick,
    ) -> Result<Vec<AssemblyClose>, MeasurementError> {
        let key = fragment.key.clone();
        let mut closes = self.expire(key.source(), arrival);
        if closes.iter().any(|close| close.key() == &key) {
            closes.push(self.isolated_close(fragment, AssemblyCloseReason::LateFragment, arrival));
            return Ok(closes);
        }
        closes.extend(self.ingest_inner(fragment, arrival, true)?);
        Ok(closes)
    }

    pub(crate) fn restore(
        &mut self,
        fragment: MeasurementFragment,
        arrival: SourceTick,
    ) -> Result<(), MeasurementError> {
        if fragment.position.expected > self.limits.capacity.fragments {
            return Err(MeasurementError::new(
                "persisted open fragment count exceeds configured capacity",
            ));
        }
        let restored_bytes = self
            .open
            .get(&fragment.key)
            .map_or(0, |open| open.total_bytes)
            .checked_add(u64::from(fragment.fact.bytes.get()))
            .ok_or_else(|| MeasurementError::new("persisted open byte count overflowed"))?;
        if restored_bytes > self.limits.capacity.bytes {
            return Err(MeasurementError::new("persisted open bytes exceed configured capacity"));
        }
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
        let open_count = self.open.len();
        if !self.open.contains_key(&key) && self.open.len() == self.limits.capacity.open {
            return Ok(vec![self.isolated_close(
                fragment,
                AssemblyCloseReason::ResourceLimit,
                arrival,
            )]);
        }
        let open = self.open.entry(key.clone()).or_insert_with(|| OpenAssembly {
            first_tick: arrival,
            expected: fragment.position.expected,
            members: BTreeMap::new(),
            total_bytes: 0,
        });
        if open.expected != fragment.position.expected {
            let attempted_fragments = u32::try_from(open.members.len()).unwrap_or(u32::MAX) + 1;
            let attempted_bytes =
                open.total_bytes.saturating_add(u64::from(fragment.fact.bytes.get()));
            return Ok(vec![self.close_with(
                &key,
                AssemblyCloseReason::ConflictingDuplicate,
                arrival,
                attempted_fragments,
                attempted_bytes,
            )]);
        }
        if let Some(existing) = open.members.get(&fragment.position.ordinal) {
            if existing.fact_digest == fragment.fact.digest
                && existing.payload_bytes == fragment.fact.bytes.get()
                && existing.quality == fragment.fact.quality
            {
                let metrics = AssemblyCloseMetrics::new(
                    open.first_tick,
                    arrival,
                    self.limits,
                    u32::try_from(open.members.len()).unwrap_or(u32::MAX) + 1,
                    open.total_bytes.saturating_add(u64::from(fragment.fact.bytes.get())),
                    u32::try_from(open_count).unwrap_or(u32::MAX),
                );
                return Ok(vec![Self::isolated_close_with_metrics(
                    fragment,
                    AssemblyCloseReason::DuplicateFragment,
                    metrics,
                )]);
            }
            let attempted_fragments = u32::try_from(open.members.len()).unwrap_or(u32::MAX) + 1;
            let attempted_bytes =
                open.total_bytes.saturating_add(u64::from(fragment.fact.bytes.get()));
            return Ok(vec![self.close_with(
                &key,
                AssemblyCloseReason::ConflictingDuplicate,
                arrival,
                attempted_fragments,
                attempted_bytes,
            )]);
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
        let attempted_fragments = u32::try_from(open.members.len()).unwrap_or(u32::MAX);
        let attempted_bytes = open.total_bytes;
        Ok(reason
            .map(|reason| {
                vec![self.close_with(&key, reason, arrival, attempted_fragments, attempted_bytes)]
            })
            .unwrap_or_default())
    }

    /// Closes assemblies from one source whose bounded wait elapsed.
    #[must_use]
    pub fn expire(&mut self, source: &SourceInstance, now: SourceTick) -> Vec<AssemblyClose> {
        let decisions = self
            .open
            .iter()
            .filter_map(|(key, open)| {
                (key.source() == source
                    && now.get().saturating_sub(open.first_tick.get()) >= self.limits.wait.0)
                    .then_some((
                        key.clone(),
                        u32::try_from(open.members.len()).unwrap_or(u32::MAX),
                        open.total_bytes,
                    ))
            })
            .collect::<Vec<_>>();
        decisions
            .into_iter()
            .map(|(key, attempted_fragments, attempted_bytes)| {
                self.close_with(
                    &key,
                    AssemblyCloseReason::WaitLimit,
                    now,
                    attempted_fragments,
                    attempted_bytes,
                )
            })
            .collect()
    }

    /// Creates a separate late-arrival fact after durable storage proves an earlier close.
    #[must_use]
    pub fn late(&self, fragment: MeasurementFragment, arrival: SourceTick) -> AssemblyClose {
        self.isolated_close(fragment, AssemblyCloseReason::LateFragment, arrival)
    }

    fn isolated_close(
        &self,
        fragment: MeasurementFragment,
        reason: AssemblyCloseReason,
        close_tick: SourceTick,
    ) -> AssemblyClose {
        let total_bytes = u64::from(fragment.fact.bytes.get());
        Self::isolated_close_with_metrics(
            fragment,
            reason,
            AssemblyCloseMetrics::new(
                close_tick,
                close_tick,
                self.limits,
                1,
                total_bytes,
                u32::try_from(self.open.len()).unwrap_or(u32::MAX),
            ),
        )
    }

    fn isolated_close_with_metrics(
        fragment: MeasurementFragment,
        reason: AssemblyCloseReason,
        metrics: AssemblyCloseMetrics,
    ) -> AssemblyClose {
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
            metrics,
        }
    }

    fn close_with(
        &mut self,
        key: &AssemblyKey,
        reason: AssemblyCloseReason,
        close_tick: SourceTick,
        attempted_fragments: u32,
        attempted_bytes: u64,
    ) -> AssemblyClose {
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
            metrics: AssemblyCloseMetrics::new(
                open.first_tick,
                close_tick,
                self.limits,
                attempted_fragments,
                attempted_bytes,
                u32::try_from(self.open.len() + 1).unwrap_or(u32::MAX),
            ),
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
    ///
    /// # Errors
    ///
    /// Returns an error when provenance is empty or exceeds the finite byte bound.
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
    ///
    /// # Errors
    ///
    /// Returns an error when either clock-domain name is empty or overlong.
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
    ///
    /// # Errors
    ///
    /// Returns an error when coherence is not contained by relation validity.
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
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, overlong, or duplicate signal-path mapping.
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
    ///
    /// # Errors
    ///
    /// Returns an error when either coordinate-frame name is empty or overlong.
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
    scope: EvidenceScope,
    members: Box<[EvidenceMemberIdentity]>,
    signal_paths: Box<[SignalPath]>,
}

impl EvidenceBlockIdentity {
    /// Constructs finite, duplicate-free member and signal-path sets.
    ///
    /// # Errors
    ///
    /// Returns an error when the member set is empty or too large, or when either set
    /// contains duplicate identities or exceeds its finite bound.
    pub fn new(
        scope: EvidenceScope,
        members: impl IntoIterator<Item = EvidenceMemberIdentity>,
        signal_paths: impl IntoIterator<Item = SignalPath>,
    ) -> Result<Self, MeasurementError> {
        let members = members.into_iter().collect::<Vec<_>>();
        let signal_paths = signal_paths.into_iter().collect::<Vec<_>>();
        if members.is_empty()
            || members.len() > MAX_EVIDENCE_MEMBERS
            || members.iter().enumerate().any(|(index, member)| members[..index].contains(member))
            || signal_paths.len() > MAX_PORT_ENTRIES
            || signal_paths
                .iter()
                .enumerate()
                .any(|(index, path)| signal_paths[..index].contains(path))
        {
            return Err(MeasurementError::new("evidence member count is outside finite bounds"));
        }
        Ok(Self {
            scope,
            members: members.into_boxed_slice(),
            signal_paths: signal_paths.into_boxed_slice(),
        })
    }
}

/// Source, capture context, window, and qualification revision of one evidence block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceScope {
    source: SourceInstance,
    context: MeasurementContext,
    window: TickRange,
    epoch: QualificationEpoch,
}

impl EvidenceScope {
    /// Groups the exact boundaries within which block evidence is interchangeable.
    #[must_use]
    pub const fn new(
        source: SourceInstance,
        context: MeasurementContext,
        window: TickRange,
        epoch: QualificationEpoch,
    ) -> Self {
        Self { source, context, window, epoch }
    }
}

/// One transmitter-stream and receiver-chain signal path present in a block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalPath {
    tx_stream: u16,
    rx_chain: u16,
}

impl SignalPath {
    /// Groups a protocol transmitter stream with its capture receive chain.
    #[must_use]
    pub const fn new(tx_stream: u16, rx_chain: u16) -> Self {
        Self { tx_stream, rx_chain }
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
    ///
    /// # Errors
    ///
    /// Returns an error when the quality count does not equal the member count.
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

/// Artifact and capture boundaries required by one model operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactScope {
    activation: TickRange,
    epoch: QualificationEpoch,
    context: MeasurementContext,
}

impl ArtifactScope {
    /// Groups exact artifact activation, revision, and capture boundaries.
    #[must_use]
    pub const fn new(
        activation: TickRange,
        epoch: QualificationEpoch,
        context: MeasurementContext,
    ) -> Self {
        Self { activation, epoch, context }
    }
}

/// Required named clock domains, fit, and maximum time error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeRequirement {
    source_clock: Box<str>,
    target_clock: Box<str>,
    fit: FitIdentity,
    maximum_error: ErrorBound,
}

impl TimeRequirement {
    /// Constructs exact clock and fit requirements.
    ///
    /// # Errors
    ///
    /// Returns an error for empty or overlong clock-domain names.
    pub fn new(
        source_clock: impl Into<Box<str>>,
        target_clock: impl Into<Box<str>>,
        fit: FitIdentity,
        maximum_error: ErrorBound,
    ) -> Result<Self, MeasurementError> {
        let source_clock = source_clock.into();
        let target_clock = target_clock.into();
        if source_clock.is_empty()
            || target_clock.is_empty()
            || source_clock.len() > MAX_SOURCE_BYTES
            || target_clock.len() > MAX_SOURCE_BYTES
        {
            return Err(MeasurementError::new("clock requirements must be nonempty"));
        }
        Ok(Self { source_clock, target_clock, fit, maximum_error })
    }
}

/// Required phase reference, coherence interval, and maximum phase error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseRequirement {
    reference: PhaseReferenceIdentity,
    coherence: TickRange,
    maximum_error: ErrorBound,
}

impl PhaseRequirement {
    /// Groups exact phase requirements.
    #[must_use]
    pub const fn new(
        reference: PhaseReferenceIdentity,
        coherence: TickRange,
        maximum_error: ErrorBound,
    ) -> Self {
        Self { reference, coherence, maximum_error }
    }
}

/// Required physical mapping for one block signal path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortRequirement {
    path: SignalPath,
    tx_antenna: u16,
    rx_antenna: u16,
}

impl PortRequirement {
    /// Groups one exact signal-path-to-physical-antenna requirement.
    #[must_use]
    pub const fn new(path: SignalPath, tx_antenna: u16, rx_antenna: u16) -> Self {
        Self { path, tx_antenna, rx_antenna }
    }
}

/// Required coordinate frames, pose, and maximum geometry error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeometryRequirement {
    source_frame: Box<str>,
    target_frame: Box<str>,
    pose: Pose,
    maximum_error: ErrorBound,
}

impl GeometryRequirement {
    /// Constructs exact geometry requirements.
    ///
    /// # Errors
    ///
    /// Returns an error for empty or overlong coordinate-frame names.
    pub fn new(
        source_frame: impl Into<Box<str>>,
        target_frame: impl Into<Box<str>>,
        pose: Pose,
        maximum_error: ErrorBound,
    ) -> Result<Self, MeasurementError> {
        let source_frame = source_frame.into();
        let target_frame = target_frame.into();
        if source_frame.is_empty()
            || target_frame.is_empty()
            || source_frame.len() > MAX_SOURCE_BYTES
            || target_frame.len() > MAX_SOURCE_BYTES
        {
            return Err(MeasurementError::new("geometry requirements must be nonempty"));
        }
        Ok(Self { source_frame, target_frame, pose, maximum_error })
    }
}

/// Exact independently established physical inputs required by an operator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalRequirements {
    time: TimeRequirement,
    phase: Option<PhaseRequirement>,
    ports: Box<[PortRequirement]>,
    geometry: Option<GeometryRequirement>,
}

impl PhysicalRequirements {
    /// Constructs a finite, duplicate-free physical requirement set.
    ///
    /// # Errors
    ///
    /// Returns an error when port requirements exceed the finite bound or repeat a signal path.
    pub fn new(
        time: TimeRequirement,
        phase: Option<PhaseRequirement>,
        ports: impl IntoIterator<Item = PortRequirement>,
        geometry: Option<GeometryRequirement>,
    ) -> Result<Self, MeasurementError> {
        let ports = ports.into_iter().collect::<Vec<_>>();
        if ports.len() > MAX_PORT_ENTRIES
            || ports
                .iter()
                .enumerate()
                .any(|(index, port)| ports[..index].iter().any(|earlier| earlier.path == port.path))
        {
            return Err(MeasurementError::new("physical port requirements are invalid"));
        }
        Ok(Self { time, phase, ports: ports.into_boxed_slice(), geometry })
    }
}

/// Exact scope and physical inputs for one operator invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelRequirements {
    operator: PhysicalOperator,
    artifact: ArtifactScope,
    physical: PhysicalRequirements,
}

impl ModelRequirements {
    /// Constructs per-operator requirements without supplying inferred physical inputs.
    ///
    /// # Errors
    ///
    /// Returns an error when angle-delay requirements omit phase, ports, or geometry, or
    /// when another operator includes inputs it does not consume.
    pub fn new(
        operator: PhysicalOperator,
        artifact: ArtifactScope,
        physical: PhysicalRequirements,
    ) -> Result<Self, MeasurementError> {
        let input_presence =
            (physical.phase.is_some(), !physical.ports.is_empty(), physical.geometry.is_some());
        let valid = match operator {
            PhysicalOperator::AngleDelay => input_presence == (true, true, true),
            PhysicalOperator::AbsoluteResponse | PhysicalOperator::FastChange => {
                input_presence == (false, false, false)
            }
        };
        if !valid {
            return Err(MeasurementError::new("physical requirements do not match operator"));
        }
        Ok(Self { operator, artifact, physical })
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
        block: &EvidenceBlock,
        requirements: &ModelRequirements,
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
        let scope = &block.identity.scope;
        if requirements.artifact.epoch != scope.epoch
            || !requirements.artifact.activation.covers(scope.window)
        {
            gaps.push(QualificationGap::ArtifactActivation);
        }
        if requirements.artifact.context != scope.context {
            gaps.push(QualificationGap::MeasurementContext);
        }

        let valid_common = |common: &RelationValidity| {
            common.source == scope.source
                && common.epoch == scope.epoch
                && common.validity.covers(scope.window)
        };
        match &self.time {
            None => gaps.push(QualificationGap::TimeRelation),
            Some(relation) => {
                if !valid_common(relation.common()) {
                    gaps.push(QualificationGap::TimeScope);
                }
                let required = &requirements.physical.time;
                if relation.source_clock() != required.source_clock.as_ref()
                    || relation.target_clock() != required.target_clock.as_ref()
                {
                    gaps.push(QualificationGap::TimeClockDomains);
                }
                if relation.fit() != required.fit {
                    gaps.push(QualificationGap::TimeFit);
                }
                if !within_error(relation.common.error, required.maximum_error) {
                    gaps.push(QualificationGap::TimeError);
                }
            }
        }

        if requirements.operator == PhysicalOperator::AngleDelay {
            let phase_required = requirements
                .physical
                .phase
                .as_ref()
                .expect("angle-delay requirements contain phase");
            match &self.phase {
                None => gaps.push(QualificationGap::PhaseRelation),
                Some(relation) => {
                    if !valid_common(relation.common()) {
                        gaps.push(QualificationGap::PhaseScope);
                    }
                    if relation.reference != phase_required.reference {
                        gaps.push(QualificationGap::PhaseReference);
                    }
                    if !relation.coherence.covers(scope.window)
                        || !phase_required.coherence.covers(scope.window)
                        || !relation.coherence.covers(phase_required.coherence)
                    {
                        gaps.push(QualificationGap::PhaseCoherence);
                    }
                    if !within_error(relation.common.error, phase_required.maximum_error) {
                        gaps.push(QualificationGap::PhaseError);
                    }
                }
            }
            match &self.port {
                None => gaps.push(QualificationGap::PortMapping),
                Some(mapping) => {
                    if !valid_common(mapping.common()) {
                        gaps.push(QualificationGap::PortScope);
                    }
                    let exact_paths = mapping.entries.len() == block.identity.signal_paths.len()
                        && requirements.physical.ports.len() == block.identity.signal_paths.len()
                        && block.identity.signal_paths.iter().all(|path| {
                            requirements.physical.ports.iter().any(|required| {
                                required.path == *path
                                    && mapping.entries.iter().any(|entry| {
                                        entry.tx_stream == path.tx_stream
                                            && entry.rx_chain == path.rx_chain
                                            && entry.tx_antenna == Some(required.tx_antenna)
                                            && entry.rx_antenna == required.rx_antenna
                                    })
                            })
                        });
                    if !exact_paths {
                        gaps.push(QualificationGap::SignalPathMapping);
                    }
                }
            }
            let geometry_required = requirements
                .physical
                .geometry
                .as_ref()
                .expect("angle-delay requirements contain geometry");
            match &self.geometry {
                None => gaps.push(QualificationGap::Geometry),
                Some(geometry) => {
                    if !valid_common(geometry.common()) {
                        gaps.push(QualificationGap::GeometryScope);
                    }
                    if geometry.source_frame() != geometry_required.source_frame.as_ref()
                        || geometry.target_frame() != geometry_required.target_frame.as_ref()
                    {
                        gaps.push(QualificationGap::GeometryFrames);
                    }
                    if geometry.pose != geometry_required.pose {
                        gaps.push(QualificationGap::GeometryPose);
                    }
                    if !within_error(geometry.common.error, geometry_required.maximum_error) {
                        gaps.push(QualificationGap::GeometryError);
                    }
                }
            }
        }
        Eligibility { gaps: gaps.into_boxed_slice() }
    }
}

fn within_error(actual: ErrorBound, maximum: ErrorBound) -> bool {
    actual.value != u64::MAX && actual.unit == maximum.unit && actual.value <= maximum.value
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
    /// Capture profile, radio mode, or channel differs from the artifact requirement.
    MeasurementContext,
    /// No exactly scoped time relation covers the block.
    TimeRelation,
    /// Time provenance has the wrong source, epoch, or validity window.
    TimeScope,
    /// Required clock domains do not match.
    TimeClockDomains,
    /// Required clock fit does not match.
    TimeFit,
    /// Time error unit or magnitude exceeds the operator tolerance.
    TimeError,
    /// No exactly scoped coherent phase relation covers the block.
    PhaseRelation,
    /// Phase provenance has the wrong source, epoch, or validity window.
    PhaseScope,
    /// Phase reference does not match.
    PhaseReference,
    /// Phase coherence does not cover the required interval and block.
    PhaseCoherence,
    /// Phase error unit or magnitude exceeds the operator tolerance.
    PhaseError,
    /// No exactly scoped port mapping covers the block.
    PortMapping,
    /// Port provenance has the wrong source, epoch, or validity window.
    PortScope,
    /// Block signal paths do not exactly match required physical mappings.
    SignalPathMapping,
    /// No exactly scoped geometry covers the block.
    Geometry,
    /// Geometry provenance has the wrong source, epoch, or validity window.
    GeometryScope,
    /// Coordinate frames do not match.
    GeometryFrames,
    /// Required pose does not match.
    GeometryPose,
    /// Geometry error unit or magnitude exceeds the operator tolerance.
    GeometryError,
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
