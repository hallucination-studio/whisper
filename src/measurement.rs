//! Bounded RF measurement assembly and explicit physical-input qualification.

use std::backtrace::Backtrace;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use crate::{BootGeneration, DeviceId};

/// Largest number of simultaneously open measurements accepted by one assembler.
const MAXIMUM_OPEN_ASSEMBLIES: usize = 1_024;
/// Largest fragment count accepted for one physical event.
const MAXIMUM_FRAGMENTS_PER_ASSEMBLY: u16 = 1_024;
/// Largest retained payload for one physical event, in bytes.
const MAXIMUM_ASSEMBLY_BYTES: u64 = 16 * 1024 * 1024;
/// Largest source label persisted with a qualification, in UTF-8 bytes.
const MAXIMUM_RELATION_SOURCE_BYTES: usize = 256;

/// Immutable identity shared by fragments from one native RF event.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AssemblyKey {
    device_id: DeviceId,
    boot_generation: BootGeneration,
    transmitter: [u8; 6],
    native_event: u64,
    retransmission: Option<u64>,
}

impl AssemblyKey {
    /// Creates an assembly identity without interpreting its native event fields.
    #[must_use]
    pub const fn new(
        device_id: DeviceId,
        boot_generation: BootGeneration,
        transmitter: [u8; 6],
        native_event: u64,
        retransmission: Option<u64>,
    ) -> Self {
        Self { device_id, boot_generation, transmitter, native_event, retransmission }
    }

    /// Returns the source instance identity.
    #[must_use]
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    /// Returns the source boot generation.
    #[must_use]
    pub const fn boot_generation(self) -> BootGeneration {
        self.boot_generation
    }

    /// Returns the native transmitter identity.
    #[must_use]
    pub const fn transmitter(self) -> [u8; 6] {
        self.transmitter
    }

    /// Returns the source-native event identity.
    #[must_use]
    pub const fn native_event(self) -> u64 {
        self.native_event
    }

    /// Returns available retransmission identity without manufacturing one.
    #[must_use]
    pub const fn retransmission(self) -> Option<u64> {
        self.retransmission
    }
}

/// Explicit state of an observation used by quality and eligibility decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceQuality {
    /// The source captured the observation and it passed source validation.
    Captured,
    /// The source did not attempt to capture the observation.
    NotCaptured,
    /// An expected captured observation was lost.
    Lost,
    /// Bytes were present but invalid for physical evidence.
    Invalid,
    /// Values were interpolated rather than captured.
    Interpolated,
    /// Training deliberately masks this observation.
    TrainingMasked,
}

/// One immutable fragment offered to measurement assembly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasurementFragment {
    key: AssemblyKey,
    ordinal: u16,
    expected_fragments: u16,
    fact_digest: [u8; 32],
    payload_bytes: u32,
    quality: EvidenceQuality,
}

impl MeasurementFragment {
    /// Creates a fragment whose ordinal lies inside a non-empty declared set.
    pub fn new(
        key: AssemblyKey,
        ordinal: u16,
        expected_fragments: u16,
        fact_digest: [u8; 32],
        payload_bytes: u32,
        quality: EvidenceQuality,
    ) -> Result<Self, MeasurementError> {
        if expected_fragments == 0 || ordinal >= expected_fragments {
            return Err(MeasurementError::new("fragment ordinal must be inside a non-empty set"));
        }
        Ok(Self { key, ordinal, expected_fragments, fact_digest, payload_bytes, quality })
    }

    /// Returns the assembly identity.
    #[must_use]
    pub const fn key(&self) -> AssemblyKey {
        self.key
    }
}

/// Fixed resource ceilings for one in-memory assembler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssemblyLimits {
    maximum_open: usize,
    maximum_fragments: u16,
    maximum_bytes: u64,
    maximum_wait_ticks: u64,
}

impl AssemblyLimits {
    /// Creates non-zero count, byte, and wait limits.
    pub fn new(
        maximum_open: usize,
        maximum_fragments: u16,
        maximum_bytes: u64,
        maximum_wait_ticks: u64,
    ) -> Result<Self, MeasurementError> {
        if maximum_open == 0
            || maximum_fragments == 0
            || maximum_bytes == 0
            || maximum_wait_ticks == 0
            || maximum_open > MAXIMUM_OPEN_ASSEMBLIES
            || maximum_fragments > MAXIMUM_FRAGMENTS_PER_ASSEMBLY
            || maximum_bytes > MAXIMUM_ASSEMBLY_BYTES
        {
            return Err(MeasurementError::new("assembly limits must all be non-zero"));
        }
        Ok(Self { maximum_open, maximum_fragments, maximum_bytes, maximum_wait_ticks })
    }
}

/// Why membership in a measurement became immutable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssemblyCloseReason {
    /// Every declared fragment was present.
    Complete,
    /// The assembly reached its maximum residence time.
    WaitLimit,
    /// The declared or observed fragment count exceeded its bound.
    CountLimit,
    /// Accepted fragment bytes exceeded the assembly byte bound.
    ByteLimit,
    /// A fragment arrived after membership for its event was fixed.
    LateFragment,
    /// The same ordinal named conflicting immutable facts.
    ConflictingDuplicate,
}

/// Association confidence retained with every close decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationUncertainty {
    /// Native event identity fixed association without arrival-time inference.
    ExactNativeIdentity,
    /// The fragment is known only to have arrived after an earlier close.
    LateAfterClose,
    /// Conflicting facts prevent a unique member choice.
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

    /// Returns the fragment's byte contribution.
    #[must_use]
    pub const fn payload_bytes(self) -> u32 {
        self.payload_bytes
    }

    /// Returns the fragment quality without collapsing missing states.
    #[must_use]
    pub const fn quality(self) -> EvidenceQuality {
        self.quality
    }
}

impl From<MeasurementFragment> for AssemblyMember {
    fn from(fragment: MeasurementFragment) -> Self {
        Self {
            ordinal: fragment.ordinal,
            fact_digest: fragment.fact_digest,
            payload_bytes: fragment.payload_bytes,
            quality: fragment.quality,
        }
    }
}

/// Durable decision fixing one measurement's members, gaps, and uncertainty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssemblyClose {
    key: AssemblyKey,
    members: Box<[AssemblyMember]>,
    missing_ordinals: Box<[u16]>,
    reason: AssemblyCloseReason,
    uncertainty: AssociationUncertainty,
    total_bytes: u64,
}

impl AssemblyClose {
    pub(crate) fn persisted(
        key: AssemblyKey,
        members: Box<[AssemblyMember]>,
        missing_ordinals: Box<[u16]>,
        reason: AssemblyCloseReason,
        uncertainty: AssociationUncertainty,
        total_bytes: u64,
    ) -> Self {
        Self { key, members, missing_ordinals, reason, uncertainty, total_bytes }
    }
    /// Returns the event identity whose membership was fixed.
    #[must_use]
    pub const fn key(&self) -> AssemblyKey {
        self.key
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

    /// Returns why membership closed.
    #[must_use]
    pub const fn reason(&self) -> AssemblyCloseReason {
        self.reason
    }

    /// Returns the association uncertainty recorded at close.
    #[must_use]
    pub const fn uncertainty(&self) -> AssociationUncertainty {
        self.uncertainty
    }

    /// Returns the sum of retained member payload bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

#[derive(Debug)]
struct OpenAssembly {
    first_tick: u64,
    expected_fragments: u16,
    members: BTreeMap<u16, AssemblyMember>,
    total_bytes: u64,
}

/// Deterministic bounded assembler keyed only by native event facts.
#[derive(Debug)]
pub struct MeasurementAssembler {
    limits: AssemblyLimits,
    open: BTreeMap<AssemblyKey, OpenAssembly>,
    closed: VecDeque<AssemblyKey>,
}

impl MeasurementAssembler {
    /// Creates an empty assembler with fixed resource bounds.
    #[must_use]
    pub fn new(limits: AssemblyLimits) -> Self {
        Self { limits, open: BTreeMap::new(), closed: VecDeque::new() }
    }

    /// Incorporates one fragment and returns a close when membership becomes fixed.
    pub fn ingest(
        &mut self,
        fragment: MeasurementFragment,
        arrival_tick: u64,
    ) -> Result<Option<AssemblyClose>, MeasurementError> {
        let key = fragment.key;
        if self.closed.contains(&key) {
            return Ok(Some(self.late_close(fragment)));
        }
        if !self.open.contains_key(&key) && self.open.len() == self.limits.maximum_open {
            return Err(MeasurementError::new("open assembly count limit reached"));
        }
        let open = self.open.entry(key).or_insert_with(|| OpenAssembly {
            first_tick: arrival_tick,
            expected_fragments: fragment.expected_fragments,
            members: BTreeMap::new(),
            total_bytes: 0,
        });
        if open.expected_fragments != fragment.expected_fragments {
            return Ok(Some(self.close_with(key, AssemblyCloseReason::ConflictingDuplicate)));
        }
        if let Some(existing) = open.members.get(&fragment.ordinal) {
            if existing.fact_digest == fragment.fact_digest {
                return Ok(None);
            }
            return Ok(Some(self.close_with(key, AssemblyCloseReason::ConflictingDuplicate)));
        }
        let payload_bytes = u64::from(fragment.payload_bytes);
        open.total_bytes = open
            .total_bytes
            .checked_add(payload_bytes)
            .ok_or_else(|| MeasurementError::new("assembly byte count overflowed"))?;
        open.members.insert(fragment.ordinal, fragment.into());
        let reason = if open.expected_fragments > self.limits.maximum_fragments
            || open.members.len() > usize::from(self.limits.maximum_fragments)
        {
            Some(AssemblyCloseReason::CountLimit)
        } else if open.total_bytes > self.limits.maximum_bytes {
            Some(AssemblyCloseReason::ByteLimit)
        } else if open.members.len() == usize::from(open.expected_fragments) {
            Some(AssemblyCloseReason::Complete)
        } else {
            None
        };
        Ok(reason.map(|reason| self.close_with(key, reason)))
    }

    /// Closes every assembly whose bounded wait has elapsed.
    #[must_use]
    pub fn expire(&mut self, now_tick: u64) -> Vec<AssemblyClose> {
        let keys = self
            .open
            .iter()
            .filter_map(|(key, open)| {
                (now_tick.saturating_sub(open.first_tick) >= self.limits.maximum_wait_ticks)
                    .then_some(*key)
            })
            .collect::<Vec<_>>();
        keys.into_iter().map(|key| self.close_with(key, AssemblyCloseReason::WaitLimit)).collect()
    }

    fn close_with(&mut self, key: AssemblyKey, reason: AssemblyCloseReason) -> AssemblyClose {
        let open = self.open.remove(&key).expect("close key must identify an open assembly");
        let missing_ordinals = (0..open.expected_fragments)
            .filter(|ordinal| !open.members.contains_key(ordinal))
            .collect::<Vec<_>>();
        let uncertainty = if reason == AssemblyCloseReason::ConflictingDuplicate {
            AssociationUncertainty::ConflictingFacts
        } else {
            AssociationUncertainty::ExactNativeIdentity
        };
        self.remember_closed(key);
        AssemblyClose {
            key,
            members: open.members.into_values().collect::<Vec<_>>().into_boxed_slice(),
            missing_ordinals: missing_ordinals.into_boxed_slice(),
            reason,
            uncertainty,
            total_bytes: open.total_bytes,
        }
    }

    fn late_close(&self, fragment: MeasurementFragment) -> AssemblyClose {
        let expected = fragment.expected_fragments;
        let ordinal = fragment.ordinal;
        let total_bytes = u64::from(fragment.payload_bytes);
        AssemblyClose {
            key: fragment.key,
            members: vec![fragment.into()].into_boxed_slice(),
            missing_ordinals: (0..expected).filter(|candidate| *candidate != ordinal).collect(),
            reason: AssemblyCloseReason::LateFragment,
            uncertainty: AssociationUncertainty::LateAfterClose,
            total_bytes,
        }
    }

    fn remember_closed(&mut self, key: AssemblyKey) {
        if self.closed.len() == self.limits.maximum_open {
            self.closed.pop_front();
        }
        self.closed.push_back(key);
    }
}

/// Common provenance, error, validity, and epoch boundary for one relation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationValidity {
    source: Box<str>,
    error_bound: u64,
    valid_from_tick: u64,
    valid_until_tick: u64,
    epoch: u64,
}

impl RelationValidity {
    /// Creates a non-empty sourced validity interval with an explicit error bound.
    pub fn new(
        source: impl Into<Box<str>>,
        error_bound: u64,
        valid_from_tick: u64,
        valid_until_tick: u64,
        epoch: u64,
    ) -> Result<Self, MeasurementError> {
        let source = source.into();
        if source.is_empty()
            || source.len() > MAXIMUM_RELATION_SOURCE_BYTES
            || valid_from_tick > valid_until_tick
        {
            return Err(MeasurementError::new("relation source and validity interval are invalid"));
        }
        Ok(Self { source, error_bound, valid_from_tick, valid_until_tick, epoch })
    }

    /// Returns the fact or artifact source for the relation.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the relation-specific conservative error bound.
    #[must_use]
    pub const fn error_bound(&self) -> u64 {
        self.error_bound
    }

    /// Returns the first included native tick.
    #[must_use]
    pub const fn valid_from_tick(&self) -> u64 {
        self.valid_from_tick
    }

    /// Returns the last included native tick.
    #[must_use]
    pub const fn valid_until_tick(&self) -> u64 {
        self.valid_until_tick
    }

    /// Returns the qualification epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    fn covers(&self, tick: u64, epoch: u64) -> bool {
        self.epoch == epoch && (self.valid_from_tick..=self.valid_until_tick).contains(&tick)
    }
}

macro_rules! relation {
    ($name:ident, $summary:literal) => {
        #[doc = $summary]
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name(RelationValidity);

        impl $name {
            /// Creates a relation from its independently sourced validity record.
            #[must_use]
            pub const fn new(validity: RelationValidity) -> Self {
                Self(validity)
            }

            /// Returns provenance, error, validity, and epoch.
            #[must_use]
            pub const fn validity(&self) -> &RelationValidity {
                &self.0
            }
        }
    };
}

relation!(TimeRelation, "A scoped relationship between clock domains.");
relation!(PhaseRelation, "A scoped coherent phase-reference relationship.");
relation!(Geometry, "A scoped physical geometry relationship.");

/// A scoped mapping from protocol streams and chains to physical ports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortMapping {
    validity: RelationValidity,
    tx_geometry_known: bool,
}

/// One independently persisted time, phase, port, or geometry qualification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualificationRelation {
    /// A clock-domain relation.
    Time(TimeRelation),
    /// A coherent phase-reference relation.
    Phase(PhaseRelation),
    /// A protocol-to-physical port mapping.
    Port(PortMapping),
    /// A physical geometry relation.
    Geometry(Geometry),
}

impl QualificationRelation {
    /// Returns the independently sourced validity record.
    #[must_use]
    pub const fn validity(&self) -> &RelationValidity {
        match self {
            Self::Time(relation) => relation.validity(),
            Self::Phase(relation) => relation.validity(),
            Self::Port(relation) => relation.validity(),
            Self::Geometry(relation) => relation.validity(),
        }
    }
}

impl PortMapping {
    /// Creates a mapping and records whether transmitter precoding preserves known geometry.
    #[must_use]
    pub const fn new(validity: RelationValidity, tx_geometry_known: bool) -> Self {
        Self { validity, tx_geometry_known }
    }

    /// Returns provenance, error, validity, and epoch.
    #[must_use]
    pub const fn validity(&self) -> &RelationValidity {
        &self.validity
    }

    /// Reports whether transmitter geometry is established rather than inferred.
    #[must_use]
    pub const fn tx_geometry_known(&self) -> bool {
        self.tx_geometry_known
    }
}

/// One causal evidence block with independently encoded member quality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceBlock {
    tick: u64,
    epoch: u64,
    quality: Box<[EvidenceQuality]>,
}

impl EvidenceBlock {
    /// Creates an evidence block without collapsing its member-quality states.
    #[must_use]
    pub fn new(tick: u64, epoch: u64, quality: impl IntoIterator<Item = EvidenceQuality>) -> Self {
        Self { tick, epoch, quality: quality.into_iter().collect() }
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

/// Explicit relation requirements fixed by one model artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelRequirements {
    time: bool,
    phase: bool,
    port: bool,
    geometry: bool,
    tx_geometry: bool,
}

impl ModelRequirements {
    /// Requirements for the absolute-response operator.
    #[must_use]
    pub const fn absolute_response() -> Self {
        Self { time: true, phase: false, port: false, geometry: false, tx_geometry: false }
    }

    /// Requirements for the coherent angle-delay operator.
    #[must_use]
    pub const fn angle_delay() -> Self {
        Self { time: true, phase: true, port: true, geometry: true, tx_geometry: true }
    }

    /// Requirements for the causal fast-change operator.
    #[must_use]
    pub const fn fast_change() -> Self {
        Self { time: true, phase: false, port: false, geometry: false, tx_geometry: false }
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
    /// Creates a snapshot without deriving one relation from another.
    #[must_use]
    pub const fn new(
        time: Option<TimeRelation>,
        phase: Option<PhaseRelation>,
        port: Option<PortMapping>,
        geometry: Option<Geometry>,
    ) -> Self {
        Self { time, phase, port, geometry }
    }

    /// Evaluates one operator for one block using artifact-declared requirements.
    #[must_use]
    pub fn eligibility(
        &self,
        operator: PhysicalOperator,
        block: &EvidenceBlock,
        requirements: ModelRequirements,
    ) -> Eligibility {
        let mandatory = match operator {
            PhysicalOperator::AbsoluteResponse => ModelRequirements::absolute_response(),
            PhysicalOperator::FastChange => ModelRequirements::fast_change(),
            PhysicalOperator::AngleDelay => ModelRequirements::angle_delay(),
        };
        let requirements = ModelRequirements {
            time: requirements.time || mandatory.time,
            phase: requirements.phase || mandatory.phase,
            port: requirements.port || mandatory.port,
            geometry: requirements.geometry || mandatory.geometry,
            tx_geometry: requirements.tx_geometry || mandatory.tx_geometry,
        };
        let mut gaps = Vec::new();
        if block.quality.is_empty() {
            gaps.push(QualificationGap::NotCaptured);
        }
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
        if requirements.time && !covers(self.time.as_ref().map(TimeRelation::validity), block) {
            gaps.push(QualificationGap::TimeRelation);
        }
        if requirements.phase && !covers(self.phase.as_ref().map(PhaseRelation::validity), block) {
            gaps.push(QualificationGap::PhaseRelation);
        }
        if requirements.port && !covers(self.port.as_ref().map(PortMapping::validity), block) {
            gaps.push(QualificationGap::PortMapping);
        }
        if requirements.geometry && !covers(self.geometry.as_ref().map(Geometry::validity), block) {
            gaps.push(QualificationGap::Geometry);
        }
        if requirements.tx_geometry
            && self.port.as_ref().is_some_and(|mapping| !mapping.tx_geometry_known())
        {
            gaps.push(QualificationGap::TxGeometry);
        }
        Eligibility { gaps: gaps.into_boxed_slice() }
    }
}

fn covers(validity: Option<&RelationValidity>, block: &EvidenceBlock) -> bool {
    validity.is_some_and(|validity| validity.covers(block.tick, block.epoch))
}

/// One explicit reason an operator cannot consume an evidence block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationGap {
    /// No capture was attempted.
    NotCaptured,
    /// An expected capture was lost.
    Lost,
    /// Captured values were invalid.
    Invalid,
    /// Values were interpolated.
    Interpolated,
    /// Training masked the values.
    TrainingMasked,
    /// No valid time relation covers the block.
    TimeRelation,
    /// No valid phase relation covers the block.
    PhaseRelation,
    /// No valid port mapping covers the block.
    PortMapping,
    /// No valid geometry covers the block.
    Geometry,
    /// Transmitter geometry is unknown because precoding is not established.
    TxGeometry,
}

/// Queryable per-operator eligibility result for one evidence block.
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

    /// Returns every explicit quality or relation gap.
    #[must_use]
    pub fn gaps(&self) -> &[QualificationGap] {
        &self.gaps
    }
}

/// Invalid fragment, resource limit, or relation input.
#[derive(Debug)]
pub struct MeasurementError {
    message: &'static str,
    backtrace: Box<Backtrace>,
}

impl MeasurementError {
    fn new(message: &'static str) -> Self {
        Self { message, backtrace: Box::new(Backtrace::capture()) }
    }

    /// Returns the captured failure backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for MeasurementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for MeasurementError {}
