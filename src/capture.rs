//! Transport-neutral packet envelopes used by the deterministic ingest path.

use std::fmt;
use std::net::SocketAddr;
use std::time::{Instant, SystemTime};

use crate::domain::identity::SessionId;

/// One UDP datagram with receive facts captured before bounded delivery admission.
#[derive(Debug)]
pub struct CapturedDatagram {
    peer: SocketAddr,
    received_monotonic: Instant,
    received_utc: SystemTime,
    bytes: Box<[u8]>,
}

impl CapturedDatagram {
    /// Creates a captured datagram from exact receive facts and encrypted bytes.
    #[must_use]
    pub fn new(
        peer: SocketAddr,
        received_monotonic: Instant,
        received_utc: SystemTime,
        bytes: impl Into<Box<[u8]>>,
    ) -> Self {
        Self { peer, received_monotonic, received_utc, bytes: bytes.into() }
    }

    pub(crate) const fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub(crate) const fn received_monotonic(&self) -> Instant {
        self.received_monotonic
    }

    pub(crate) const fn received_utc(&self) -> SystemTime {
        self.received_utc
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_bytes(self) -> Box<[u8]> {
        self.bytes
    }
}

/// Durable outcome for one candidate accepted by the capture writer queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// Store-scoped replay admission rejected the packet without writes.
    ReplayRejected,
    /// The admitted packet and its complete write set committed atomically.
    Committed(CommitReceipt),
}

/// Committed packet disposition stored by the bounded delivery ingest path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketDisposition {
    /// The authenticated native-frame kind is not defined by version 1.
    UnknownKind,
    /// A known native-frame kind did not satisfy its exact body grammar.
    MalformedKnownBody,
    /// The authenticated capability firmware digest did not match its configured pin.
    BuildMismatch,
    /// The authenticated capability digest did not match its configured pin.
    CapabilityPinMismatch,
    /// A conforming capability epoch row was inserted or exactly validated.
    CapabilityCommitted,
    /// A conforming authenticated health packet committed.
    HealthCommitted,
    /// Authenticated body capability identity did not match durable/configured authority.
    CapabilityMismatch,
    /// CSI arrived before a capability row was committed for its device epoch.
    CapabilityUnavailable,
    /// Authenticated CSI source identity did not match the configured link.
    SourceMismatch,
    /// Authenticated CSI radio facts did not match the configured link policy.
    RadioMismatch,
    /// Authenticated CSI exceeded the configured decoded-body budget.
    BodyBudgetMismatch,
    /// Authenticated CSI could not satisfy the imported typed observation domain.
    DecodedDomainRejected,
    /// A fully conforming native-coordinate CSI observation committed.
    CsiCommitted,
}

/// Monotonic packet position within one Capture Session.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
pub struct CaptureRecordSequence(u64);

impl CaptureRecordSequence {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Returns the numeric Capture Session position.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for CaptureRecordSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Monotonic query-visible commit position within one Store.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProjectionSequence(u64);

impl ProjectionSequence {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Returns the numeric Store projection position.
    #[must_use]
    #[cfg(feature = "ingest-test-hooks")]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ProjectionSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProjectionCommit {
    store_id: [u8; 32],
    sequence: ProjectionSequence,
}

impl ProjectionCommit {
    pub(crate) const fn new(store_id: [u8; 32], sequence: ProjectionSequence) -> Self {
        Self { store_id, sequence }
    }

    pub(crate) const fn store_id(self) -> [u8; 32] {
        self.store_id
    }

    pub(crate) const fn sequence(self) -> ProjectionSequence {
        self.sequence
    }
}

/// Post-commit identity for one admitted capture packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    disposition: PacketDisposition,
    record_sequence: CaptureRecordSequence,
    projection_sequence: ProjectionSequence,
}

impl CommitReceipt {
    pub(crate) const fn new(
        disposition: PacketDisposition,
        record_sequence: CaptureRecordSequence,
        projection_sequence: ProjectionSequence,
    ) -> Self {
        Self { disposition, record_sequence, projection_sequence }
    }

    /// Returns the packet's committed first-match disposition.
    #[must_use]
    #[cfg(feature = "ingest-test-hooks")]
    pub const fn disposition(self) -> PacketDisposition {
        self.disposition
    }

    /// Returns the committed Capture Session record sequence.
    #[must_use]
    #[cfg(feature = "ingest-test-hooks")]
    pub const fn record_sequence(self) -> CaptureRecordSequence {
        self.record_sequence
    }

    /// Returns the committed Store projection sequence.
    #[must_use]
    pub const fn projection_sequence(self) -> ProjectionSequence {
        self.projection_sequence
    }
}

/// The only transport family understood by the first native-frame decoder.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum WireFormat {
    /// The authenticated native-frame UDP envelope.
    NativeFrameUdp,
}

/// An immutable view of one datagram accepted by the capture boundary.
///
/// This type records receive context and exact encrypted bytes. It does not
/// open sockets, read clocks, look up secrets, or decode the payload.
#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapturedPacket {
    session_id: SessionId,
    record_seq: u64,
    receive_monotonic_ns: u64,
    receive_utc_ns: i64,
    peer: SocketAddr,
    wire_format: WireFormat,
    bytes: Box<[u8]>,
}

#[allow(dead_code)]
impl CapturedPacket {
    /// Creates a packet from already captured receive context and owned bytes.
    #[must_use]
    pub(crate) fn new(
        session_id: SessionId,
        record_seq: u64,
        receive_monotonic_ns: u64,
        receive_utc_ns: i64,
        peer: SocketAddr,
        wire_format: WireFormat,
        bytes: impl Into<Box<[u8]>>,
    ) -> Self {
        Self {
            session_id,
            record_seq,
            receive_monotonic_ns,
            receive_utc_ns,
            peer,
            wire_format,
            bytes: bytes.into(),
        }
    }

    /// Returns the session identity supplied by the outer session record.
    #[must_use]
    pub(crate) const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the total session record sequence.
    #[must_use]
    pub(crate) const fn record_seq(&self) -> u64 {
        self.record_seq
    }

    /// Returns host receive monotonic time in nanoseconds.
    #[must_use]
    pub(crate) const fn receive_monotonic_ns(&self) -> u64 {
        self.receive_monotonic_ns
    }

    /// Returns host receive UTC time in nanoseconds for display and locating records.
    #[must_use]
    pub(crate) const fn receive_utc_ns(&self) -> i64 {
        self.receive_utc_ns
    }

    /// Returns the source peer address; route resolution ignores its port.
    #[must_use]
    pub(crate) const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Returns the transport family recorded at the capture boundary.
    #[must_use]
    pub(crate) const fn wire_format(&self) -> WireFormat {
        self.wire_format
    }

    /// Returns the immutable datagram bytes.
    #[must_use]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_roundtrips_all_receive_context_without_mutable_bytes() {
        let session = SessionId::new("test-session").expect("valid session");
        let packet = CapturedPacket::new(
            session.clone(),
            42,
            123_456,
            -7,
            "192.0.2.10:5005".parse().expect("peer"),
            WireFormat::NativeFrameUdp,
            vec![1_u8, 2, 3].into_boxed_slice(),
        );

        assert_eq!(packet.session_id(), &session);
        assert_eq!(packet.record_seq(), 42);
        assert_eq!(packet.receive_monotonic_ns(), 123_456);
        assert_eq!(packet.receive_utc_ns(), -7);
        assert_eq!(packet.peer(), "192.0.2.10:5005".parse().expect("peer"));
        assert_eq!(packet.wire_format(), WireFormat::NativeFrameUdp);
        assert_eq!(packet.bytes(), &[1, 2, 3]);

        let cloned = packet.clone();
        assert_eq!(cloned, packet);
        assert_eq!(cloned.bytes(), &[1, 2, 3]);
    }
}
