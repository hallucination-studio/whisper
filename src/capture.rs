//! Transport-neutral packet envelopes used by the deterministic ingest path.

use std::net::SocketAddr;

use crate::domain::identity::SessionId;

/// The transport family that supplied a captured datagram.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum WireFormat {
    /// An ESP32 UDP datagram whose protocol magic is decoded by `esp32`.
    Esp32Udp,
}

/// An immutable in-memory view of one authoritative received datagram.
///
/// Construction records all receive context supplied by the capture boundary. It
/// deliberately does not open sockets, read clocks, perform I/O, or decode bytes.
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

    /// Returns the source peer address; route resolution intentionally ignores its port.
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
            WireFormat::Esp32Udp,
            vec![1_u8, 2, 3].into_boxed_slice(),
        );

        assert_eq!(packet.session_id(), &session);
        assert_eq!(packet.record_seq(), 42);
        assert_eq!(packet.receive_monotonic_ns(), 123_456);
        assert_eq!(packet.receive_utc_ns(), -7);
        assert_eq!(packet.peer(), "192.0.2.10:5005".parse().expect("peer"));
        assert_eq!(packet.wire_format(), WireFormat::Esp32Udp);
        assert_eq!(packet.bytes(), &[1, 2, 3]);

        let cloned = packet.clone();
        assert_eq!(cloned, packet);
        assert_eq!(cloned.bytes(), &[1, 2, 3]);
    }
}
