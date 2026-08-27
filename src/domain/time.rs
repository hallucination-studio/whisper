//! Explicit monotonic time and time-quality values for deterministic replay.

use std::fmt;

use serde::Serialize;

/// Errors produced while constructing time values.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TimeError {
    /// An interval ended before it started.
    #[error("time interval end {end} precedes start {start}")]
    ReversedInterval {
        /// Interval start in session nanoseconds.
        start: u64,
        /// Interval end in session nanoseconds.
        end: u64,
    },
    /// A clock-corrected event omitted its mapping version.
    #[error("clock-corrected event time requires a clock mapping version")]
    MissingClockMapping,
    /// A receive-only event incorrectly supplied a clock mapping version.
    #[error("receive-only event time must not supply a clock mapping version")]
    UnexpectedClockMapping,
    /// A receive-only event must use the host receive timestamp verbatim.
    #[error("receive-only event time {event} differs from received time {received}")]
    ReceiveEventMismatch {
        /// Host receive timestamp in session nanoseconds.
        received: u64,
        /// Supplied event timestamp in session nanoseconds.
        event: u64,
    },
    /// A clock-corrected event did not carry device capture ticks.
    #[error("clock-corrected event time requires a device timestamp")]
    MissingDeviceTimestamp,
    /// A device timestamp did not identify a clock domain.
    #[error("device clock domain must not be empty")]
    EmptyClockDomain,
    /// A clock mapping version was empty.
    #[error("clock mapping version must not be empty")]
    EmptyClockMappingVersion,
}

/// Monotonic session time measured in nanoseconds from the session epoch.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SessionTime(u64);

impl SessionTime {
    /// Creates a session timestamp from nanoseconds.
    #[must_use]
    pub const fn from_nanos(nanoseconds: u64) -> Self {
        Self(nanoseconds)
    }

    /// Returns the timestamp in nanoseconds.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// Adds nanoseconds without wrapping.
    #[must_use]
    pub const fn checked_add(self, nanoseconds: u64) -> Option<Self> {
        match self.0.checked_add(nanoseconds) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the elapsed duration when `self` is not earlier than `other`.
    #[must_use]
    pub const fn checked_duration_since(self, other: Self) -> Option<u64> {
        self.0.checked_sub(other.0)
    }
}

impl fmt::Display for SessionTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}ns", self.0)
    }
}

/// A half-open interval `[start, end)` in session monotonic time.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TimeInterval {
    start: SessionTime,
    end: SessionTime,
}

impl TimeInterval {
    /// Creates an interval, allowing an empty interval but not reversed bounds.
    pub const fn try_new(start: SessionTime, end: SessionTime) -> Result<Self, TimeError> {
        if end.as_nanos() < start.as_nanos() {
            return Err(TimeError::ReversedInterval {
                start: start.as_nanos(),
                end: end.as_nanos(),
            });
        }
        Ok(Self { start, end })
    }

    /// Returns the start bound.
    #[must_use]
    pub const fn start(self) -> SessionTime {
        self.start
    }

    /// Returns the exclusive end bound.
    #[must_use]
    pub const fn end(self) -> SessionTime {
        self.end
    }

    /// Returns the width in nanoseconds.
    #[must_use]
    pub const fn duration_ns(self) -> u64 {
        self.end.as_nanos() - self.start.as_nanos()
    }

    /// Reports whether no time lies in this interval.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start.as_nanos() == self.end.as_nanos()
    }

    /// Reports whether the timestamp lies in this half-open interval.
    #[must_use]
    pub const fn contains(self, time: SessionTime) -> bool {
        time.as_nanos() >= self.start.as_nanos() && time.as_nanos() < self.end.as_nanos()
    }
}

/// A timestamp supplied by a capture device, with its explicit clock domain.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DeviceTimestamp {
    ticks: u64,
    clock_domain: Box<str>,
}

impl DeviceTimestamp {
    /// Creates a device timestamp.
    pub fn try_new(ticks: u64, clock_domain: impl Into<Box<str>>) -> Result<Self, TimeError> {
        let clock_domain = clock_domain.into();
        if clock_domain.trim().is_empty() {
            return Err(TimeError::EmptyClockDomain);
        }
        Ok(Self { ticks, clock_domain })
    }

    /// Returns the raw device tick count.
    #[must_use]
    pub const fn ticks(&self) -> u64 {
        self.ticks
    }

    /// Returns the device clock domain.
    #[must_use]
    pub fn clock_domain(&self) -> &str {
        &self.clock_domain
    }
}

/// The version of an explicit host/device clock mapping.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ClockMappingVersion(Box<str>);

impl ClockMappingVersion {
    /// Creates a non-empty mapping version.
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, TimeError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(TimeError::EmptyClockMappingVersion);
        }
        Ok(Self(value))
    }

    /// Returns the mapping version.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The source used to obtain an event timestamp.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum EventTimeSource {
    /// The host receive monotonic timestamp is the event timestamp.
    #[default]
    ReceiveOnly,
    /// A verified device clock mapping corrected the timestamp.
    ClockCorrected,
}

/// Coarse quality levels used by configuration and evidence.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum TimeQuality {
    /// No usable event-time quality is available.
    #[default]
    Unknown,
    /// Host receive monotonic time is ordered and usable for non-coherent work.
    ReceiveOnly,
    /// A verified capture clock mapping is available.
    ClockCorrected,
}

impl From<EventTimeSource> for TimeQuality {
    fn from(source: EventTimeSource) -> Self {
        match source {
            EventTimeSource::ReceiveOnly => Self::ReceiveOnly,
            EventTimeSource::ClockCorrected => Self::ClockCorrected,
        }
    }
}

/// Event timing and provenance carried by a decoded observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FrameTiming {
    received: SessionTime,
    device: Option<DeviceTimestamp>,
    event: SessionTime,
    source: EventTimeSource,
    mapping_version: Option<ClockMappingVersion>,
    uncertainty_ns: u64,
}

impl FrameTiming {
    /// Constructs timing after enforcing mapping/source consistency.
    pub fn try_new(
        received: SessionTime,
        device: Option<DeviceTimestamp>,
        event: SessionTime,
        source: EventTimeSource,
        mapping_version: Option<ClockMappingVersion>,
        uncertainty_ns: u64,
    ) -> Result<Self, TimeError> {
        match (source, mapping_version.is_some()) {
            (EventTimeSource::ReceiveOnly, true) => return Err(TimeError::UnexpectedClockMapping),
            (EventTimeSource::ClockCorrected, false) => return Err(TimeError::MissingClockMapping),
            _ => {}
        }
        if source == EventTimeSource::ReceiveOnly && event != received {
            return Err(TimeError::ReceiveEventMismatch {
                received: received.as_nanos(),
                event: event.as_nanos(),
            });
        }
        if matches!(source, EventTimeSource::ClockCorrected) && device.is_none() {
            return Err(TimeError::MissingDeviceTimestamp);
        }
        Ok(Self { received, device, event, source, mapping_version, uncertainty_ns })
    }

    /// Returns the host receive timestamp.
    #[must_use]
    pub const fn received(&self) -> SessionTime {
        self.received
    }

    /// Returns the optional device timestamp.
    #[must_use]
    pub const fn device(&self) -> Option<&DeviceTimestamp> {
        self.device.as_ref()
    }

    /// Returns the effective event timestamp.
    #[must_use]
    pub const fn event(&self) -> SessionTime {
        self.event
    }

    /// Returns the event-time source.
    #[must_use]
    pub const fn source(&self) -> EventTimeSource {
        self.source
    }

    /// Returns the optional clock mapping version.
    #[must_use]
    pub const fn mapping_version(&self) -> Option<&ClockMappingVersion> {
        self.mapping_version.as_ref()
    }

    /// Returns the uncertainty in nanoseconds.
    #[must_use]
    pub const fn uncertainty_ns(&self) -> u64 {
        self.uncertainty_ns
    }
}
