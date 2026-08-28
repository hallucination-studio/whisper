//! Timestamp and interval invariant tests.

use crate::domain::time::{
    ClockMappingVersion, DeviceTimestamp, EventTimeSource, FrameTiming, SessionTime, TimeError,
    TimeInterval,
};

#[test]
fn receive_only_time_is_the_host_receive_time() {
    let received = SessionTime::from_nanos(10);
    assert!(matches!(
        FrameTiming::try_new(
            received,
            None,
            SessionTime::from_nanos(11),
            EventTimeSource::ReceiveOnly,
            None,
            0,
        ),
        Err(TimeError::ReceiveEventMismatch { .. })
    ));
    assert!(
        FrameTiming::try_new(received, None, received, EventTimeSource::ReceiveOnly, None, 0)
            .is_ok()
    );
}

#[test]
fn interval_is_half_open_and_rejects_reverse_bounds() {
    let interval = TimeInterval::try_new(SessionTime::from_nanos(2), SessionTime::from_nanos(5))
        .expect("interval");
    assert!(interval.contains(SessionTime::from_nanos(2)));
    assert!(!interval.contains(SessionTime::from_nanos(5)));
    assert!(TimeInterval::try_new(SessionTime::from_nanos(5), SessionTime::from_nanos(2)).is_err());
}

#[test]
fn clock_mapping_version_rejects_empty_values_with_precise_error() {
    assert!(matches!(ClockMappingVersion::new(" \t"), Err(TimeError::EmptyClockMappingVersion)));
}

#[test]
fn device_timestamp_enforces_clock_domain_utf8_byte_limit() {
    let exact_limit = "\u{e9}".repeat(64);
    let over_limit = format!("{exact_limit}a");
    assert_eq!(exact_limit.len(), 128);
    assert_eq!(over_limit.len(), 129);

    let timestamp = DeviceTimestamp::try_new(7, exact_limit).expect("128-byte clock domain");
    assert_eq!(timestamp.clock_domain().len(), 128);

    let error = DeviceTimestamp::try_new(7, over_limit).expect_err("129 bytes must be rejected");
    assert_eq!(error, TimeError::ClockDomainTooLong { actual_bytes: 129, max_bytes: 128 });
    assert_eq!(error.to_string(), "device clock domain is 129 UTF-8 bytes; maximum is 128 bytes");
}

#[test]
fn clock_mapping_version_enforces_utf8_byte_limit() {
    let exact_limit = format!("{}ab", "\u{754c}".repeat(42));
    let over_limit = format!("{exact_limit}c");
    assert_eq!(exact_limit.len(), 128);
    assert_eq!(over_limit.len(), 129);

    let version = ClockMappingVersion::new(exact_limit).expect("128-byte mapping version");
    assert_eq!(version.as_str().len(), 128);

    let error = ClockMappingVersion::new(over_limit).expect_err("129 bytes must be rejected");
    assert_eq!(error, TimeError::ClockMappingVersionTooLong { actual_bytes: 129, max_bytes: 128 });
    assert_eq!(error.to_string(), "clock mapping version is 129 UTF-8 bytes; maximum is 128 bytes");
}

#[test]
fn empty_clock_text_errors_take_precedence_over_byte_limits() {
    let whitespace = " ".repeat(129);

    assert_eq!(DeviceTimestamp::try_new(7, ""), Err(TimeError::EmptyClockDomain));
    assert_eq!(ClockMappingVersion::new(""), Err(TimeError::EmptyClockMappingVersion));
    assert_eq!(DeviceTimestamp::try_new(7, whitespace.clone()), Err(TimeError::EmptyClockDomain));
    assert_eq!(ClockMappingVersion::new(whitespace), Err(TimeError::EmptyClockMappingVersion));
}
