//! Timestamp and interval invariant tests.

use crate::domain::time::{
    ClockMappingVersion, EventTimeSource, FrameTiming, SessionTime, TimeError, TimeInterval,
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
