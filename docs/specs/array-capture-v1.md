# Locally coherent array capture v1

This contract defines the bounded Host-side source-adapter input for an
ESPARGOS-class locally coherent receive array. It does not change the existing
ESP32-S3 firmware, native-frame v1 bytes, or ordinary single-path ESP capability.

## Canonical envelope

All integers use little-endian byte order. Strings are a nonzero `u16` byte
length followed by UTF-8. Collections use the stated count followed by items in
their source order. The digest is SHA-256 over every preceding envelope byte.

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 4 | ASCII `WAC1` |
| 4 | 2 | schema version `1` |
| 6 | 2 | reserved zero |
| 8 | 4 | payload bytes |
| 12 | payload bytes | canonical payload below |
| end − 32 | 32 | SHA-256 digest |

The payload contains, in order:

1. sensor string, device `u64`, key epoch `u16`, and boot generation `u32`;
2. transmitter and native-event 32-byte identities, then a `u8` retransmission
   marker and optional 32-byte retransmission identity;
3. 32-byte profile, radio, and channel identities;
4. array and RF-device strings, then the 32-byte native LTF identity;
5. source-window start/end `u64` values and associated UTC nanoseconds `u64`;
6. native bandwidth `u32`, rate code `u32`, optional-MCS marker plus `u16`, and
   Host receive monotonic nanoseconds `u64`;
7. a `u16` per-path radio-fact count; each item is native antenna `u16`, RSSI
   and noise `i16` hundredths of dBm, then an optional-gain marker and `i16`
   hundredths of dB;
8. a `u16` frequency count and each exact `u64` frequency in hertz;
9. a `u16` path count; each path contains Tx stream and Rx chain `u16`, a
   32-byte native path identity, and Tx/Rx logical-path strings;
10. a `u32` sample count followed by path-major IQ samples. Each sample is
    native `i16` I, native `i16` Q, and one acquisition-state byte.

Acquisition states distinguish captured, not captured, lost, invalid,
interpolated, and training-masked values. A zero IQ pair remains a measurement,
not a missing marker. Frequency values are nonzero and strictly increasing.
Path and native-path identities are unique. The IQ and state counts must equal
`frequency count × path count`.

The format limits one capture to 4,096 frequencies, 256 paths, 4,194,304 IQ
samples, 256 UTF-8 bytes per identity, and 20 MiB including the digest. Parsing
rejects unsupported versions, nonzero reserved bytes, overflow, truncation,
non-canonical encodings, invalid identities, shape mismatches, and digest
mismatches.

## Qualified two-by-four adaptation

The first adapter accepts exactly eight distinct Rx chains from one Tx stream.
It binds the capture digest, source/boot, profile/radio/channel, window, and all
eight paths to one measurement evidence block. The requested operator must be
angle-delay. Time, phase, port, and geometry eligibility are evaluated by the
measurement qualification boundary; no aggregate calibrated flag is accepted.

The sealed calibration must name the same RF device and local array, contain
one Tx plus eight Rx mappings, map qualification antenna indices to the eight
physical elements, cover every frequency and capture timestamp, and use the
same time/phase/geometry epoch. Phase coherence must cover the capture interval.
Array-to-world and device-to-array transforms must be finite rigid transforms;
the array-to-world pose and error budgets must match the operator requirements.
Collinear or duplicate phase centres cannot produce an angle-delay record.

The bounded estimator performs a per-element delay transform followed by a
15-degree local azimuth/elevation scan. It evaluates at most 64 delay bins and
retains at most eight separated candidates. Reported error contains half-bin
delay resolution plus angular grid, aperture, and calibration geometry error;
these deterministic bounds do not establish real-hardware accuracy.

The earliest retained qualified peak is only `DirectPathPossible`. A peak that
matches an explicitly supplied immutable, already-qualified static spectrum is
`StableStatic`; unmatched strong residuals are `DynamicCandidate`; other paths
remain `Unexplained`. None of these values is a person position, foot point,
hip, track, or world-state fact. Static-reference bytes and their digest remain
available; the adapter never deletes a static reflection or promotes a formal
background condition.

Each record retains one array identity, world origin, world-coordinate unit
directions, local angles, delay, normalized power, uncertainty, sample
coverage, and the capture/calibration/static-reference digests. Three-view
coverage reports each independently qualified array. It does not share or
combine carrier phase across arrays and does not intersect rays into a person
position. At least two locally non-degenerate views are reported separately as
the accepted coverage minimum.
