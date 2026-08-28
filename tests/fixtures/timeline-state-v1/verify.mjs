import { readFileSync } from "node:fs";

const vectorUrl = new URL("vector-v1.txt", import.meta.url);
const vector = Object.fromEntries(
  readFileSync(vectorUrl, "utf8")
    .trim()
    .split("\n")
    .map((line) => line.split("=")),
);

function head(major, value) {
  const number = BigInt(value);
  if (number < 24n) {
    return Buffer.from([(major << 5) | Number(number)]);
  }
  if (number <= 0xffn) {
    return Buffer.from([(major << 5) | 24, Number(number)]);
  }
  if (number <= 0xffffn) {
    const bytes = Buffer.alloc(3);
    bytes[0] = (major << 5) | 25;
    bytes.writeUInt16BE(Number(number), 1);
    return bytes;
  }
  if (number <= 0xffff_ffffn) {
    const bytes = Buffer.alloc(5);
    bytes[0] = (major << 5) | 26;
    bytes.writeUInt32BE(Number(number), 1);
    return bytes;
  }
  const bytes = Buffer.alloc(9);
  bytes[0] = (major << 5) | 27;
  bytes.writeBigUInt64BE(number, 1);
  return bytes;
}

function unsigned(value) {
  return head(0, value);
}

function signed(value) {
  const number = BigInt(value);
  return number >= 0n ? unsigned(number) : head(1, -1n - number);
}

function text(value) {
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([head(3, bytes.length), bytes]);
}

function byteString(hex) {
  const bytes = Buffer.from(hex, "hex");
  return Buffer.concat([head(2, bytes.length), bytes]);
}

function array(values) {
  return Buffer.concat([head(4, values.length), ...values]);
}

function map(entries) {
  return Buffer.concat([
    head(5, entries.length),
    ...entries.flatMap(([key, value]) => [text(key), value]),
  ]);
}

const nullValue = Buffer.from([0xf6]);
const falseValue = Buffer.from([0xf4]);
const trueValue = Buffer.from([0xf5]);

function openWindow(windowId, startNs, endNs) {
  return map([
    ["window_id", unsigned(windowId)],
    ["start_ns", unsigned(startNs)],
    ["end_ns", unsigned(endNs)],
    ["observations", array([])],
  ]);
}

function timelineState({
  lastRecordSeq,
  explicitClockNs,
  lastAdvanceNs,
  closedWindowFrontier,
  openWindows,
  sourceStates = [],
  streamStates = [],
  missingSpans = [],
  finished,
}) {
  return map([
    ["schema_version", unsigned(1)],
    ["window_contract_id", byteString(vector.window_contract_id)],
    ["session_id", text("session-1")],
    ["last_record_seq", lastRecordSeq === null ? nullValue : unsigned(lastRecordSeq)],
    ["explicit_clock_ns", explicitClockNs === null ? nullValue : unsigned(explicitClockNs)],
    ["last_advance_ns", lastAdvanceNs === null ? nullValue : unsigned(lastAdvanceNs)],
    ["source_states", array(sourceStates)],
    ["stream_states", array(streamStates)],
    [
      "closed_window_frontier",
      closedWindowFrontier === null ? nullValue : unsigned(closedWindowFrontier),
    ],
    ["open_windows", array(openWindows)],
    ["missing_spans", array(missingSpans)],
    ["finished", finished ? trueValue : falseValue],
  ]);
}

function deviceEpoch(device, bootGeneration) {
  return map([
    ["device", unsigned(device)],
    ["boot_generation", unsigned(bootGeneration)],
  ]);
}

function streamIdentity(link, profileByte, bootGeneration) {
  return map([
    ["sensor", text("sensor-a")],
    ["link", text(link)],
    ["profile", byteString(profileByte.repeat(32))],
    ["device_epoch", deviceEpoch(1, bootGeneration)],
  ]);
}

function sourceState(bootGeneration, maximumSequence, first, last) {
  return map([
    ["device_epoch", deviceEpoch(1, bootGeneration)],
    ["maximum_sequence", unsigned(maximumSequence)],
    ["seen_ranges", array([map([["first", unsigned(first)], ["last", unsigned(last)]])])],
  ]);
}

function streamState({ profileByte, bootGeneration, segmentId, status, lastActivityNs, maximumEventNs, endedAtNs, epochTermination }) {
  return map([
    ["stream", streamIdentity("link-a", profileByte, bootGeneration)],
    ["segment_id", unsigned(segmentId)],
    ["status", text(status)],
    ["last_activity_ns", unsigned(lastActivityNs)],
    ["maximum_event_ns", unsigned(maximumEventNs)],
    ["ended_at_ns", endedAtNs === null ? nullValue : unsigned(endedAtNs)],
    ["end_reason", status === "active" ? nullValue : text(epochTermination === null ? "inactive" : "epoch")],
    ["epoch_termination", epochTermination ?? nullValue],
  ]);
}

function missingSpan(link, profileByte, segmentId, endNs) {
  return map([
    ["stream", streamIdentity(link, profileByte, 1)],
    ["segment_id", unsigned(segmentId)],
    ["start_ns", unsigned(5_000_000_000)],
    ["end_ns", endNs === null ? nullValue : unsigned(endNs)],
    ["reason", text("inactive")],
  ]);
}

function classification(kind) {
  return map([["kind", text(kind)], ["value", nullValue]]);
}

function disposition(windowId) {
  return map([
    ["kind", text("windowed")],
    ["window_id", unsigned(windowId)],
    ["reason", nullValue],
  ]);
}

function observation(recordSeq, captureSequence, receivedNs, bootGeneration, profileByte, corrected = false) {
  const eventNs = corrected ? 5_050_000_000 : receivedNs;
  return map([
    ["input", map([
      ["session", text("session-1")],
      ["record_seq", unsigned(recordSeq)],
      ["decoder_version", text("native-frame-v1")],
    ])],
    ["sensor", text("sensor-a")],
    ["hardware", text("esp32-s3")],
    ["link", text("link-a")],
    ["device_epoch", deviceEpoch(1, bootGeneration)],
    ["capture_sequence", unsigned(captureSequence)],
    ["callback_tick_us", unsigned(500)],
    ["timing", map([
      ["received_ns", unsigned(receivedNs)],
      ["device", corrected ? map([["ticks", unsigned(1_234)], ["clock_domain", text("esp-clock")]]) : nullValue],
      ["event_ns", unsigned(eventNs)],
      ["source", text(corrected ? "clock_corrected" : "receive_only")],
      ["mapping_version", corrected ? text("map-v1") : nullValue],
      ["uncertainty_ns", unsigned(corrected ? 25 : 0)],
    ])],
    ["radio", map([
      ["channel", corrected ? unsigned(6) : nullValue],
      ["centre_frequency_hz", corrected ? unsigned(2_437_000_000) : nullValue],
      ["bandwidth_hz", corrected ? unsigned(20_000_000) : nullValue],
      ["ppdu", corrected ? text("he") : nullValue],
      ["rssi_dbm", signed(-42)],
      ["noise_floor_dbm", signed(-90)],
    ])],
    ["profile", byteString(profileByte.repeat(32))],
    ["csi", corrected ? map([
      ["layout", map([
        ["paths", array([map([["kind", text("tx_rx")], ["tx_stream", unsigned(1)], ["rx_chain", unsigned(2)]])])],
        ["samples", map([["kind", text("ieee_tone_index")], ["values", array([signed(-1), unsigned(1)])]])],
        ["order", text("path_then_sample")],
      ])],
      ["samples", array([
        map([["i", signed(-3)], ["q", unsigned(4)], ["valid", trueValue]]),
        map([["i", unsigned(5)], ["q", signed(-6)], ["valid", falseValue]]),
      ])],
      ["encoding", map([
        ["signed_bits", unsigned(16)],
        ["scale_numerator", unsigned(1)],
        ["scale_denominator", unsigned(1)],
        ["complex_order", text("imaginary_real")],
      ])],
      ["phase_state", text("raw")],
    ]) : map([
      ["layout", map([
        ["paths", array([map([["kind", text("raw_path_ordinal")], ["ordinal", unsigned(0)]])])],
        ["samples", map([["kind", text("opaque_sample_ordinal")], ["count", unsigned(1)]])],
        ["order", text("path_then_sample")],
      ])],
      ["samples", array([map([["i", unsigned(1)], ["q", unsigned(2)], ["valid", trueValue]])])],
      ["encoding", map([
        ["signed_bits", unsigned(16)],
        ["scale_numerator", unsigned(1)],
        ["scale_denominator", unsigned(1)],
        ["complex_order", text("real_imaginary")],
      ])],
      ["phase_state", text("unavailable")],
    ])],
  ]);
}

function bufferedObservation(recordSeq, captureSequence, receivedNs, bootGeneration, corrected) {
  return map([
    ["segment_id", unsigned(recordSeq)],
    ["classification", classification(bootGeneration === 1 ? "in_order" : "first")],
    ["disposition", disposition(5)],
    ["observation", observation(recordSeq, captureSequence, receivedNs, bootGeneration, "a1", corrected)],
  ]);
}

const empty = timelineState({
  lastRecordSeq: null,
  explicitClockNs: null,
  lastAdvanceNs: null,
  closedWindowFrontier: null,
  openWindows: [],
  finished: false,
});
const advance = timelineState({
  lastRecordSeq: 0,
  explicitClockNs: 1_000_000_000,
  lastAdvanceNs: 1_000_000_000,
  closedWindowFrontier: null,
  openWindows: [openWindow(1, 1_000_000_000, 2_000_000_000)],
  finished: false,
});
const finish = timelineState({
  lastRecordSeq: 1,
  explicitClockNs: 1_500_000_000,
  lastAdvanceNs: 1_000_000_000,
  closedWindowFrontier: 1,
  openWindows: [],
  finished: true,
});
const inactive = timelineState({
  lastRecordSeq: 2,
  explicitClockNs: 5_000_000_000,
  lastAdvanceNs: 5_000_000_000,
  closedWindowFrontier: 3,
  sourceStates: [sourceState(1, 8, 7, 8)],
  streamStates: [
    streamState({ profileByte: "a1", bootGeneration: 1, segmentId: 2, status: "active", lastActivityNs: 5_000_000_000, maximumEventNs: 5_000_000_000, endedAtNs: null, epochTermination: null }),
    streamState({ profileByte: "b2", bootGeneration: 1, segmentId: 0, status: "inactive", lastActivityNs: 0, maximumEventNs: 0, endedAtNs: 5_000_000_000, epochTermination: null }),
  ],
  openWindows: [map([
    ["window_id", unsigned(5)],
    ["start_ns", unsigned(5_000_000_000)],
    ["end_ns", unsigned(6_000_000_000)],
    ["observations", array([bufferedObservation(2, 8, 5_000_000_000, 1, false)])],
  ])],
  missingSpans: [missingSpan("link-a", "b2", 0, null)],
  finished: false,
});
const epoch = timelineState({
  lastRecordSeq: 3,
  explicitClockNs: 5_100_000_000,
  lastAdvanceNs: 5_000_000_000,
  closedWindowFrontier: 3,
  sourceStates: [sourceState(1, 8, 7, 8), sourceState(2, 40, 40, 40)],
  streamStates: [
    streamState({ profileByte: "a1", bootGeneration: 1, segmentId: 2, status: "terminated", lastActivityNs: 5_000_000_000, maximumEventNs: 5_000_000_000, endedAtNs: 5_100_000_000, epochTermination: map([["record_seq", unsigned(3)], ["received_ns", unsigned(5_100_000_000)], ["new_device_epoch", deviceEpoch(1, 2)]]) }),
    streamState({ profileByte: "a1", bootGeneration: 2, segmentId: 3, status: "active", lastActivityNs: 5_100_000_000, maximumEventNs: 5_050_000_000, endedAtNs: null, epochTermination: null }),
    streamState({ profileByte: "b2", bootGeneration: 1, segmentId: 0, status: "terminated", lastActivityNs: 0, maximumEventNs: 0, endedAtNs: 5_000_000_000, epochTermination: null }),
  ],
  openWindows: [map([
    ["window_id", unsigned(5)],
    ["start_ns", unsigned(5_000_000_000)],
    ["end_ns", unsigned(6_000_000_000)],
    ["observations", array([
      bufferedObservation(2, 8, 5_000_000_000, 1, false),
      bufferedObservation(3, 40, 5_100_000_000, 2, true),
    ])],
  ])],
  missingSpans: [missingSpan("link-a", "b2", 0, 5_100_000_000)],
  finished: false,
});
const atomicFinish = timelineState({
  lastRecordSeq: 4,
  explicitClockNs: 5_200_000_000,
  lastAdvanceNs: 5_000_000_000,
  closedWindowFrontier: 5,
  sourceStates: [sourceState(2, 40, 40, 40)],
  openWindows: [],
  finished: true,
});
const prunedAdvance = timelineState({
  lastRecordSeq: 4,
  explicitClockNs: 10_100_000_000,
  lastAdvanceNs: 10_100_000_000,
  closedWindowFrontier: 9,
  sourceStates: [sourceState(2, 40, 40, 40)],
  streamStates: [
    streamState({ profileByte: "a1", bootGeneration: 2, segmentId: 3, status: "inactive", lastActivityNs: 5_100_000_000, maximumEventNs: 5_050_000_000, endedAtNs: 10_100_000_000, epochTermination: null }),
  ],
  openWindows: [],
  missingSpans: [map([
    ["stream", streamIdentity("link-a", "a1", 2)],
    ["segment_id", unsigned(3)],
    ["start_ns", unsigned(10_100_000_000)],
    ["end_ns", nullValue],
    ["reason", text("inactive")],
  ])],
  finished: false,
});

const actual = {
  empty_cbor_hex: empty.toString("hex"),
  advance_cbor_hex: advance.toString("hex"),
  finish_cbor_hex: finish.toString("hex"),
  inactive_cbor_hex: inactive.toString("hex"),
  epoch_cbor_hex: epoch.toString("hex"),
  atomic_finish_cbor_hex: atomicFinish.toString("hex"),
  pruned_advance_cbor_hex: prunedAdvance.toString("hex"),
};

let matches = true;
for (const [name, value] of Object.entries(actual)) {
  console.log(`${name}=${value}`);
  if (vector[name] !== value) {
    matches = false;
  }
}
if (!matches) {
  throw new Error("timeline state vector literals do not match independent encoding");
}
