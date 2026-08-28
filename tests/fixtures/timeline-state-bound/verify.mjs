import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const fixture = new Map(
  readFileSync(new URL("vector-v1.txt", import.meta.url), "utf8")
    .trim()
    .split("\n")
    .map((line) => line.split("=", 2)),
);

const textValue = (name) => {
  const value = fixture.get(name);
  assert.notEqual(value, undefined, `missing fixture field ${name}`);
  return value;
};
const integer = (name) => BigInt(textValue(name));
const count = (name) => Number(integer(name));

const SCHEMA = Object.freeze({
  root: [
    "schema_version", "window_contract_id", "session_id", "last_record_seq",
    "explicit_clock_ns", "last_advance_ns", "source_states", "stream_states",
    "closed_window_frontier", "open_windows", "missing_spans", "finished",
  ],
  device_epoch: ["device", "boot_generation"],
  epoch_termination: ["record_seq", "received_ns", "new_device_epoch"],
  stream_identity: ["sensor", "link", "profile", "device_epoch"],
  seen_range: ["first", "last"],
  source_state: ["device_epoch", "maximum_sequence", "seen_ranges"],
  stream_state: [
    "stream", "segment_id", "status", "last_activity_ns", "maximum_event_ns",
    "ended_at_ns", "end_reason", "epoch_termination",
  ],
  open_window: ["window_id", "start_ns", "end_ns", "observations"],
  missing_span: ["stream", "segment_id", "start_ns", "end_ns", "reason"],
  buffered_observation: ["segment_id", "classification", "disposition", "observation"],
  classification: ["kind", "value"],
  disposition: ["kind", "window_id", "reason"],
  csi_observation: [
    "input", "sensor", "hardware", "link", "device_epoch", "capture_sequence",
    "callback_tick_us", "timing", "radio", "profile", "csi",
  ],
  input_receipt: ["session", "record_seq", "decoder_version"],
  device_timestamp: ["ticks", "clock_domain"],
  frame_timing: [
    "received_ns", "device", "event_ns", "source", "mapping_version", "uncertainty_ns",
  ],
  radio_metadata: [
    "channel", "centre_frequency_hz", "bandwidth_hz", "ppdu", "rssi_dbm", "noise_floor_dbm",
  ],
  csi_capture: ["layout", "samples", "encoding", "phase_state"],
  csi_layout: ["paths", "samples", "order"],
  sample_encoding: [
    "signed_bits", "scale_numerator", "scale_denominator", "complex_order",
  ],
  iq_sample: ["i", "q", "valid"],
  csi_path_tx_rx: ["kind", "tx_stream", "rx_chain"],
  csi_path_raw: ["kind", "ordinal"],
  sample_axis: ["kind", "count"],
  sample_axis_values: ["kind", "values"],
});

const U64_MAX = (1n << 64n) - 1n;
const U32_MAX = (1n << 32n) - 1n;
const U16_MAX = (1n << 16n) - 1n;
const U8_MAX = (1n << 8n) - 1n;

function headerSize(value) {
  assert(value >= 0n && value <= U64_MAX, `CBOR argument out of range: ${value}`);
  if (value <= 23n) return 1n;
  if (value <= U8_MAX) return 2n;
  if (value <= U16_MAX) return 3n;
  if (value <= U32_MAX) return 5n;
  return 9n;
}

const unsignedSize = headerSize;
const textSize = (value) => {
  const bytes = BigInt(Buffer.byteLength(value, "utf8"));
  return headerSize(bytes) + bytes;
};
const boundedTextSize = (bytes) => headerSize(bytes) + bytes;
const byteStringSize = (bytes) => headerSize(bytes) + bytes;
const arraySize = (length, elementSize) => headerSize(length) + length * elementSize;

function mapSize(keys, values) {
  assert.equal(keys.length, values.length, "schema key/value count mismatch");
  return headerSize(BigInt(keys.length)) + keys.reduce(
    (total, key, index) => total + textSize(key) + values[index],
    0n,
  );
}

const maximumPathSizes = Object.freeze({
  tx_rx: mapSize(SCHEMA.csi_path_tx_rx, [textSize("tx_rx"), unsignedSize(U16_MAX), unsignedSize(U16_MAX)]),
  raw_path_ordinal: mapSize(SCHEMA.csi_path_raw, [textSize("raw_path_ordinal"), unsignedSize(U16_MAX)]),
});

function axisSize(variant, axisLength) {
  if (variant === "opaque_sample_ordinal") {
    return mapSize(SCHEMA.sample_axis, [textSize(variant), unsignedSize(axisLength)]);
  }
  const elementSize = variant === "ieee_tone_index" ? 3n : unsignedSize(U64_MAX);
  return mapSize(SCHEMA.sample_axis_values, [
    textSize(variant),
    arraySize(axisLength, elementSize),
  ]);
}

function layoutSize(paths, axisLength, pathVariant, axisVariant) {
  return mapSize(SCHEMA.csi_layout, [
    arraySize(paths, maximumPathSizes[pathVariant]),
    axisSize(axisVariant, axisLength),
    textSize("path_then_sample"),
  ]);
}

function bruteMaximumLayout(coordinateCap) {
  let maximum = { size: 0n };
  for (let paths = 1n; paths <= coordinateCap; paths += 1n) {
    for (let axisLength = 1n; paths * axisLength <= coordinateCap; axisLength += 1n) {
      for (const pathVariant of Object.keys(maximumPathSizes)) {
        for (const axisVariant of ["opaque_sample_ordinal", "ieee_tone_index", "frequency_hz"]) {
          const size = layoutSize(paths, axisLength, pathVariant, axisVariant);
          if (size > maximum.size) {
            maximum = { size, paths, axisLength, pathVariant, axisVariant };
          }
        }
      }
    }
  }
  return maximum;
}

function maximizeNestedArrayHeaders(arrayCount, totalElements) {
  let previous = Array(totalElements + 1).fill(Number.NEGATIVE_INFINITY);
  previous[0] = 0;
  for (let arrays = 0; arrays < arrayCount; arrays += 1) {
    const next = Array(totalElements + 1).fill(Number.NEGATIVE_INFINITY);
    for (let assigned = 0; assigned <= totalElements; assigned += 1) {
      if (!Number.isFinite(previous[assigned])) continue;
      for (let length = 0; assigned + length <= totalElements; length += 1) {
        const candidate = previous[assigned] + Number(headerSize(BigInt(length)));
        next[assigned + length] = Math.max(next[assigned + length], candidate);
      }
    }
    previous = next;
  }
  return BigInt(previous[totalElements]);
}

const routes = Array.from({ length: count("route_count") }, (_, index) => {
  const datagramBody = (
    integer(`route_${index}_maximum_datagram_bytes`) < integer(`route_${index}_pin_datagram_bytes`)
      ? integer(`route_${index}_maximum_datagram_bytes`)
      : integer(`route_${index}_pin_datagram_bytes`)
  ) - integer("native_header_bytes") - integer("authentication_tag_bytes");
  const plaintext = [
    integer(`route_${index}_maximum_plaintext_bytes`),
    integer(`route_${index}_pin_plaintext_bytes`),
    datagramBody,
  ].reduce((left, right) => left < right ? left : right);
  const rawFromPlaintext = plaintext - integer("csi_fixed_body_bytes") - integer("ltf_block_bytes");
  const rawBytes = rawFromPlaintext < integer(`route_${index}_maximum_raw_csi_bytes`)
    ? rawFromPlaintext
    : integer(`route_${index}_maximum_raw_csi_bytes`);
  assert(rawBytes >= 2n, `route ${index} cannot carry one logical CSI sample`);
  return {
    sensor: textValue(`route_${index}_sensor`),
    link: textValue(`route_${index}_link`),
    peakRate: integer(`route_${index}_peak_packets_per_second`),
    logicalSamples: rawBytes / 2n,
  };
});

for (const route of routes) {
  assert.equal(route.logicalSamples, integer("expected_logical_samples_per_route"));
}

const layoutMaximum = bruteMaximumLayout(
  routes.reduce((maximum, route) => maximum > route.logicalSamples ? maximum : route.logicalSamples, 0n),
);
assert.deepEqual(layoutMaximum, {
  size: integer("expected_layout_maximum"),
  paths: integer("expected_layout_paths"),
  axisLength: integer("expected_layout_axis_values"),
  pathVariant: textValue("expected_layout_path_variant"),
  axisVariant: textValue("expected_layout_axis_variant"),
});

const duration = integer("inactive_after_ns") + 3n * integer("allowed_lateness_ns") + integer("width_ns");
const rateQuanta = (duration + 999_999_999n) / 1_000_000_000n + 1n;
const bufferedObservations = routes.reduce((total, route) => total + route.peakRate * rateQuanta, 0n);
for (const route of routes) {
  route.observationCapacity = route.peakRate * rateQuanta;
}
const routeCount = BigInt(routes.length);
const openWindows = (duration + integer("step_ns") - 1n) / integer("step_ns") + 2n;
const retainedEntries = bufferedObservations + routeCount;
const seenValues = (integer("reorder_horizon") + 1n) < (bufferedObservations + 1n)
  ? integer("reorder_horizon") + 1n
  : bufferedObservations + 1n;
const seenRanges = (bufferedObservations + 1n) < ((integer("reorder_horizon") + 2n) / 2n)
  ? bufferedObservations + 1n
  : (integer("reorder_horizon") + 2n) / 2n;

const deviceEpoch = mapSize(SCHEMA.device_epoch, [unsignedSize(U64_MAX), unsignedSize(U32_MAX)]);
const epochTermination = mapSize(SCHEMA.epoch_termination, [
  unsignedSize(U64_MAX), unsignedSize(U64_MAX), deviceEpoch,
]);
const seenRange = mapSize(SCHEMA.seen_range, [unsignedSize(U64_MAX), unsignedSize(U64_MAX)]);
const sourceState = mapSize(SCHEMA.source_state, [
  deviceEpoch,
  unsignedSize(U64_MAX),
  arraySize(seenRanges, seenRange),
]);

const routeStateShapes = routes.map((route) => {
  const streamIdentity = mapSize(SCHEMA.stream_identity, [
    textSize(route.sensor), textSize(route.link), byteStringSize(32n), deviceEpoch,
  ]);
  return {
    route,
    terminatedEpochStream: mapSize(SCHEMA.stream_state, [
      streamIdentity,
      unsignedSize(U64_MAX),
      textSize("terminated"),
      unsignedSize(U64_MAX),
      unsignedSize(U64_MAX),
      unsignedSize(U64_MAX),
      textSize("epoch"),
      epochTermination,
    ]),
    missingSpan: mapSize(SCHEMA.missing_span, [
      streamIdentity,
      unsignedSize(U64_MAX),
      unsignedSize(U64_MAX),
      unsignedSize(U64_MAX),
      textSize("inactive"),
    ]),
  };
});
const streamState = headerSize(retainedEntries) + routeStateShapes.reduce(
  (total, shape) => total + (shape.route.observationCapacity + 1n) * shape.terminatedEpochStream,
  0n,
);
const missingSpanState = headerSize(retainedEntries) + routeStateShapes.reduce(
  (total, shape) => total + (shape.route.observationCapacity + 1n) * shape.missingSpan,
  0n,
);

const gapClassification = mapSize(SCHEMA.classification, [
  textSize("gap"), unsignedSize(U64_MAX),
]);
const reorderedClassification = mapSize(SCHEMA.classification, [
  textSize("reordered"), unsignedSize(integer("reorder_horizon")),
]);
assert.equal(gapClassification, integer("expected_gap_classification_bytes"));
assert.equal(reorderedClassification, integer("expected_reordered_classification_bytes"));

const windowedDisposition = mapSize(SCHEMA.disposition, [
  textSize("windowed"), unsignedSize(U64_MAX), 1n,
]);
const inputReceipt = mapSize(SCHEMA.input_receipt, [
  textSize(textValue("session_id")),
  unsignedSize(U64_MAX),
  textSize(textValue("decoder_version")),
]);
const deviceTimestamp = mapSize(SCHEMA.device_timestamp, [
  unsignedSize(U64_MAX), boundedTextSize(integer("maximum_clock_text_bytes")),
]);
const frameTiming = mapSize(SCHEMA.frame_timing, [
  unsignedSize(U64_MAX),
  deviceTimestamp,
  unsignedSize(U64_MAX),
  textSize("clock_corrected"),
  boundedTextSize(integer("maximum_clock_text_bytes")),
  unsignedSize(U64_MAX),
]);
const radioMetadata = mapSize(SCHEMA.radio_metadata, [
  unsignedSize(U16_MAX),
  unsignedSize(U64_MAX),
  unsignedSize(U64_MAX),
  textSize("legacy"),
  2n,
  2n,
]);
const sampleEncoding = mapSize(SCHEMA.sample_encoding, [
  unsignedSize(U8_MAX),
  unsignedSize(U32_MAX),
  unsignedSize(U32_MAX),
  textSize("real_imaginary"),
]);
const iqSample = mapSize(SCHEMA.iq_sample, [5n, 5n, 1n]);
const routeBufferedObservations = routes.map((route) => {
  const layout = bruteMaximumLayout(route.logicalSamples).size;
  const capture = mapSize(SCHEMA.csi_capture, [
    layout,
    arraySize(route.logicalSamples, iqSample),
    sampleEncoding,
    textSize("unavailable"),
  ]);
  const observation = mapSize(SCHEMA.csi_observation, [
    inputReceipt,
    textSize(route.sensor),
    textSize("esp32-s3"),
    textSize(route.link),
    deviceEpoch,
    unsignedSize(U64_MAX),
    unsignedSize(U64_MAX),
    frameTiming,
    radioMetadata,
    byteStringSize(32n),
    capture,
  ]);
  return {
    route,
    size: mapSize(SCHEMA.buffered_observation, [
      unsignedSize(U64_MAX), gapClassification, windowedDisposition, observation,
    ]),
  };
});

const nestedArrayHeaders = maximizeNestedArrayHeaders(Number(openWindows), Number(bufferedObservations));
assert.equal(nestedArrayHeaders, integer("expected_observation_array_header_sum"));
const openWindowWithoutObservationHeader = mapSize(SCHEMA.open_window, [
  unsignedSize(U64_MAX), unsignedSize(U64_MAX), unsignedSize(U64_MAX), 0n,
]);
const openWindowState = headerSize(openWindows)
  + openWindows * openWindowWithoutObservationHeader
  + nestedArrayHeaders
  + routeBufferedObservations.reduce(
    (total, receipt) => total + receipt.route.observationCapacity * receipt.size,
    0n,
  );

const canonicalMaximum = mapSize(SCHEMA.root, [
  unsignedSize(integer("schema_version")),
  byteStringSize(32n),
  textSize(textValue("session_id")),
  unsignedSize(U64_MAX),
  unsignedSize(U64_MAX),
  unsignedSize(U64_MAX),
  arraySize(retainedEntries, sourceState),
  streamState,
  unsignedSize(U64_MAX),
  openWindowState,
  missingSpanState,
  1n,
]);
assert.equal(canonicalMaximum, integer("expected_canonical_maximum"));

console.log(`logical samples per route = ${routes.map((route) => route.logicalSamples).join(", ")}`);
console.log(`layout maximum = ${layoutMaximum.size}`);
console.log(`max layout = ${layoutMaximum.paths} ${layoutMaximum.pathVariant} paths x ${layoutMaximum.axisLength} ${layoutMaximum.axisVariant} axis`);
console.log(`Gap classification size = ${gapClassification}`);
console.log(`Reordered classification size at horizon ${integer("reorder_horizon")} = ${reorderedClassification}`);
console.log(`nested array header sum = ${nestedArrayHeaders}`);
console.log(`final canonical maximum = ${canonicalMaximum}`);
