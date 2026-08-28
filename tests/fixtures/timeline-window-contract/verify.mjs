import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const vector = Object.fromEntries(
  readFileSync(new URL("vector-v1.txt", import.meta.url), "utf8")
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

function text(value) {
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([head(3, bytes.length), bytes]);
}

function map(entries) {
  return Buffer.concat([
    head(5, entries.length),
    ...entries.flatMap(([key, value]) => [text(key), value]),
  ]);
}

const canonical = map([
  ["schema_version", unsigned(1)],
  ["timeline_version", text("timeline-v1")],
  ["width_ns", unsigned(vector.width_ns)],
  ["step_ns", unsigned(vector.step_ns)],
  ["alignment", text("session_time_zero")],
  ["allowed_lateness_ns", unsigned(vector.allowed_lateness_ns)],
  ["inactive_after_ns", unsigned(vector.inactive_after_ns)],
  ["reorder_horizon", unsigned(vector.reorder_horizon)],
  ["missing_data", text("explicit_spans_no_zero_fill")],
  ["event_time_admission", text("absolute_difference_at_most_allowed_lateness")],
  ["inactivity", text("greater_than_or_equal")],
]);

const canonicalHex = canonical.toString("hex");
const digest = createHash("sha256").update(canonical).digest("hex");

console.log(`canonical_cbor_hex=${canonicalHex}`);
console.log(`sha256=${digest}`);

if (vector.canonical_cbor_hex !== canonicalHex || vector.sha256 !== digest) {
  throw new Error("window contract vector literals do not match independent encoding");
}
