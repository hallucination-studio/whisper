import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const fixtureUrl = new URL("./vector-v1.txt", import.meta.url);
const fields = new Map(
  (await readFile(fixtureUrl, "utf8"))
    .trimEnd()
    .split("\n")
    .map((line) => {
      const separator = line.indexOf("=");
      assert.notEqual(separator, -1, `invalid fixture line: ${line}`);
      return [line.slice(0, separator), line.slice(separator + 1)];
    }),
);

assert.deepEqual([...fields.keys()], [
  "deployment_id",
  "device_id",
  "key_epoch",
  "epoch_key_hex",
  "preimage_hex",
  "identity_sha256",
  "included_epoch_key_hex",
  "included_identity_sha256",
  "replay_window_packets",
  "mutated_replay_window_packets",
  "peer",
  "mutated_peer",
  "link_id",
  "mutated_link_id",
  "peak_packets_per_second",
  "mutated_peak_packets_per_second",
  "maximum_authenticated_bytes_per_second",
  "mutated_maximum_authenticated_bytes_per_second",
  "maximum_valid_datagram_bytes",
  "mutated_maximum_valid_datagram_bytes",
]);

const vector = {
  deploymentId: fields.get("deployment_id"),
  deviceId: BigInt(fields.get("device_id")),
  keyEpoch: Number(fields.get("key_epoch")),
  epochKey: Buffer.from(fields.get("epoch_key_hex"), "hex"),
  replayWindowPackets: Number(fields.get("replay_window_packets")),
  peer: fields.get("peer"),
  linkId: fields.get("link_id"),
  peakPacketsPerSecond: Number(fields.get("peak_packets_per_second")),
  maximumAuthenticatedBytesPerSecond: BigInt(
    fields.get("maximum_authenticated_bytes_per_second"),
  ),
  maximumValidDatagramBytes: Number(fields.get("maximum_valid_datagram_bytes")),
};

function deriveIdentity({ deploymentId, deviceId, keyEpoch, epochKey }) {
  const deployment = Buffer.from(deploymentId, "utf8");
  assert.ok(deployment.length <= 0xffff_ffff, "deployment ID exceeds u32");
  assert.ok(deviceId >= 0n && deviceId <= 0xffff_ffff_ffff_ffffn, "device ID exceeds u64");
  assert.ok(keyEpoch >= 1 && keyEpoch <= 0xffff, "key epoch is not nonzero u16");
  assert.equal(epochKey.length, 32, "epoch key is not 32 bytes");

  const deploymentLength = Buffer.alloc(4);
  deploymentLength.writeUInt32BE(deployment.length);
  const deviceBytes = Buffer.alloc(8);
  deviceBytes.writeBigUInt64BE(deviceId);
  const keyEpochBytes = Buffer.alloc(2);
  keyEpochBytes.writeUInt16BE(keyEpoch);
  const preimage = Buffer.concat([
    Buffer.from("whisper.replay-window.identity", "ascii"),
    Buffer.from([0x00, 0x01, 0x01]),
    deploymentLength,
    deployment,
    deviceBytes,
    keyEpochBytes,
    epochKey,
  ]);
  return { preimage, digest: createHash("sha256").update(preimage).digest("hex") };
}

const canonical = deriveIdentity(vector);
assert.equal(canonical.preimage.toString("hex"), fields.get("preimage_hex"));
assert.equal(canonical.digest, fields.get("identity_sha256"));

const includedMutation = deriveIdentity({
  ...vector,
  epochKey: Buffer.from(fields.get("included_epoch_key_hex"), "hex"),
});
assert.notEqual(includedMutation.digest, canonical.digest);
assert.equal(includedMutation.digest, fields.get("included_identity_sha256"));

const excludedMutations = [
  ["replayWindowPackets", Number(fields.get("mutated_replay_window_packets"))],
  ["peer", fields.get("mutated_peer")],
  ["linkId", fields.get("mutated_link_id")],
  ["peakPacketsPerSecond", Number(fields.get("mutated_peak_packets_per_second"))],
  [
    "maximumAuthenticatedBytesPerSecond",
    BigInt(fields.get("mutated_maximum_authenticated_bytes_per_second")),
  ],
  ["maximumValidDatagramBytes", Number(fields.get("mutated_maximum_valid_datagram_bytes"))],
];
for (const [name, value] of excludedMutations) {
  assert.equal(deriveIdentity({ ...vector, [name]: value }).digest, canonical.digest, name);
}

console.log(`verified replay-window identity v1: ${canonical.digest}`);
