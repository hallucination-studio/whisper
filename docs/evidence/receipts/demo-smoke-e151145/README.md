# Physical ESP32-S3 to unchanged Chrome demo-smoke

This receipt retains the bounded Issue #126 execution at Host revision
`e15114515fcb97142dd1e62cd65ccf7c69b8025f`. Its classification is only `demo-smoke`.

The clean generated firmware set was written with esptool write-time
verification, and the immutable application image was independently verified.
The fixed provisioning command completed successfully. A fresh Store and one
Host capture session then admitted real-board native frames.

Installed Chrome 151.0.7922.174 was launched through Playwright 1.62.1
with `channel: "chrome"`. The page was loaded once with zero signal rows at
Projection watermark `4`, left unchanged, and visibly
updated to `LIVE` with a signal row at watermark `13`.
The retained screenshot shows that updated page.

The final topology and signals reads share the receipt Store and Capture
Session at Projection watermark `37`. The greatest
visible CSI record is `23`; the same frozen Store contains
`37` packet records and `12`
CSI observations for that Capture Session. Controlled Host shutdown reported
`queue_drop_count=0`.

## Procedure

1. Build the production Host and firmware through the
   [production-image procedure](../../../operations/firmware.md#build-the-production-image).
2. Write the generated flash set and independently verify the immutable
   application through
   [Flash and verify the application](../../../operations/firmware.md#flash-and-verify-the-application).
3. Provision the board through
   [Fixed development Wi-Fi provisioning](../../../operations/firmware.md#fixed-development-wi-fi-provisioning).
4. Initialize a fresh Store, start one Host capture session, and follow the
   [read-only browser behavior](../../../specs/demo-slice-v2.md#read-only-browser-behavior):
   load installed Chrome once, leave the page unchanged, then stimulate a
   fresh physical CSI packet.
5. Read the final topology and signals snapshots, stop the Host under control,
   and close the
   [sanitized demo-smoke receipt](../../../specs/demo-slice-v2.md#sanitized-demo-smoke-receipt).

## Artifacts

- [Exact DemoSmokeReceipt](DemoSmokeReceipt.json)
- [Updated Chrome page](chrome.png)
- [Final topology body](topology.json)
- [Final signals body](signals.json)

These artifacts contain no key, credential, SSID, private address, MAC,
serial port, command line, or raw packet. They do not establish Timeline,
World, restart, corpus, scenario, `live-physical-e2e`, formal evidence, or
multi-sensor acceptance.
