---
status: accepted
---

# Give Host cleanup to an independent supervisor

The bounded delivery path must release its Managed store lease even when a
shutdown future is cancelled, the public runtime handle is dropped, or an
async task panics, while SQLite close and writer join must never block a Tokio
worker. We therefore give one independent `HostSupervisor` thread the final
`CaptureRuntime`, pinned `QueryStore`, task-completion, transport-shutdown, and
lease owners; `HostRuntime` only requests stop and observes completion.

## Considered options

- A detached Tokio lifecycle task kept the public interface small, but runtime
  destruction could cancel its cleanup and its final destructors ran on a
  worker.
- Per-request query connections plus a reader reaper simplified last-owner
  detection, but changed the accepted pinned `QueryStore` seam and introduced a
  broader lifecycle mechanism.
- The selected supervisor retains the pinned query seam, tracks blocking jobs,
  and force-closes accepted TCP connections after a finite grace. It costs one
  lifecycle thread but localizes fatal arbitration, blocking teardown, and
  lease release without adding a database actor, pool, second candidate queue,
  or second fact authority.
