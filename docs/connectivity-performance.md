# Connectivity and performance

OmaBridge carries bounded TCP streams over authenticated QUIC. Configuring a relay
does not prove relay-only operation: the transport may upgrade to a direct path.
Measure path selection, listener readiness and application requests separately.

## Automatic connection recovery

A forward retains its loopback listener and re-resolves the authorized peer route
for new streams. Publication can follow the official T3 runtime port without
recreating grants. Missing or invalid runtime metadata fails closed rather than
using a stale port. Already accepted streams are not migrated or replayed.

## Negotiated compression

T3 compression is optional and disabled by default. Both peers must explicitly
negotiate `deflate-block-v1`; other services remain byte-transparent. Encoded and
decoded sizes are bounded, malformed blocks fail closed, and legacy peers can
use the original uncompressed protocol.

Compression is not application-aware. Attacker-controlled text and secrets in
the same block can expose a length side channel; do not enable it where that risk
is unacceptable. Already compressed or encrypted payloads may not benefit. See
[configuration and bounds](host-domains.md#performance-and-compression).

## Reproducible measurement

Use `tests/wan_perf.py`, `tests/wan_perf_client.py` and `tools/probe_gateway.py`
only with explicitly selected fixture hosts. Inspect their environment variables
and authorization before execution. Keep private host configuration outside Git.
Measure first request, persistent connections, new streams and payload transfer
separately. Verify payload checksums, document sample count/percentile method and
compare the same source, path and payload before/after a change.

An isolated HTTP fixture does not establish T3 model latency or mobile network
performance. An emulator, VPS or tethered Linux host does not establish physical
Android behavior. Preserve actual reconnect intervals in any acceptance recording.
Deployment observations and benchmark receipts belong in private operator records.
