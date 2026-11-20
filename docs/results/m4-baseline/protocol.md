# Single-flow M4 baseline protocol

Measure the GCC Release bulk application from the accepted M3 tree. Keep the
payload, application, congestion algorithm, endpoint placement, IPv4 link MTU,
Ethernet offloads and no-load path fixed. Compare stack-to-Linux against
DUT-Linux-to-peer-Linux and Linux-to-stack against peer-Linux-to-DUT-Linux.
The stack traverses the DUT's persistent TUN. The kernel control terminates
directly in the DUT kernel in that namespace.

The production payload is 1,000,000,000 bytes with pattern seed 1, 256 KiB
application buffers, and CUBIC. Use one full-size pilot per arm before
production. Production has five matched repeats in each direction. Reverse
both direction order and control/comparison order on even repeats. Require
the predeclared count and an independent SHA-256 match at both endpoints.
Keep every arm and mark the campaign incomplete if an arm fails.

Place DUT work on CPU 8 and peer work on CPU 10. The two placements use
separate physical cores. Keep CPUs 9 and 11 free of benchmark endpoint
processes. Record effective affinity, host load, per-CPU and softirq
statistics, endpoint cgroup snapshots, route, link, queue and offload readback.
Run each arm serially with no shaping, traffic generation or live packet
capture. Setup and analysis use CPUs 28–31 at nice 10. Use the same topology
and frozen kernel bulk binary for later candidate modes.

Use the receiver application's established-connection-to-EOF interval for
decimal Gbit/s. Collect the direct application child's user and system CPU
with wait4. This scope includes startup, payload generation or verification,
backend execution and close processing charged to the process. Divide each
process's CPU seconds by receiver-confirmed decimal GB. Container cgroup CPU
and host softirq have broader observation scopes and stay separate from the
application-process comparison.

Try ordinary process-scoped perf and retain the response. Test ordering, byte
and hash rejection, role/backend/status checks, and a real child's CPU
measurement. Run the Release suite and archive commands, image, hashes, raw
and compact receipts in the private data volume.
