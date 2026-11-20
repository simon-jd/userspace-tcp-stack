# M4 TUN checksum and TCPv4 offload results

The bulk client and server transferred one CUBIC flow at a time across a
same-host Docker bridge. The DUT was pinned to CPU 8 and the Linux peer
to CPU 10. All timed arms used an Ethernet MTU of 1,500 B, the same
veth feature policy (TSO and GSO on, GRO off), and the same application
options and supplied payload. Both endpoints verified 1,000,000,000 B
and their SHA-256 matched the independent byte oracle
(`57c114707df855575bf7f97161237ef9ece1c41ebd58c104b1a344115d707969`).
Each timed comparison has 30 valid arms, with five repeats in each
direction for three modes and zero excluded arms. The [legacy bulk
baseline](../m4-baseline/README.md) used a different Ethernet feature policy.

The Linux peer always used a kernel socket. In Linux control arms both
endpoints used kernel sockets on the bridge and bypassed TUN. The legacy
userspace arm used raw IP TUN frames (`0x1801`). The checksum and TCPv4
arms used one FD with `IFF_VNET_HDR` (`0x5801`) and a 10-byte virtio
header. The active TUN advertised generic TX checksum in both modes.
TUN TX TCP segmentation read back off in checksum mode and on in
TCPv4 mode. The timed traffic shows TCPv4 aggregates crossing TUN,
including on RX with Ethernet GRO off. Linux can also forward an
existing GSO frame intact, and the aggregate counters alone cannot
identify the origin of the original RX aggregation.

## One-GB comparisons

Each row reports five runs as median [minimum, maximum]. The receiver
reports application payload goodput over its transfer window. DUT
process CPU is full-lifetime `wait4` user plus system CPU seconds per
decimal GB, calculated per arm before aggregation. The component
medians need not sum to the total median. TUN counters are syscall
attempts per GB, including retries. Cgroup and host snapshots cover
different work or windows, including kernel activity outside the
endpoint process. The archives retain all seven arms with
snapshot-detected CPU interference (four in the checksum comparison
and three in the TCPv4 comparison). The ordinary `perf stat` probe
exited 1 with `perf_event_paranoid=4`, leaving PMU metrics and
hotspot attribution unavailable.

### Legacy, checksum and Linux

| Data direction | DUT mode | Receiver Gbit/s | DUT process CPU s/GB | TUN read attempts/GB | TUN write attempts/GB |
|---|---|---:|---:|---:|---:|
| DUT to peer | legacy | 3.844730 [3.795204, 4.044186] | 2.081810 [1.980628, 2.111770] | 215,975 [191,855, 262,647] | 693,092 [692,212, 694,278] |
| DUT to peer | checksum | 3.819570 [3.656728, 3.950047] | 2.083299 [2.016051, 2.176201] | 227,216 [187,348, 255,229] | 692,484 [691,256, 694,210] |
| DUT to peer | kernel | 13.912233 [11.377170, 14.338395] | 0.565808 [0.549853, 0.704576] | — | — |
| Peer to DUT | legacy | 3.734832 [3.216178, 4.758035] | 2.145412 [1.684731, 2.491759] | 690,621 [690,618, 690,782] | 345,638 [345,381, 346,349] |
| Peer to DUT | checksum | 4.767136 [3.257947, 4.840425] | 1.681749 [1.656399, 2.459943] | 690,705 [690,621, 690,891] | 345,998 [345,384, 346,202] |
| Peer to DUT | kernel | 14.096981 [13.442059, 14.451450] | 0.440195 [0.435580, 0.483725] | — | — |

### Checksum, TCPv4 and Linux

| Data direction | DUT mode | Receiver Gbit/s | DUT process CPU s/GB | TUN read attempts/GB | TUN write attempts/GB |
|---|---|---:|---:|---:|---:|
| DUT to peer | checksum | 3.793475 [3.648356, 4.020459] | 2.098698 [1.978493, 2.180822] | 265,161 [191,609, 269,259] | 691,001 [690,748, 693,970] |
| DUT to peer | tcpv4 | 11.332250 [11.015706, 11.460682] | 0.693101 [0.686844, 0.713248] | 18,151 [15,265, 19,008] | 22,889 [22,855, 22,907] |
| DUT to peer | kernel | 14.062712 [13.249755, 14.257840] | 0.567298 [0.561793, 0.604249] | — | — |
| Peer to DUT | checksum | 4.828159 [4.588214, 4.984220] | 1.660528 [1.608766, 1.747395] | 690,624 [690,619, 690,882] | 345,382 [345,316, 345,908] |
| Peer to DUT | tcpv4 | 14.226223 [13.608965, 14.522408] | 0.536779 [0.521614, 0.586024] | 23,055 [20,891, 23,340] | 19,018 [4,634, 19,038] |
| Peer to DUT | kernel | 14.209680 [14.058806, 14.349310] | 0.433161 [0.428855, 0.451804] | — | — |

Checksum-only sent at a median 3.819570 Gbit/s versus 3.844730 in
legacy and received at 4.767136 Gbit/s versus 3.734832 in legacy.
All four mode/direction contrasts in goodput and total process CPU
had overlapping per-arm ranges. TCPv4 versus checksum increased
median goodput from 3.793475 to 11.332250 Gbit/s on transmit and
from 4.828159 to 14.226223 Gbit/s on receive. Median DUT process
CPU fell from 2.098698 to 0.693101 s/GB and from 1.660528 to
0.536779 s/GB, respectively. Both TCPv4 directions still used more
DUT process CPU than their Linux controls. The TCPv4 receive
goodput range overlapped the Linux control range.

Across the five TCPv4 transmit arms, 76,409 GSO writes represented
3,433,276 logical TCP segments (44.93 per aggregate). Across the five
receive arms, 93,032 incoming aggregates represented 3,467,867 logical
segments (37.28 per aggregate). Checksum-only and legacy had zero
aggregate datagrams and logical segments. [Machine-readable replay
output](summary.json) includes the six-arm functional run, user and
system CPU, checksum metadata totals, retry counts and interference flags.

## Sealed evidence and replay

All three campaigns are under `utcp-data:/m4/performance/` on the
Ubuntu test host. Each contains `plan.json` with original argv,
`bin/`, the frozen runner scripts, state snapshots, per-arm endpoint
outputs and readbacks, and a `SHA256SUMS` manifest.

| Directory | Arms | Files verified | SHA-256 of `SHA256SUMS` |
|---|---:|---:|---|
| `tun-vnet-tcpv4-smoke-1` | 6 | 132 | `109ac5513761df51cd5825006514d637c4fa240c83869a3cfe66970bc3e533fa` |
| `tun-checksum-1gb-r5-01` | 30 | 587 | `a8f7b573a45cea06778abd171db8f26fbd7ec4f2a0f3961d47cb4223ff576f63` |
| `tun-tcpv4-1gb-r5-01` | 30 | 596 | `3eb45928249f48915d3755b58e7368bef923a7d72177a185755d6c7ac46c6982` |

From the repository root, replay from the read-only volume and compare
to the tracked summary. The script also accepts a local copy of the
three campaign directories as its positional argument and requires
Python 3.11+ and GNU `sha256sum`.

```sh
result=docs/results/m4-tun-vnet
docker run --rm --network none --cpuset-cpus 16-23 \
  -v utcp-data:/data:ro -v "$PWD/$result:/audit:ro" utcp-testbed:dev \
  nice -n 10 python3 /audit/audit.py /data/m4/performance \
  | diff -u "$result/summary.json" -
```

The frozen runner source is `aa21d9354a3829d487188a5097cde29368ee6a0d`.
All userspace archive mode executables have SHA-256
`38607feb53cb4dea4e668f16b773a7c632822a5f0adb1e5a5dea958ea1c7ca7f`
and were built from `1c6911eeb1c432ae997b00f1fe2206c430d58c3e` using
g++-15 15.2.0 Release. The VNET task head
`622177421772e0e73e6009c177ac5331fbb2e83a` adds default checks and design
notes over that runtime. The Linux binary came from
`da05184dd3d6766987b236b29db8caa031e7d367` and has SHA-256
`52b94b903903f80581311ac4070e107f3c5fd2eb0f962d4a155f564ae090d128`.
The historical userspace binary embeds paths rooted at
`/home/postedism/Desktop/utcp-wt/m4-tun-vnet`. In a detached checkout of
the measured runtime, the independent rebuild used the following
prefix map and matched the archived SHA-256 byte for byte.

```sh
producer_source=/home/postedism/Desktop/utcp-wt/m4-tun-vnet
taskset -c 16-23 nice -n 10 cmake --preset gcc-release \
  "-DCMAKE_CXX_FLAGS=-ffile-prefix-map=$PWD=$producer_source"
taskset -c 16-23 nice -n 10 cmake --build --preset gcc-release -j8 --target utcp-bulk
sha256sum build/gcc-release/apps/utcp-bulk/utcp-bulk
```

## Functional runs and wire capture

The archived smoke verified six transfers of 4,000,055 B on E-cores.
The separate wire check verified 2,768 completed IPv4 and TCP
checksums, 2,768 distinct payload segments and the same 4,000,055 B
payload digest. Its transmit device counted 310 GSO datagrams and
838 logical segments within those aggregates. The wire check forced
segmentation and checksum completion before capture and used a
different Ethernet feature policy from the timing experiments.

The original capture and receipts are in
`~/Desktop/utcp-wt/m4-tun-vnet/.logs/wire-release/` on Ubuntu. Check
them with the [capture manifest](wire-capture.sha256). The smoke and
wire payload SHA-256 is
`77465f5ba9eb55dfa849fb59cdcc431c59922ccd05b289365cc92e5c9e608698`.
An independent direct-veth test also observed RX aggregates with GRO
enabled and segmentation offloads disabled. That setup tests the
receive path under its own feature configuration.

After a GCC Release build of `utcp-bulk`, run the bounded Docker
checks from the repository root in the project test environment. The
wire check requires an unused test subnet and an output directory.

```sh
tests/interop/m4_tun_offload.sh
tests/interop/m4_tun_offload_wire.sh build/m4-tun-wire
```
