# M4 TCP payload copies

On a normal 65,549-byte Linux TCP transfer, every application byte crossed the send ring into its final packet exactly once. On receive, every byte crossed from the original input packet into the receive ring exactly once. The synchronous socket API made one further copy on each direction between the application and its ring. Read shutdown had an avoidable cost. In the fixed unread-prefix case the change removed 11,852 copied bytes across ten calls.

## Linux transfers with 4 KiB chunks

Each row is a separate local Linux connection, with a userspace endpoint and a stock kernel endpoint in an isolated TUN namespace. All eight endpoint summaries matched the independently generated stream, SHA-256 `1e76f01beaa38c9fe81c1647403b441f35f5695fbfc0bd8bc666bf354753e602`. Entries give payload bytes / completed memcpy calls. Each fresh boundary covered stream offsets [0, 65549) exactly once. A chunk boundary can split one payload range across two calls. [Machine-readable measurements](linux.json)

| Userspace direction | Socket API boundary | Ordinary packet boundary | Aggregate packet boundary | GRO fallback boundary |
| --- | ---: | ---: | ---: | ---: |
| Legacy send | 65,549 / 17 | 65,549 / 61 | 0 | — |
| Legacy receive | 65,549 / 19 | 65,549 / 62 | 0 | 0 |
| TCPv4 VNET send | 65,549 / 17 | 3,285 / 4 | 62,264 / 19 | — |
| TCPv4 VNET receive | 65,549 / 19 | 1,448 / 1 | 44,888 / 16 | 19,213 / 19 |

Five transmit aggregates and six receive aggregates appeared in the VNET device statistics. GSO copied directly from send chunks into a large packet. GRO read the input span directly, including the fallback that breaks an aggregate into logical segments. The 10-byte VNET prefix was written into reserved headroom. The fixture retained the same IP address in memory across prepend and decode and checked the payload after framing.

The GDB probe bracketed both real memcpy call instructions in the GCC Debug ring implementation on x86-64. It read each real source immediately before the call, compared the destination immediately after return and saved the stream offset, length and source digest. For TX it checked the destination and exact offset inside the final PacketBuf. For RX it checked that the source lay inside the original IPv4/TCP payload passed to Stack::receive. Socket API copies were checked against the caller's buffer. The replay independently regenerated the expected bytes for every observed slice. Production builds do not include the probe. Debugger stops perturb packet timing, so the Linux counts describe these four transfers only.

The measurement covers userspace TCP payload memcpy operations at the socket and packet boundaries. Header writes, checksum scans, allocator initialization, optional packet capture, simulator transport, UDP, the TUN syscall and kernel-side segmentation or copying are outside that count. The earlier echo staging measurements cover a separate application buffer. [Application staging report](../m4-copy-allocation/README.md)

## Fixed ordinary streams

The same nine GCC Debug test cases passed on the control and the changed core. They use a 1,460-byte MSS and the default 4 KiB ring chunks. Exact byte/call assertions belong to this configuration.

| Case | Observed packet work |
| --- | --- |
| Partial send and reads | A 5,059-byte offer admitted 4,096 bytes. TX gathered 1,460, 1,460 and 1,176 bytes. RX stored the same three lengths. Application reads took 517 and 3,579 bytes. |
| Aggregate and retransmit | Four MSS segments used one 5,840-byte GSO packet, gathered in two calls. With ACKs withheld, a loss timer gathered another 1,460 bytes in one ordinary retransmission. The sequence and payload matched the original. The remaining application bytes stayed queued. |
| GSO pool exhausted | Holding the only large buffer forced the next 5,840 bytes into ordinary packets using five copies. The initial 5,840-byte aggregate used two copies. |
| In-order GRO | A valid frame with three full segments and a 17-byte tail delivered 4,397 bytes in two copies (4,096 + 301). |
| Reordered and repeated GRO | Two logical segments arrived above a hole, then arrived identically again. The first arrival stored 2,920 bytes across three copies. The duplicate added zero. Filling the 1,460-byte hole took one copy. |
| GRO under chunk pressure | The one-free-chunk receiver admitted two 1,460-byte segments and dropped the third. It returned exactly those 2,920 bytes. |

## Permanently closed read direction

Shutdown now consumes the readable prefix directly. For later arrivals the receiver reserves the same chunks and processes ranges, overlaps, pruning, receive-window limits and FIN using the original reassembly logic. A specialized write loop omits materializing the bytes once the socket has irrevocably closed its read side. The normal materializing loop has no instrumentation or per-chunk mode test. Receive selects the appropriate insertion path using the existing socket shutdown flag. No per-connection state was added. On both builds GDB measured Tcb at 2,208 bytes, RecvBuffer at 152 and ByteRing at 88. This measurement predates the separate memory-layout work.

| Valid-stream operation | Control bytes / calls | Changed bytes / calls |
| --- | ---: | ---: |
| Read shutdown after the application read 73 bytes from a 4,500-byte prefix | 4,427 / 3 into a discarded scratch buffer | 0 / 0 |
| Gap fill after shutdown, with a 41-byte out-of-order tail and FIN pending | 3,692 / 3 into the ring plus 3,733 / 4 out to scratch | 0 / 0 |
| One-chunk receiver after shutdown, including admission, pruning and a redelivered tail | 4,130 / 5 into the ring plus 4,113 / 4 to scratch | 0 / 0 |
| Shutdown of both directions after 183 unread bytes and FIN | 183 / 1 to scratch | 0 / 0 |

In the first two rows, the 4,541 bytes accepted before shutdown and the application's 73-byte read were identical in both builds. The pending FIN became effective only after hole fill. The receiver acknowledged all 8,233 payload bytes and FIN, returned EOF to the application and released the same three chunks. The one-chunk case reproduced a real admission drop and one prune before the redelivered tail completed the stream. Applying the changed-core copy expectations to the control failed. The Release build passed these nine tests plus the existing close/read-shutdown regression and the three core/suite checks. These tests provide functional and copy evidence. Latency, throughput and allocator-call effects of this change were not measured.

## Provenance and replay

The control is `4f9f1ac9a409e0c8a04e3141cbe7729e96f0bd7d`. Its production sources are identical to `15d2f1bbdbc5c0d19a004cd59c56e48bc6c5d7ca`. The changed core is `b42ecb931f52726bd4231b7eb5945fac87f3f5c2`. The final observer and replay tools are from `11a5bec21b19f283c28c829779e22a649ef24362`. GCC 15.2, GDB 17.1 and Linux x86-64 were used. Development and all four functional wire arms ran on CPUs 24–27 at nice 10. The private archive is `utcp-data:/m4/core-copy-physical-n21/`. It includes the endpoint and fixture executables, observations, test XML, stack statistics, negative control and tool copies. Its 63-file manifest has SHA-256 `9c7d31213640969793b79f173db4b828c3de11474fed0dbd9fd065af196b95b4`.

Replay the archive on Ubuntu with a read-only mount.

```sh
docker run --rm --network none --cpuset-cpus 24-27 \
  --mount type=volume,src=utcp-data,dst=/out,volume-subpath=m4/core-copy-physical-n21,readonly \
  -w /out utcp-testbed:dev nice -n 10 bash -euo pipefail -c '
    echo "9c7d31213640969793b79f173db4b828c3de11474fed0dbd9fd065af196b95b4  SHA256SUMS" | sha256sum -c -
    sha256sum -c --quiet SHA256SUMS
    python3 -I tools/core_copy_check.py unit fixture-before/{physical.json,physical.xml} --baseline | cmp fixture-before/verified.json -
    python3 -I tools/core_copy_check.py unit fixture-after/{physical.json,physical.xml} | cmp fixture-after/verified.json -
    python3 -I tools/core_copy_check.py wire /out | cmp verification/linux-physical.json -
  '
```

For fresh observations, build `utcp_unit_tests` and `utcp-bulk` with the `gcc-debug` preset in a clean checkout of the desired source. Use the final observer in both builds. Its supported environment is the debug-symbol GCC/libstdc++ Linux x86-64 build above. A new, empty output directory is required. Append `--baseline` to the checker for the control.

```sh
observer=/absolute/path/to/final/testbed/m4
out=$(mktemp -d)
cases='TcpOffload.PartialSend*:TcpOffload.VnetGroFrame*:TcpOffload.ReadShutdown*:TcpOffload.ShutdownBoth*:TcpOffload.FreshGso*:TcpOffload.HeldLarge*:TcpOffload.OutOfOrderGro*:TcpOffload.InOrderGroFallsBack*'
UTCP_COPY_OUTPUT="$out/copies.json" taskset -c 24-27 nice -n 10 \
  gdb --batch -nx -q -x "$observer/core_copy_gdb.py" --args \
  build/gcc-debug/tests/unit/utcp_unit_tests "--gtest_filter=$cases" "--gtest_output=xml:$out/cases.xml"
python3 -I "$observer/core_copy_check.py" unit "$out/copies.json" "$out/cases.xml"
```

From a checkout containing the final tools and debug bulk binary, `bash testbed/m4/core_copy_wire.sh FRESH_NAME` creates four new private functional runs. Each process has one local peer in the same private namespace. The host debugger traces its own child inside the container using the default ptrace restrictions. Results go into a new subdirectory of `utcp-data:/m4/`.
