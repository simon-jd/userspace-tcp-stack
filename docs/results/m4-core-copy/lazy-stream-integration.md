# TCP copy verification after lazy stream allocation

The integrated runtime is `1d327d2e20ac239b6ae5480705253168f1702e03`. It combines the memory candidate `2353344bf1999b0976bd72161bcecae46cd7d5c6` and the original copy study `2987d64b05c9f3a30d67fe40cc5587f14b64cd4c`. The matching control `54bbbc84aeaafe119c8951639ad0964bcbf37ccd` adds the same tests and diagnostic tools to the memory candidate. Its production source, headers and application tree match the memory candidate exactly.

An idle socket closing its read direction now skips the receive-queue operation while its stream pointer is empty. First payload or FIN activates the stream before accessing the queue. A zero-length send and receive, followed by read shutdown on an untouched established socket, kept its stream-state count at zero. A first bare FIN and a first 53-byte segment carrying FIN each ended in CLOSE_WAIT with EOF and one stream state. Both released all receive chunks. The existing first-transfer test independently exercised ordinary bidirectional activation with NewReno, CUBIC and BBR. Both extra tests passed in both builds.

## Core copies and interoperability

For each build, the nine ordinary stream fixtures passed at the default 4 KiB chunk size. The debugger checked the actual source, destination, stream offset and number of bytes on every ring copy. The two fixture receipts reproduce the corresponding pre-integration counts byte for byte. In the unread-prefix and pending-FIN test, the integrated build saved 11,852 copied bytes and ten calls. Applying its expected counts to the unchanged memory control failed. The split between API copies, freshly materialized packets and required retransmission remains the same as in the [original copy study](README.md).

Each executable ran four separate transfers against the local Linux TCP implementation, in network-isolated TUN namespaces, once per direction and offload mode. All eight transfers reached 65,549 bytes and produced SHA-256 `1e76f01beaa38c9fe81c1647403b441f35f5695fbfc0bd8bc666bf354753e602` at both endpoints. The physical observations independently matched every slice of the reference stream. The two runs produced the same counts in these four arms.

| Integrated userspace boundary | Copied bytes | Completed memcpy calls |
| --- | ---: | ---: |
| Legacy application → send ring | 65,549 | 17 |
| Legacy send ring → packet | 65,549 | 61 |
| Legacy packet → receive ring | 65,549 | 62 |
| Legacy receive ring → application | 65,549 | 19 |
| TCPv4 send ring → GSO packet | 62,264 | 19 |
| TCPv4 send ring → ordinary packet | 3,285 | 4 |
| TCPv4 aggregate → receive ring | 44,888 | 16 |
| TCPv4 aggregate through logical fallback → receive ring | 19,213 | 19 |
| TCPv4 ordinary packet → receive ring | 1,448 | 1 |

The TCPv4 socket API copied 65,549 bytes in 17 send or 19 receive calls. Five GSO datagrams and six GRO datagrams were observed per matching direction. Each fresh application byte crossed its packet/ring boundary once. The calls differ with segmentation and chunk boundaries. Kernel-side copies and timing are outside the debugger measurement.

## Population and object sizes

A separate Release functional run on CPUs 24, 25 and 26 kept 10,000 established connections for 5.400753391 seconds. The server had 10,001 TCP slots including the listener and zero stream objects through the idle hold. All three active samples had 10,000 stream objects. The client verified 50,000 replies and 3,200,000 bytes. Both endpoints reported zero errors and the client reported zero mismatches.

GDB measured the same sizes in both Debug builds. Tcb was 1,016 bytes, StreamState 1,064, TimeWaitEntry 64, RecvBuffer 152 and ByteRing 88. The live Release server independently reported the same Tcb and StreamState sizes. The observed idle RSS delta from the started listener was 15,425,536 bytes, or 1,542.5536 bytes per connection. This is one functional run. The five paired timing runs and the earlier 10,000-connection comparison belong to the [separate memory study](../m4-memory/README.md).

The eleven ordinary integration tests also passed under Clang AddressSanitizer and UndefinedBehaviorSanitizer with leak detection and immediate failure enabled. The studies used development CPUs 24–27 at nice 10. No timing comparison was made from debugger or population observations.

## Verification archive

The new 137-file archive is `utcp-data:/m4/copy-memory-integrated-result-n21/`. Its manifest SHA-256 is `e17fb73f9d49d4fc5417e0edbc94bdce3e03011cb47cfa59f7931a137e8f4c27`. Both executables on each side of the comparison, raw observer records, stack statistics, Linux endpoint receipts and population snapshots are retained there. The Debug bulk executable digests were `0dc054849577001c2f829fd824fa167f04002adee7de0769d6f4d3b26b7ecc69` for the control and `2dc3268d5fb808cf184aaf4a99e68285a8d85073d0f032bbd057fd5cbb78ceea` for the integrated runtime.

```sh
docker run --rm --network none --cpuset-cpus 24-27 \
  --mount type=volume,src=utcp-data,dst=/out,volume-subpath=m4/copy-memory-integrated-result-n21,readonly \
  -w /out utcp-testbed:dev nice -n 10 bash -euo pipefail -c '
    echo "e17fb73f9d49d4fc5417e0edbc94bdce3e03011cb47cfa59f7931a137e8f4c27  SHA256SUMS" | sha256sum -c -
    sha256sum -c --quiet SHA256SUMS
    python3 -I method/core_copy_check.py unit before/fixture/{copies.json,cases.xml} --baseline | cmp before/fixture/verified.json -
    python3 -I method/core_copy_check.py unit after/fixture/{copies.json,cases.xml} | cmp after/fixture/verified.json -
    for arm in before after; do
      python3 -I method/core_copy_check.py wire "$arm/wire" | cmp "$arm/wire-summary.json" -
    done
  '
```
