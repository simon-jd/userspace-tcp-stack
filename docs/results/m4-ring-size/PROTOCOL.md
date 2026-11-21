# Core ring allocation size study

## Frozen design

The experimental unit is one complete matched block on the same accepted memory and copy baseline. Build the same source using GCC 15 Release and core ring chunks of 2, 4 and 8 KiB. The 4 KiB arm is the current default. Keep the default pool storage cap at 4 GiB in all three arms. ChunkPool takes a count when explicitly configured. Its allocation and free-list bookkeeping are outside this cap. Keep the application buffers, packet limits, congestion control, MTU 1500, seeds, stack profile, legacy single-queue TUN, mode, host image and Linux peer executable fixed. No offloads or new allocator.

Run six matched blocks, one for each permutation, in this order (KiB):

1. 2, 4, 8
2. 4, 8, 2
3. 8, 2, 4
4. 8, 4, 2
5. 4, 2, 8
6. 2, 8, 4

For bulk, alternate direction order per block. Within each direction traverse the registered arm order; use a single fixed Linux kernel peer. Every transfer uses the production bulk application, CUBIC, 256 KiB application chunks, seed 1, and exactly 1,000,000,000 bytes. Verify the independent oracle and both endpoints' SHA-256 and byte counts. Record receiver goodput and sender/receiver user, system and total process CPU seconds per decimal GB. Primary CPU is the userspace endpoint in each direction. Use the existing testbed/m4/performance receipts.

For echo, run the registered arm order at each block. Hold 10,000 simultaneously established connections at both ends for at least five seconds, then byte-check five 64 B responses per connection at 5,000 requests/s, seed 1. Use the existing echo_load gates, staged echo, CUBIC and TCP_NODELAY. Collect server baseline, idle and three in-workload RSS samples, through-drain VmHWM, exact chunks obtained from the heap and free at each application observation, high-water chunk storage bytes (allocated count times experimental chunk size) and final allocation failures if the source supplies them. The pool retains every chunk obtained from the heap, so the last pre-shutdown count bounds all previous allocations in that process. Also report echo latency p50/p99, error counts and active process CPU. The raw samples include transport, allocator, application and process accounting with separate scopes. The uninstrumented echo pool counts describe actual backing allocations; they do not count unrelated C++ heap calls.

No timing workloads on CPUs 8-15 until the coordinator releases them. For measured bulk pin DUT/peer to 8/10, for echo pin server/client/collector to 8/10/12. All runs are serial. No benchmark warm results influence the following selection. Store raw data, hashes, exact commands, executable build settings, image and source identities in dedicated utcp-data paths. Retain every attempt. A failed setup can be rerun with a preserved reason; never remove a slower valid sample. If an arm fails a correctness gate record it separately and replay a complete block after fixing the cause, on identical source for all compared arms.

## Selection registered before performance data

For each nondefault size, compare each complete block against the matched 4 KiB result. Report every block and the median paired percentage change with min/max, positive and negative signs. Do not pool directions. Treat a change as repeatable only if at least five of six paired observations move in the stated direction. This is an engineering decision rule, not a significance test.

An alternative is eligible only when every valid arm satisfies all transfer and echo workload gates and all of its runs meet the existing server limits (idle delta <= 2 KiB/connection, max active sampled delta <= 12 KiB/connection, VmHWM <= 128 MiB). Veto a choice if its median paired goodput loss in either direction exceeds 5%, or if its median paired DUT CPU, max active RSS delta/connection, or process VmHWM increases by more than 5%. Apply these vetoes regardless of sign count. Also veto any pool exhaustion under the normal workload. Idle RSS remains a hard limit and is published even when numerically indistinguishable across arms.

Among eligible alternatives, require a repeatable median benefit of at least 5% for at least one of: either-direction receiver goodput, either-direction DUT CPU, max active RSS delta/connection, or process VmHWM. If two alternatives qualify, rank by the larger of their repeatable median percentage reductions in max active RSS delta/connection and VmHWM. Break a tie by worst-direction goodput gain, then worst-direction DUT CPU reduction, then prefer the smaller chunk. If neither qualifies, retain 4 KiB. Allocation counts, resident pool bytes, sender/peer CPU breakdown, latency, tail ranges and any trade-offs remain visible even when they do not change the choice. A change to the production default requires independent confirmation.
