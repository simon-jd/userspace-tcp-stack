# Verification receipt

The 2026-11-20 run used base Stack commit
`22b7cf30961cffb4b456c01aafb8c662f404212d` with the adapter and runner in this
directory's changeset. The platform was Ubuntu 26.04.1 LTS,
`7.0.0-42-generic`, x86-64. The official Packetdrill checkout was clean at
`15ab46aedd01a5e664ec5cfb2b1888328cdd3901`. Its build used GCC 15.2.0,
Bison package `2:3.8.2+dfsg-1ubuntu0.26.04.1`, and Flex package
`2.6.4-8.2build2`. The testbed image ID was
`sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66`.

```text
109c11cb421d949fd03dd8a821f56b48ae969c0d72fbd604f6aea0f3f3c76802  packetdrill
3fb703130031dba4e3966b78a634f8e5e35c4c974d52da2f643c78ec4509b9a0  packetdrill.h
bf2655a35dd464c429e7cb09d8000d873a3590f1b7a225fef248de739d56ee32  utcp_packetdrill.so
```

`readelf --wide --dyn-syms` listed `packetdrill_interface_init` as a global
function. The retained host receipt is `build/packetdrill/receipts/run-9DENaqaB/`.
Both repetitions produced the same callback counts and state-transition
times. Packetdrill assigns a kernel ephemeral port to the passive peer, so
the passive wire tuple and absolute sequence numbers can vary.

```text
run 1: active open and passive open passed
run 2: active open and passive open passed
bad-expected-ack: rejected with exit 1
missing-egress: rejected with exit 1
active   rx=4 tx=5 sleeps=3 clock_reads=354 regressions=0 fds=0 tcp_slots=0 time_wait=1 queued=0
passive  rx=6 tx=4 sleeps=5 clock_reads=425 regressions=0 fds=0 tcp_slots=0 time_wait=0 queued=0
```

The passive input segment appeared at 0.030035 s and the delayed ACK at
0.230035 s in Packetdrill's virtual script time. The Stack trace included
`timer=delack conn=2 virtual_us=230295`.

## Additional checks

- `taskset -c 30,31 nice -n 10 ctest --test-dir build/m3-packetdrill-core -j2 --output-on-failure`
  had 1,063 passes and four tshark-dependent skips. A second invocation with
  `-R '^sim\.SimPcap\.'` in the testbed image passed all five selected tests,
  including the four skipped on the host.
- Clang 21.1.8 accepted the adapter with `-fsyntax-only` and the project's
  warning flags. `bash -n`, `shellcheck`, and `git diff --check` passed.
- Both positive scripts also passed with `-fsanitize=address,undefined`
  applied to the adapter and the PIC GCC ASan Stack archive. These two
  supplementary runs used a local Packetdrill copy with `RTLD_DEEPBIND`
  and its startup `mlockall` call removed for ASan.
  An unsuppressed active run reported 6,661 bytes in 124 upstream allocations.
  Unmodified Packetdrill `--dry_run` with the sanitizer runtime loaded
  reported 5,898 bytes in 114 allocations before loading any adapter.
  The two supplementary passes kept leak detection enabled with suppressions
  for Packetdrill's `read_script`, `add_packet_dump`,
  `parse_command_line_options`, and `new_event`. They reported no remaining
  sanitizer diagnostics. The local patch, invocations, suppressions, and
  logs are retained in `build/packetdrill/`.
