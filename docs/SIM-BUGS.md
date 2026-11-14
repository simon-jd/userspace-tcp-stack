# Simulator bugs

Every invariant violation the simulator sweeps found (DESIGN §7.3, §7.4), with its root cause and fix, and the
tshark expert analysis of the sampled seeds. Each entry's dumped scenario is in `tests/sim/corpus/` as
`<entry>-<seed>.scenario`; CI replays all of them (`sim.SimCorpus.EveryEntryPasses`).

## Violations

| Entry | Seed | Found by | Checker | Symptom | Root cause | Fixing commit |
|---|---|---|---|---|---|---|
| sb-0001 | 5 | m1-tcp-core sweep | InFlightChecker | data sent past the peer's window | an ACK that advanced SND.UNA with an older SEQ did not update SND.WND | dddacee |
| sb-0002 | 209 | m1-tcp-core sweep | hang | the run did not finish | the walk over lost segments did not stop after the last lost segment | ed50a9c |
| sb-0003 | 3106 | m1-tcp-robust 1e4 sweep | TerminationChecker | RST received in CLOSE-WAIT reported as an illegal end | checker: the peer's orphan FIN-WAIT-2 timeout followed by an RST to our next segment is a legal end (Linux frees the orphan after `tcp_fin_timeout`) | 6999c42 (checker) |
| sb-0004 | 5582 | m1-tcp-robust 1e4 sweep | TerminationChecker | as sb-0003 | as sb-0003 | 6999c42 (checker) |
| sb-0005 | 6144 | m1-tcp-robust 1e4 sweep | TerminationChecker | as sb-0003 | as sb-0003 | 6999c42 (checker) |

## 1e5-seed acceptance sweep (m1-accept-sweep, test F)

Command (server, `gcc-sweep` build, CPUs 16-31):

    tools/sim_sweep.py --seeds 0:100000 --jobs 8 --asan-sim build/gcc-asan/apps/utcp-sim/utcp-sim --out DIR

Every failing seed is replayed twice by the sweep (identical digest, or for a crash the rolling digest and event
count, required before a fix) and once under the ASan/UBSan build.

## tshark expert analysis

Rule (acceptance test G, fixed before the run):

- Input: the pcaps that `tools/sim_sweep.py` writes for the sampled seeds (`seed % 500 == 0`, 200 seeds in
  0:100000) of the final, clean 1e5-seed run, in `DIR/samples/seed-N/`.
- Command: `tools/tshark_expert.sh DIR/samples`, run in the `utcp-testbed:dev` image (TShark 4.6.4).
- Files checked: every `*.egress.pcap` (before link impairment); the `*.ingress.pcap` files only of seeds whose
  scenario has `bitflip_ppm` and `garbage_ppm` 0 on every link, because bit flips and garbage produce malformed
  frames on ingress by design.
- Pass: every file is readable and no file has an Error-severity expert item. An Error item is investigated like
  an invariant violation: root cause, fix in the stack (or evidence that the dissector is wrong), and an entry in
  the table above.
- Warning-severity items do not fail the check; they are counted by type (group, protocol, summary) below.
