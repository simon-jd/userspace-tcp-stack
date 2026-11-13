# Simulator corpus

One file per SIM-BUGS entry: the dumped scenario of the failing seed, named
`<entry>-<seed>.scenario` (for example `sb-0007-123456.scenario`). The test
`sim.SimCorpus.EveryEntryPasses` and `utcp-sim --corpus tests/sim/corpus`
replay every `*.scenario` file here, sorted by name, and expect verdict `ok`.

Format: the `key=value` lines of `utcp::sim::to_kv` (one key per line, `#`
comments and blank lines allowed, missing keys take their defaults, unknown
keys and a `gen_version` above the simulator's are errors). Get one with

    utcp-sim --seed N --dump-scenario > tests/sim/corpus/sb-XXXX-N.scenario

or take `scenario.txt` from the sweep's failure directory
(`<out>/failures/seed-N/scenario.txt`). The file keeps the scenario exactly,
so it replays after the generator changes (`gen_version`).
