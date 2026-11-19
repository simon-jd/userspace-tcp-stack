# BBRv1 measurement inputs

The release candidate is `769311e157dea0e7983a2cd5bd086736339dc62b`. Two independent builds used the clean tracked source, the testbed image and the same in-container source path, `/home/postedism/Desktop/utcp-wt/int-wire40`. They produced identical `utcp-bulk` and `libutcp_core.a` files. On the private Ubuntu host, run the following from the later measurement checkout to restore the measured pair. The recipe checks existing files before using them and validates the preset, kernel, image and timing scripts.

```sh
taskset -c 16-31 nice -n 10 bash docs/results/m2-bbr/restore-runtime.sh \
    3dcd4b48508c8d3352157460bf1f819c472741d40dd095d74dfd8eb245bb4eac
```

The source archive, source manifest, build logs, exact CMake configuration, both binaries, restore script and preregistered pair order are under `utcp-data:/m2/archive/m2c-bbr-769311e-runtime-a1/`. The volume retains the original file bytes and SHA-256 manifest. The runtime uses kernel `7.0.0-42-generic`, `gcc-release` and image `sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66`.

| Input | SHA-256 |
|---|---|
| utcp-bulk | `6bf415a2a5745d356e4583d633327bc3d58f7b49a4ae2c47078fb54405acbc7d` |
| libutcp_core.a | `c3d0fa75effdfc6215e5eb80db0e96cb196ccf79c4c3bffc0b2bce54e2e35d53` |
| tools/m2 and testbed/m2 | `43bf359c7ba1bf5d40f3a58ef7c4c9e5ba82737038b6d25ba35aa52d55b72912` |
| plan.toml | `2b82eec750eb826956239fccb6cb2c3bcf1f9311ddd24a098900b151221fbdf1` |
| pair-order.txt | `d5d8203e4fe494859c8561d79cb70b8d2d308ffa898a42d95666d66ef0fdb29e` |

The smoke plan has one cell at 100 Mbit/s, 20 ms, 0% configured random loss and two BDPs of queue. Each of five repetitions places BBR on the stack and on Linux in consecutive 30-second transfers on slot 0. The launch order comes from seed `2026111903`. To recheck the ten registered specifications, run the following in the measured checkout.

```sh
python3 -B tools/m2/matrix.py expand docs/results/m2-bbr/plan.toml | cmp - docs/results/m2-bbr/pair-order.txt
```

## Live calibration

Both slots recorded the same sysctl and module-parameter digest `795239ee27aa80ccc53bfffd887dddc48aaba8497ce72e08c1f23e1320cbadcf` and reuse key `f0ecf3e4882789e261bb9fa8a3da91adf519b7b0f8f2c8d9b8dbfee286c1013e`. The private volume's `/m2/archive/m2c-bbr-769311e-topology-a1/` holds both complete topology and sysctl records. Its SHA-256 manifest digest is `f5574588796dcd1421f42ea7ee37ed0128378dc2a9dce76cbd5e7407243f89da`. The [freeze](freeze.json), [slot 0](gate-slot0.json) and [slot 1](gate-slot1.json) receipts identify the actual binaries, cpusets, 62 bound inputs per gate, independent wire replay and per-stage archive digests.

After obtaining the timing lease for a later campaign, restore the runtime and start the topology under its own prefix. Check that the production consumer accepts the live key on each slot being used. Ordinary campaigns use one slot at a time.

```sh
# Set UTCP_M2_PREFIX to the topology's actual private prefix.
taskset -c 16-31 nice -n 10 python3 -B - <<'PY'
import sys
sys.path.insert(0, 'tools/m2')
import matrix as m
for n in (0, 1):
    slot = m.Slot(n)
    key = m.current_key(slot, m.static_meta())
    assert key == 'f0ecf3e4882789e261bb9fa8a3da91adf519b7b0f8f2c8d9b8dbfee286c1013e'
    gate = f'm2c-bbr/769311e-calib-a1-s{n}'
    assert m.check_gate(slot, [gate], key) == gate
    print(n, key, gate)
PY
```

## Smoke replay

The original measurements live in `utcp-data:/m2/m2c-bbr/smoke-769311e-a1/`. The verified
archives live in `/m2/archive/m2c-bbr-smoke-769311e-verification-a1/` on that volume.
The raw archive preserves all 171 files and 993,935,550 source bytes. Its compressed size is
467,595,802 bytes. The compact analysis archive contains 100 analysis inputs and its manifest.
The [archive checksums](ARCHIVES.sha256), [five pairs and seeds](physical/pair-order.csv),
[endpoint digests and windows](evidence.csv), [physical capture index](physical/capture-audit.csv)
and [packet totals](physical/physical.json) identify the inputs to the two result rows.
The [CUBIC receipt](cubic-proof.json) covers the separate 15-transfer proof. The acquisition and
cleanup archive is `/m2/archive/m2c-bbr-769311e-closure-a1/`, with manifest digest
`b03efe42850a8c22c5f5480004ecba0c09e26aef8925f826959908d2a30625c8`.

On this host the kernel's current-boot journal recorded BIOS 1836 (2026-04-16) and CPU microcode
0x133 at boot on November 7. Kernel entries during the first calibration also identified BIOS
1836. DMI and the CPU inventory after the ten transfers matched the boot values. The proof and
post-smoke observation used boot ID `301fbbf4-0e61-41c9-a238-a0512d797dac`. These observations
bound the firmware comparison to those times. Individual runs sampled socket, topology and CPU
state. Firmware was not polled per transfer.

For a replay, start an isolated analysis shell from the candidate or a documentation-only descendant.

```sh
docker run --rm -it --network none --cpuset-cpus 16-31 --name "utcp-bbr-live-review-$$" \
    -v "$PWD:/utcp:ro" -v utcp-data:/data:ro -v utcp-data:/work \
    sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66 \
    nice -n 10 bash
```

In the shell, use a new volume scratch directory for every replay.

```bash
set -euo pipefail
res=/utcp/docs/results/m2-bbr
arc=/data/m2/archive/m2c-bbr-smoke-769311e-verification-a1
work=$(mktemp -d /work/m2/archive/bbr-smoke-replay.XXXXXXXX)
export TMPDIR="$work" MPLCONFIGDIR="$work/mpl"
(cd "$arc" && sha256sum -c "$res/ARCHIVES.sha256")
raw=$(awk '$2 ~ /-raw-.*tar.gz$/ {print $2}' "$res/ARCHIVES.sha256")
tar xzf "$arc/$raw" -C "$work"
camp="$work/smoke-769311e-a1"
(cd "$camp" && sha256sum -c "$work/manifest/raw.sha256")
python3 -IB /utcp/tools/m2/analyze.py tables "$work/tables" --archive "$arc/analysis.tar.gz"
for f in runs.csv cells.csv; do cmp "$work/tables/$f" "$res/$f"; done
python3 -IB "$res/verify/smoke_replay.py" /utcp "$camp" "$work/checked" "$res/freeze.json"
for f in evidence.csv endpoint-cc.csv bbr-trace.json medians.json; do cmp "$work/checked/$f" "$res/$f"; done
verify=/utcp/docs/results/m2-checkpoint/verify
python3 -IB "$verify/physical_checkpoint.py" "$camp" "$res/evidence.csv" "$work/physical"
diff -qr "$work/physical" "$res/physical"
python3 -IB "$verify/diagnostics.py" /utcp "$camp" "$res/evidence.csv" "$work/diagnostics.csv"
cmp "$res/diagnostics.csv" "$work/diagnostics.csv"
python3 -IB /utcp/tools/m2/plot.py "$camp" "$work/plots"
diff -qr "$work/plots" "$res/plots"
```
