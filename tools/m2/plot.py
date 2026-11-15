#!/usr/bin/env python3
"""Overlay plots of a campaign (M2 design §5.12, DESIGN §14).

  plot.py CAMPAIGN_DIR OUT_DIR

Per (cell, algorithm) one PNG, OUT_DIR/<cell>-<cc>.png, from the
median-goodput repetition of each implementation among the valid runs
(selection_of): three panels on one time axis (seconds since the receiver's
accept, t0; the §5.6 window starts at 5 s):
  1. cwnd in packets (10 ms samples) of the stack and of Linux; the stack's
     retransmissions (tx events of retransmission kinds) and RTOs from its
     trace, Linux's retransmissions from the total_retrans deltas of its
     samples, as marks;
  2. delivery rate and pacing rate (Mbit/s, 10 ms samples);
  3. the receiver's goodput over 100 ms (Mbit/s).
Needs matplotlib (in the testbed image); runs in a helper container started
by `matrix.py plot`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze as A  # noqa: E402

NS = A.NS
COLORS = {"utcp": "#1f77b4", "linux": "#d62728"}


def selection_of(runs):
    """{impl: (meta, summary)} of the median-goodput valid run per impl. With
    an even count the lower of the two middle runs is taken."""
    out = {}
    for impl in sorted({m["impl"] for m, _ in runs}):
        side = [(m, s) for m, s in runs if m["impl"] == impl and s.get("valid")
                and s.get("goodput_bps") is not None]
        if not side:
            continue
        side.sort(key=lambda ms: (ms[1]["goodput_bps"], ms[0].get("run", "")))
        out[impl] = side[(len(side) - 1) // 2]
    return out


def retrans_marks(snd, t0):
    """Times (s since t0) at which the sampled total_retrans increased."""
    ser = A.series(snd, "total_retrans")
    return [(t - t0) / NS for (t, v), (_, prev) in zip(ser[1:], ser[:-1]) if v > prev]


def trace_marks(trace_path, t0):
    rexmit, rto = [], []
    if not trace_path.exists():
        return rexmit, rto
    with open(trace_path) as f:
        for line in f:
            e = json.loads(line)
            if e.get("ev") == "tx" and e.get("tx") in ("fast_rexmit", "rexmit", "rto_rexmit", "pmtu_rexmit", "tlp"):
                rexmit.append((e["t"] - t0) / NS)
            elif e.get("ev") == "rto":
                rto.append((e["t"] - t0) / NS)
    return rexmit, rto


def plot_cell(cell, cc, sel, campdir, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(3, 1, figsize=(11, 9), sharex=True)
    for impl, (meta, summ) in sorted(sel.items()):
        rd = Path(campdir) / meta["run"]
        snd, rcv = A.read_jsonl(rd / "snd.jsonl"), A.read_jsonl(rd / "rcv.jsonl")
        t0 = A.find_event(rcv, "start")["t"]
        c = COLORS.get(impl, "k")
        label = f"{'stack' if impl == 'utcp' else 'Linux'} {meta['run']} ({summ['goodput_bps'] / 1e6:.2f} Mbit/s)"
        cw = A.series(snd, "cwnd")
        ax[0].plot([(t - t0) / NS for t, _ in cw], [v for _, v in cw], color=c, lw=0.8, label=label)
        top = max([v for _, v in cw] or [1])
        if impl == "utcp":
            rexmit, rto = trace_marks(rd / "trace.jsonl", t0)
            if not (rd / "trace.jsonl").exists():
                rexmit = retrans_marks(snd, t0)
            ax[0].plot(rexmit, [top * 1.02] * len(rexmit), "|", color=c, ms=6, label=f"stack retransmissions ({len(rexmit)})")
            ax[0].plot(rto, [top * 1.06] * len(rto), "v", color=c, ms=5, label=f"stack RTOs ({len(rto)})")
        else:
            rx = retrans_marks(snd, t0)
            ax[0].plot(rx, [top * 1.04] * len(rx), "|", color=c, ms=6, label=f"Linux retransmissions (10 ms samples, {len(rx)})")
        for key, style in (("delivery_rate", "-"), ("pacing_rate", ":")):
            ser = A.series(snd, key)
            ax[1].plot([(t - t0) / NS for t, _ in ser], [v * 8 / 1e6 for _, v in ser], style, color=c, lw=0.8,
                       label=f"{'stack' if impl == 'utcp' else 'Linux'} {key.replace('_', ' ')}")
        rb = A.series(rcv, "bytes_received")
        if rb:
            gs = A.rate_series(rb, NS // 10, NS // 10, rb[0][0], rb[-1][0])
            ax[2].plot([(t - t0) / NS for t, v in gs if v is not None], [v / 1e6 for t, v in gs if v is not None],
                       color=c, lw=0.8, label=f"{'stack' if impl == 'utcp' else 'Linux'} goodput (100 ms)")
    ax[0].set_ylabel("cwnd (packets)")
    ax[1].set_ylabel("Mbit/s")
    ax[2].set_ylabel("Mbit/s")
    ax[2].set_xlabel("seconds since the receiver's accept (window starts at 5 s)")
    for a in ax:
        a.axvline(A.WARMUP_S, color="grey", lw=0.5, ls="--")
        a.legend(fontsize=7, loc="best")
        a.grid(alpha=0.3)
    fig.suptitle(f"cell {cell} (Mbit/s-ms-loss %-queue xBDP), {cc}")
    fig.tight_layout()
    path = Path(out) / f"{cell}-{cc}.png"
    fig.savefig(path, dpi=110)
    plt.close(fig)
    return path


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    campdir, out = Path(argv[1]), Path(argv[2])
    out.mkdir(parents=True, exist_ok=True)
    groups = {}
    for meta, summ in A.campaign_runs(campdir):
        if meta.get("impl") in ("utcp", "linux") and meta.get("cell"):
            groups.setdefault((meta["cell"], meta.get("cc")), []).append((meta, summ))
    for (cell, cc), runs in sorted(groups.items()):
        sel = selection_of(runs)
        if not sel:
            print(f"{cell} {cc}: no valid run")
            continue
        p = plot_cell(cell, cc, sel, campdir, out)
        print(f"{p}: " + ", ".join(f"{impl} {m['run']}" for impl, (m, _) in sorted(sel.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
