"""Retain original runner observations even if a shard does not finish."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
import sim_sweep


class ObservedSweep(sim_sweep.Sweep):
    def __init__(self, args):
        super().__init__(args)
        self.out.mkdir(parents=True, exist_ok=True)
        self.observations = (self.out / "observed.jsonl").open("x", buffering=1)

    def record(self, row):
        super().record(row)
        with self.lock:
            self.observations.write(json.dumps(row, separators=(",", ":")) + "\n")
            if row["verdict"] != "ok":
                print(f"original non-ok seed: {json.dumps(row)}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    sim_sweep.Sweep = ObservedSweep
    sys.exit(sim_sweep.main())
