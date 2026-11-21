"""Reproduce tables, plots and endpoint census from a verified multiflow restore."""

import hashlib
import json
import sys
from pathlib import Path

RESULTS = Path(__file__).resolve().parents[1] / "m2-multiflow"
sys.path.insert(0, str(RESULTS))
import archive_replay as replay


def main(campaign, work):
    measured = RESULTS / "measured"
    receipt = json.loads((measured / "archive-replay.json").read_text())
    tables = work / "tables"
    replay.run_tables(campaign, "acquisition-q1", tables)
    manifest = replay.manifest(tables)
    if (
        len(manifest) != receipt["table_files"]
        or hashlib.sha256(replay.manifest_bytes(manifest)).hexdigest()
        != receipt["tables_sha256"]
    ):
        raise ValueError("multiflow table and plot manifest differs from the receipt")
    for name, digest in manifest.items():
        if replay.digest(measured / name) != digest:
            raise ValueError(f"replayed table or plot differs from Git: {name}")
    census = work / "physical-connections.csv"
    connections = replay.connections(campaign, tables, census)
    if connections != receipt["connections"] or replay.digest(census) != replay.digest(
        measured / census.name
    ):
        raise ValueError("endpoint census differs")
    print(f"Verified {len(manifest)} multiflow tables and plots, plus the endpoint census")


if __name__ == "__main__":
    main(*map(Path, sys.argv[1:]))
