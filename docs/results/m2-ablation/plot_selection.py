"""Check each plotted endpoint's median against independently selected complete pairs."""

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path


def main(camp, evidence, plotlog, out):
    members = defaultdict(list)
    with evidence.open() as stream:
        for row in csv.DictReader(stream):
            if row["counted"] == "1":
                name = row["run"]
                rate = json.loads((camp / name / "summary.json").read_text())[
                    "goodput_bps"
                ]
                members[row["cell"], row["algo"], row["impl"]].append((rate, name))
    expected = {k: sorted(v)[(len(v) - 1) // 2] for k, v in members.items() if v}
    seen = {}
    for line in plotlog.read_text().splitlines():
        if ".png: " not in line:
            continue
        image, selected = line.split(".png: ")
        for item in selected.split(", "):
            impl, name = item.split()
            meta = json.loads((camp / name / "meta.json").read_text())
            key = (meta["cell"], meta["algo"], impl)
            assert (
                Path(image).name == f"{key[0]}-{key[1]}"
                and meta["impl"] == impl
                and key not in seen
            )
            seen[key] = name
    assert seen == {k: v[1] for k, v in expected.items()}
    with out.open("x", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["cell", "variant", "impl", "goodput_bps", "selected_run"])
        for key, value in sorted(expected.items()):
            w.writerow([*key, *value])


if __name__ == "__main__":
    main(*(Path(v) for v in sys.argv[1:]))
