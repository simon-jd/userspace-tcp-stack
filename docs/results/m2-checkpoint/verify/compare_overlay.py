import csv
import re
import sys
from pathlib import Path

with open(sys.argv[1]) as f:
    expected = {(r["cell"], r["algo"], r["impl"]): r["run"] for r in csv.DictReader(f)}
actual = {}
for line in Path(sys.argv[2]).read_text().splitlines():
    m = re.fullmatch(
        r".*/([\d.]+-[\d.]+-[\d.]+-[\d.]+)-(cubic|newreno)\.png: linux ([\w.-]+), utcp ([\w.-]+)", line
    )
    if not m:
        continue
    cell, algo, linux, utcp = m.groups()
    for impl, run in (("linux", linux), ("utcp", utcp)):
        key = (cell, algo, impl)
        assert key not in actual
        actual[key] = run
assert len(actual) == 32 and actual == expected, (
    len(actual),
    set(expected.items()) ^ set(actual.items()),
)
print("All 32 printed overlay selections match the medians of counted pairs.")
