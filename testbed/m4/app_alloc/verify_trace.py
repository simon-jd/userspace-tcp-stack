import json
import sys
from pathlib import Path
d=Path(sys.argv[1])
stats=json.loads((d/"stack-stats.jsonl").read_text())
last=-1
count=0
with (d/"events.trace").open() as stream:
    for line in stream:
        row=json.loads(line)
        assert row["ev"]=="tx" and row["t"]>=last
        last=row["t"]
        count+=1
assert count==stats["trace_events"] and stats["trace_blocks"]>=2
print(json.dumps(dict(events=count,blocks=stats["trace_blocks"],file_bytes=(d/"events.trace").stat().st_size)))
