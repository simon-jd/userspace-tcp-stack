import json
from pathlib import Path
import subprocess
import sys
import time
p=Path(sys.argv[1])
start=int(time.monotonic())+1
for number in range(40):
    time.sleep(max(0,start+number-time.monotonic()))
    row=json.loads(subprocess.check_output([sys.executable,str(Path(__file__).with_name("snapshot.py")),str(p),f"series-{number:02}"]))
    if row["final"]:
        break
