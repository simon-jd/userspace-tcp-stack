"""Print the checkpoint host's Linux-compatible defaults from the frozen binary before transport setup.

Run in the testbed image with --network none and no TUN device.
"""

import json
import subprocess
import sys

references = []
for cc in ("newreno", "cubic"):
    command = [
        sys.argv[1],
        "--backend",
        "utcp",
        "--tun",
        "utcp0",
        "--addr",
        "198.18.0.2",
        "--profile",
        "linux",
        "--connect",
        "198.19.12.5:5201",
        "--send",
        "--duration",
        "30",
        "--cc",
        cc,
        "--jsonl",
        "-",
        "--set",
        "snd_buf_max=64Mi",
        "--set",
        "rcv_buf_max=32Mi",
        "--set",
        "gso_max_size=65215",
    ]
    process = subprocess.run(command, capture_output=True, text=True)
    assert process.returncode == 1 and (
        "interface utcp0 does not exist" in process.stderr or "/dev/net/tun" in process.stderr
    ), (process.returncode, process.stderr)
    rows = [json.loads(line) for line in process.stdout.splitlines()]
    assert [r["ev"] for r in rows] == ["clock", "config"]
    references.append(rows[1])
assert references[0] == references[1]
assert references[0]["cc"] == "newreno" and references[0]["cc_flavor"] == "linux"
print(json.dumps(references[0], sort_keys=True, indent=2))
