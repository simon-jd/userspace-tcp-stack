"""Check the published CLI generator vectors and replay a saved strict failure."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sim, sweep = sys.argv[1:]
golden = {
    4: "9d33ebe468594b9446903e7dd887f2b24a7351de104ead0f74bb2e4692f7ff70",
    5: "52a0d36ca8f96aa4b832943b5ff909825874c483cfe7b55fdd840e7fd887809c",
}
default = subprocess.check_output([sim, "--seed", "42", "--dump-scenario"])
assert hashlib.sha256(default).hexdigest() == golden[5]
for version, expected in golden.items():
    dump = subprocess.check_output([sim, "--seed", "42", "--gen-version", str(version),
                                    "--dump-scenario"])
    assert hashlib.sha256(dump).hexdigest() == expected, version

assert subprocess.run([sim, "--seed", "42", "--strict-fast-rexmit", "--no-strict-fast-rexmit"],
                      capture_output=True).returncode == 2

with tempfile.TemporaryDirectory() as out:
    root = Path(out)
    for strict in (False, True):
        flags = ["--strict-fast-rexmit" if strict else "--no-strict-fast-rexmit"]
        run = subprocess.run([sys.executable, sweep, "--sim", sim, "--seeds", "42:43",
                              "--gen-version", "4", "--plant-fail", "42", "--out", out,
                              "--jobs", "1", "--no-taskset", *flags], check=False)
        assert run.returncode == 1
        summary = json.loads((root / "summary.json").read_text())
        failure = json.loads((root / "failures.jsonl").read_text())
        assert summary["strict_fast_rexmit"] is strict
        assert failure["identical"]
        directory = root / "failures" / "seed-42"
        args = failure["replay_args"]
        assert args == ["--scenario", "scenario.txt", *flags]
        replay = subprocess.run([sim, *args, "--jsonl", "-"], cwd=directory,
                                capture_output=True, text=True, check=False)
        assert replay.returncode == 1, replay.stderr
        result = json.loads(replay.stdout)
        assert (result["verdict"], result["digest"], result["events"]) == (
            failure["verdict"], failure["digests"][0], failure["events"])
