"""Verify the sealed M4 records and recompute their numerical reports."""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

from replay_archive import capture_path, read_manifest, sha256, verify

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent
PERF = "m4/performance"
COMBINED_ECHO = ("20261120T224631Z-13ee3744", "20261120T224653Z-a0e10a5a")


def checked_file(root, name, checksum):
    path = root / name
    if capture_path(name) or path.is_symlink() or path.resolve() != path:
        raise ValueError(f"unexpected capture or linked file: {path}")
    if sha256(path) != checksum:
        raise ValueError(f"SHA-256 mismatch: {path}")


def verify_inputs(data):
    for name, checksum in read_manifest(HERE / "m4-performance-manifests.sha256").items():
        manifest = data / PERF / name
        verify(manifest, checksum)
        entries = read_manifest(manifest)
        for path, expected in entries.items():
            checked_file(manifest.parent, path, expected)
        print(f"{len(entries)} authenticated files in {manifest.parent.name}", flush=True)
    entries = read_manifest(HERE / "m4-echo-allocation-inputs.sha256")
    for path, checksum in entries.items():
        checked_file(data, path, checksum)
    print(f"{len(entries)} authenticated echo/allocation input files", flush=True)


def replay(out, name, script, *args):
    with (out / name).open("xb") as dest:
        subprocess.run([sys.executable, "-B", str(script), *map(str, args)], stdout=dest, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data", type=Path, help="read-only evidence mount")
    parser.add_argument("scratch", type=Path, help="separate writable scratch parent")
    args = parser.parse_args()
    data, scratch = args.data.resolve(strict=True), args.scratch.resolve(strict=True)
    repo = RESULTS.parents[1]
    for root in (data, repo):
        if root == scratch or root in scratch.parents or scratch in root.parents:
            parser.error("scratch parent must be separate from the evidence and checkout mounts")
    out = Path(tempfile.mkdtemp(prefix="m4-replay.", dir=scratch))
    print(f"WORK={out}", flush=True)
    verify_inputs(data)
    perf = data / PERF
    baseline = RESULTS / "m4-baseline/audit.py"
    for campaign in ("baseline-pilot-01", "baseline-r1"):
        args = (perf / campaign, "--clock-ticks", "100")
        replay(out, f"{campaign}.json", baseline, *args)
        replay(out, f"{campaign}.csv", baseline, *args, "--csv")
    replay(out, "tun-vnet.json", RESULTS / "m4-tun-vnet/audit.py", perf)
    replay(
        out, "multiqueue.json", RESULTS / "m4-tun-multiqueue/audit.py", perf,
        "--baseline-audit", baseline, "--clock-ticks", "100",
    )
    replay(out, "legacy-echo.json", HERE / "replay_legacy_echo.py", data)
    replay(out, "copy-allocation.json", HERE / "replay_copy_allocation.py", data)
    replay(
        out, "integrated-echo.json", HERE / "replay_integrated_echo.py",
        *(data / "m4-echo-load" / arm for arm in COMBINED_ECHO),
    )
    for name, checksum in read_manifest(HERE / "m4-replay-results.sha256").items():
        verify(out / name, checksum)
    for left, right in (
        ("baseline-r1.json", "m4-baseline/summary.json"),
        ("baseline-r1.csv", "m4-baseline/evidence.csv"),
        ("tun-vnet.json", "m4-tun-vnet/summary.json"),
        ("multiqueue.json", "m4-tun-multiqueue/evidence.json"),
    ):
        if (out / left).read_bytes() != (RESULTS / right).read_bytes():
            raise ValueError(f"replayed output differs from Git: {right}")


if __name__ == "__main__":
    main()
