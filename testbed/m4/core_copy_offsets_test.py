"""Exercise copy-offset controls against the archived integrated before/after fixtures."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def check(checker, fixture, copies, baseline):
    command = [sys.executable, "-I", str(checker), "unit", str(copies), str(fixture / "cases.xml")]
    if baseline:
        command.append("--baseline")
    return subprocess.run(command, capture_output=True, text=True, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="directory containing before/fixture and after/fixture")
    args = parser.parse_args()
    checker = Path(__file__).with_name("core_copy_check.py")
    controls = [
        ("after", "PartialSendAndShortReadsKeepTheAcceptedBytes", "tx_packet", 0, 256),
        ("after", "FreshGsoIsBoundedByTheLogicalCwndAndRetainsPerSegmentRecovery",
         "tx_retransmit", 0, 256),
        ("after", "ReadShutdownWithUnreadPrefixAndPendingFinPreservesAdmission",
         "rx_packet", 8192, -256),
        ("before", "ReadShutdownStillChargesOutOfOrderChunksAndPrunesOnHoleFill",
         "rx_after_shutdown", 4096, -256),
    ]
    for arm in ("before", "after"):
        fixture = args.archive / arm / "fixture"
        result = check(checker, fixture, fixture / "copies.json", arm == "before")
        if result.returncode or result.stdout != (fixture / "verified.json").read_text():
            raise RuntimeError(f"{arm}: genuine observation failed to reproduce: {result.stderr}")
    with tempfile.TemporaryDirectory() as temp:
        changed = Path(temp) / "copies.json"
        for arm, case, kind, offset, shift in controls:
            fixture = args.archive / arm / "fixture"
            records = json.loads((fixture / "copies.json").read_text())
            row = next(r for r in records if r["case"] == "TcpOffload_" + case and
                       r["path"] == kind and r["offset"] == offset)
            # Only this one offset changes. All source digests, lengths, call
            # counts and path labels still match the periodic fixture payload.
            row["offset"] += shift
            changed.write_text(json.dumps(records))
            result = check(checker, fixture, changed, arm == "before")
            expected = f"ValueError: ('copy coverage', '{case}', '{kind}',"
            if result.returncode == 0 or expected not in result.stderr:
                raise RuntimeError(f"{case}/{kind}: expected a coverage failure: {result.stderr}")
            print(f"{arm} {case}/{kind}: rejected offset {offset} shifted by {shift:+}")
    print("Two genuine fixtures reproduced. Four offset controls rejected.")


if __name__ == "__main__":
    main()
