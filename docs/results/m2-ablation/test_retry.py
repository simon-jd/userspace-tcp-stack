"""Exercise normal replay commands with two invalid originals and a valid retry pair.

Run with an actual completed ablation input directory (including pcaps) mounted
read-only and a new private-volume scratch directory. This test copies its inputs.
It produces diagnostic test evidence, never additional measured transfers.
"""

import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import audit


def invoke(script, *arguments, error=None):
    command = [sys.executable, "-B", str(script), *map(str, arguments)]
    result = subprocess.run(
        command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    if error:
        assert result.returncode != 0 and error in result.stdout, result.stdout
    elif result.returncode:
        raise RuntimeError(result.stdout)
    return result.stdout


def data(path):
    with path.open() as f:
        return list(csv.DictReader(f))


def main(original, stage):
    stage.mkdir(parents=True, exist_ok=False)
    camp = stage / "m2d-ablation"
    camp.mkdir()
    shutil.copy2(original / "plan.json", camp / "plan.json")
    for mp in original.glob("*/meta.json"):
        shutil.copytree(mp.parent, camp / mp.parent.name)

    names = ["10-100-1-2-compat-r0-" + side for side in ("utcp", "linux")]
    for name in names:
        rd = camp / name
        retry = camp / (name + "-rerun1")
        rd.rename(retry)
        rd.mkdir()
        shutil.copy2(retry / "meta.json", rd / "meta.json")
        shutil.copytree(retry / "pre", rd / "pre")
        m = audit.read(retry / "meta.json")
        m.update(rerun=1, rerun_of=name, run=retry.name)
        (retry / "meta.json").write_text(json.dumps(m))
        for directory in (rd, retry):
            s = audit.analyze.summarize_run(directory)
            assert s["valid"] == (directory == retry)
            if directory == rd and name.endswith("-linux"):
                partial_metadata = audit.read(rd / "meta.json")
                for key in ("reuse_key", "sender_exit"):
                    del partial_metadata[key]
                (rd / "meta.json").write_text(json.dumps(partial_metadata))
            else:
                (directory / "summary.json").write_text(json.dumps(s))

    def replay(where, label):
        out = stage / label
        invoke(HERE / "audit.py", where, out)
        rows = data(out / "evidence.csv")
        assert len(rows) == 142 and sum(r["counted"] == "1" for r in rows) == 140
        for row in rows:
            if row["run"] in names:
                assert row["valid"] == row["counted"] == "0"
                assert row["invalid"] == "no receiver JSONL;no sender JSONL"
                assert row["receiver_bytes"] == row["transfer_sha256"] == ""
        failed = audit.read(out / "invalid-attempts.json")
        assert set(failed) == set(names)
        assert (
            failed[names[0]]["saved_summary"] and not failed[names[1]]["saved_summary"]
        )
        assert failed[names[1]]["absent_metadata"] == ["reuse_key", "sender_exit"]
        assert [r["reuse_key"] for r in rows if r["run"] == names[1]] == [""]
        assert all(
            not {"snd.jsonl", "rcv.jsonl"}.intersection(v["available_inputs"])
            for v in failed.values()
        )
        assert (
            len(data(out / "endpoint-cc.csv")) == 140
            and len(data(out / "profile-trace.csv")) == 70
        )
        statuses = audit.read(out / "qualification.json")
        assert len(statuses) == 14 and all(
            v["status"] == "ok" and v["counted"] == 10 for v in statuses.values()
        )
        return out

    native = stage / "tables"
    analyze = audit.REPO / "tools/m2/analyze.py"
    invoke(analyze, "tables", native, "--campaign", camp)
    families = data(native / "cells.csv")
    assert len(families) == 28 and all(
        r["status"] == "ok" and r["n_counted"] == "5" for r in families
    )
    raw = replay(camp, "raw-audit")
    invoke(
        HERE / "report.py",
        camp,
        raw / "evidence.csv",
        native / "cells.csv",
        stage / "raw-report",
    )
    phys = stage / "physical"
    invoke(
        audit.CHECKPOINT / "physical_checkpoint.py", camp, raw / "evidence.csv", phys
    )
    physical = audit.read(phys / "physical.json")
    assert physical["counted_pairs"] == 70 and physical["verified_pcaps"] == 280
    assert set(physical["attempts_without_endpoint_start"]) == set(names)
    compact = stage / "compact.tar.gz"
    invoke(analyze, "archive", camp, compact)
    invoke(analyze, "tables", stage / "compact-tables", "--archive", compact)
    for name in ("runs.csv", "cells.csv"):
        assert (native / name).read_bytes() == (
            stage / "compact-tables" / name
        ).read_bytes()
    import tarfile

    with tarfile.open(compact) as archive:
        archive.extractall(stage / "extract", filter="data")
    restored = stage / "extract/m2d-ablation"
    shutil.copy2(camp / "plan.json", restored / "plan.json")
    copied = replay(restored, "compact-audit")
    assert {f.name for f in raw.iterdir()} == {f.name for f in copied.iterdir()}
    for f in raw.iterdir():
        assert f.read_bytes() == (copied / f.name).read_bytes(), f.name
    invoke(
        HERE / "report.py",
        restored,
        copied / "evidence.csv",
        stage / "compact-tables/cells.csv",
        stage / "compact-report",
    )
    for f in (stage / "raw-report").iterdir():
        assert f.read_bytes() == (stage / "compact-report" / f.name).read_bytes(), (
            f.name
        )

    # Plot and export the same counted selection from the ordinary raw and compact entry points.
    for label, source, evidence in (("raw", camp, raw), ("compact", restored, copied)):
        rendered = stage / (label + "-plots")
        transcript = stage / (label + "-plots.txt")
        transcript.write_text(invoke(audit.REPO / "tools/m2/plot.py", source, rendered))
        invoke(
            HERE / "plot_selection.py",
            source,
            evidence / "evidence.csv",
            transcript,
            stage / (label + "-selection.csv"),
        )
    assert (stage / "raw-selection.csv").read_bytes() == (
        stage / "compact-selection.csv"
    ).read_bytes()
    images = sorted((stage / "raw-plots").glob("*.png"))
    assert len(images) == 14
    for image in images:
        assert image.read_bytes() == (stage / "compact-plots" / image.name).read_bytes()

    # An excluded record may omit a late identity field, but an actually recorded
    # incorrect key, or the absence of a required counted key/exit, must fail.
    for label, name, key, value, message in (
        (
            "wrong-recorded-key",
            names[1],
            "reuse_key",
            "incorrect",
            "changed final reuse key",
        ),
        (
            "missing-counted-key",
            names[0] + "-rerun1",
            "reuse_key",
            None,
            "final reuse key",
        ),
        (
            "missing-counted-exit",
            names[0] + "-rerun1",
            "sender_exit",
            None,
            "terminal sender exit",
        ),
    ):
        meta = camp / name / "meta.json"
        original_bytes = meta.read_bytes()
        masked = json.loads(original_bytes)
        if value is None:
            del masked[key]
        else:
            masked[key] = value
        meta.write_text(json.dumps(masked))
        try:
            invoke(HERE / "audit.py", camp, stage / label, error=message)
        finally:
            meta.write_bytes(original_bytes)

    # Keep the valid saved summary, but take away one counted sender's samples.
    # An already-recorded successful transfer must still fail the ordinary audit.
    sender = camp / (names[0] + "-rerun1") / "snd.jsonl"
    sender.rename(stage / "missing-counted-sender.jsonl")
    try:
        invoke(
            HERE / "audit.py",
            camp,
            stage / "negative-audit",
            error="raw-to-summary mismatch",
        )
    finally:
        (stage / "missing-counted-sender.jsonl").rename(sender)
    print(
        "142 physical evidence rows, 140 counted, 2 explicitly invalid originals, 70 pairs and 280 counted captures."
        " Raw/compact audit, report, plot and selection outputs agree. An early missing terminal summary/key/exit is retained. Missing or incorrect counted evidence and a wrong observed key were rejected."
    )


if __name__ == "__main__":
    main(*(Path(a) for a in sys.argv[1:]))
