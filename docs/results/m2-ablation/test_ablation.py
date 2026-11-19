"""Negative controls for the full-profile and shared-reference attribution rules."""

import csv
import json
import subprocess
import tempfile
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit
import report


def stat(lo, hi):
    return {"min": lo, "max": hi, "median": (lo + hi) / 2, "n": 5}


def run_report(base, evidence, output):
    subprocess.run(
        [
            sys.executable,
            "-B",
            str(audit.HERE / "report.py"),
            str(base),
            str(base / evidence),
            str(base / "cells.csv"),
            str(base / output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def write_example(base):
    rows, cells = [], []
    for cell in report.CELLS:
        for variant in report.VARIANTS:
            for side in ("utcp", "linux"):
                rate = 2 if variant == "rfc" and side == "linux" else 1
                metrics = dict(
                    goodput_bps=rate * 1e6,
                    retrans_pct=1.0,
                    qdelay_p50_ms=0.1,
                    qdelay_p99_ms=0.2,
                )
                agg = dict(cell=cell, algo=variant, impl=side, n_counted=5, status="ok")
                for metric, value in metrics.items():
                    for key in ("median", "min", "max", "n"):
                        agg[metric + "_" + key] = report.A.fmt(
                            5 if key == "n" else value
                        )
                cells.append(agg)
                for index in range(5):
                    name = f"{cell}-{variant}-{side}-{index}"
                    directory = base / name
                    directory.mkdir()
                    (directory / "summary.json").write_text(
                        json.dumps(dict(metrics, flags=[], valid=True))
                    )
                    rows.append(
                        dict(
                            cell=cell,
                            algo=variant,
                            impl=side,
                            run=name,
                            counted=1,
                        )
                    )
    report.save(base / "evidence.csv", rows)
    report.save(base / "cells.csv", cells)
    run_report(base, "evidence.csv", "result")
    return rows


class AblationTests(unittest.TestCase):
    def test_common_control_can_disagree_with_native_rfc_control(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            write_example(base)
            with (base / "result" / "effects.csv").open() as f:
                effects = list(csv.DictReader(f))
            for row in effects:
                if row["effect"] == "compat minus all four":
                    self.assertEqual(float(row["median"]), 0)
                elif row["reference"] == "primary":
                    self.assertEqual(row["status"], "no gap to attribute")
                    self.assertEqual(row["median"], "")
                else:
                    self.assertEqual(row["status"], "goodput gap")
                    self.assertEqual(float(row["median"]), 0)

    def test_excluded_transfer_contributes_flags_only(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            rows = write_example(base)
            extra = dict(rows[0], run="excluded-physical-transfer", counted=0)
            (base / extra["run"]).mkdir()
            (base / extra["run"] / "summary.json").write_text(
                json.dumps(
                    {"flags": ["foreign_cpu"], "goodput_bps": 1e12, "valid": False}
                )
            )
            report.save(base / "all-evidence.csv", [*rows, extra])
            run_report(base, "all-evidence.csv", "with-excluded")
            raw = (base / "result" / "tables.md").read_text()
            result = (base / "with-excluded" / "tables.md").read_text()
            self.assertNotIn("with `foreign_cpu`", raw)
            self.assertEqual(result.count("1 with `foreign_cpu`"), 1)
            for output in ("effects.csv", "comparisons.csv"):
                self.assertEqual(
                    (base / "result" / output).read_bytes(),
                    (base / "with-excluded" / output).read_bytes(),
                )

    def test_pre_only_excluded_attempt_and_missing_counted_summary(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            rows = write_example(base)
            rows = [dict(r, valid=1, flags="", invalid="") for r in rows]
            partial = dict(
                rows[0],
                run="pre-only-attempt",
                counted=0,
                valid=0,
                invalid="no receiver JSONL;no sender JSONL",
            )
            rd = base / partial["run"]
            rd.mkdir()
            (rd / "meta.json").write_text(json.dumps({"run": rd.name}))
            report.save(base / "pre-evidence.csv", [*rows, partial])
            run_report(base, "pre-evidence.csv", "pre-output")
            self.assertIn(
                "1 excluded attempt", (base / "pre-output/tables.md").read_text()
            )
            for name in ("comparisons.csv", "effects.csv"):
                self.assertEqual(
                    (base / "pre-output" / name).read_bytes(),
                    (base / "result" / name).read_bytes(),
                )
            (base / rows[0]["run"] / "summary.json").unlink()
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                run_report(base, "pre-evidence.csv", "corrupt-counted")
            self.assertIn("Missing counted or valid summary", caught.exception.stderr)

    def test_shared_rfc_bound(self):
        result = report.corner_range(
            report.share, stat(10, 12), stat(18, 20), stat(14, 17)
        )
        self.assertEqual(result["min"], 25)
        self.assertEqual(result["max"], 87.5)
        self.assertEqual(result["median"], 56.25)

    def test_negative_gap_and_unclipped_shares(self):
        result = report.corner_range(
            report.share, stat(18, 20), stat(10, 12), stat(21, 22)
        )
        self.assertLess(result["max"], 0)
        result = report.corner_range(
            report.share, stat(10, 12), stat(18, 20), stat(21, 22)
        )
        self.assertGreater(result["min"], 100)

    def test_interaction_uses_one_rfc_and_linux_per_corner(self):
        args = [stat(0, 0), stat(10, 10), stat(5, 5), *[stat(1, 1)] * 4]
        self.assertEqual(report.corner_range(report.interaction, *args)["median"], 10)

    def test_frozen_threshold_and_missing_samples(self):
        self.assertEqual(
            report.A.gap_verdict("goodput_bps", stat(8, 11), stat(10, 12), 1), "no gap"
        )
        self.assertEqual(
            report.A.gap_verdict("goodput_bps", stat(8, 9), dict(stat(11, 12), n=4), 1),
            "n/a",
        )

    def test_rfc_variants_and_unmodified_kernel(self):
        refs = audit.profiles()
        plan = audit.matrix.load_plan(audit.HERE / "plan.toml")
        for spec in audit.matrix.expand_plan(plan):
            m = {**spec, "gso_ipv4_max_size": 65536}
            if m["impl"] == "utcp":
                extra = spec.get("stack_set", [])
                m["stack_set"] = audit.verify_profile_trace.BASE_SETS + extra
                expected = audit.settings(m, spec, refs)
                self.assertEqual(expected["cc"], "newreno")
                self.assertEqual(
                    expected["rack_tlp"], "true" if m["algo"] == "compat" else "false"
                )
                if m["algo"] == "rfc-all":
                    self.assertEqual(len(extra), 5)
                mutated = copy.deepcopy(m)
                mutated["stack_set"].append("rack_tlp=true")
                with self.assertRaises(AssertionError):
                    audit.settings(mutated, spec, refs)
            else:
                self.assertIsNone(audit.settings(m, spec, refs))
                with self.assertRaises(AssertionError):
                    audit.settings(dict(m, stack_set=["initial_cwnd=10"]), spec, refs)


if __name__ == "__main__":
    unittest.main()
