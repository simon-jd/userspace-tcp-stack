"""Negative controls for the full-profile and shared-reference attribution rules."""

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit
import report


def stat(lo, hi):
    return {"min": lo, "max": hi, "median": (lo + hi) / 2, "n": 5}


class AblationTests(unittest.TestCase):
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
