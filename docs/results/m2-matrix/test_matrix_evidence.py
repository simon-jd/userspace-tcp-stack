"""Targeted regressions for an enabled trace sink emitting zero filtered events and for gap boundaries."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit
import report


class FilteredTrace(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.path = Path(scratch.name) / "trace.jsonl"
        self.path.touch()
        self.meta = {"trace": True, "rcv_ip": "198.19.12.5"}
        self.stats = dict(
            trace_events=0, trace_blocks=1, **dict.fromkeys(audit.ELIGIBLE_COUNTERS, 0)
        )
        self.summary = dict(
            trace_events=0, sender_counters=dict.fromkeys(audit.ELIGIBLE_COUNTERS, 0)
        )

    def check(self):
        return audit.verified_trace(self.path, self.meta, 7, self.stats, self.summary)

    def test_present_enabled_zero(self):
        self.assertEqual(self.check(), ({}, hashlib.sha256(b"").hexdigest()))

    def test_missing_or_disabled(self):
        self.meta["trace"] = False
        with self.assertRaises(AssertionError):
            self.check()
        self.meta["trace"] = True
        self.path.unlink()
        with self.assertRaises(AssertionError):
            self.check()

    def test_absent_sink_or_unallocated_buffer(self):
        del self.stats["trace_events"]
        with self.assertRaises(AssertionError):
            self.check()
        self.stats["trace_events"] = 0
        self.stats["trace_blocks"] = 0
        with self.assertRaises(AssertionError):
            self.check()

    def test_shorter_than_reported_or_different_count(self):
        self.stats["trace_events"] = 1
        with self.assertRaises(AssertionError):
            self.check()
        self.summary["trace_events"] = 1
        with self.assertRaises(ValueError):
            self.check()

    def test_bytes_with_zero_count(self):
        self.path.write_text("{}\n")
        with self.assertRaises(AssertionError):
            self.check()

    def test_empty_trace_contradicts_native_counter(self):
        for counter in audit.ELIGIBLE_COUNTERS:
            with self.subTest(counter=counter):
                self.stats[counter] = self.summary["sender_counters"][counter] = 1
                with self.assertRaises(AssertionError):
                    self.check()
                self.stats[counter] = self.summary["sender_counters"][counter] = 0

    def test_nonempty_trace_retains_connection_and_count_checks(self):
        event = dict(
            t=5,
            conn=7,
            ev="tx",
            tx="fast_rexmit",
            cwnd=9,
            tuple="198.18.0.2:34560>198.19.12.5:5201",
        )
        data = (json.dumps(event) + "\n").encode()
        self.path.write_bytes(data)
        self.stats["trace_events"] = self.summary["trace_events"] = 1
        self.assertEqual(self.check(), ({"tx": 1}, hashlib.sha256(data).hexdigest()))
        event["conn"] = 99
        self.path.write_text(json.dumps(event) + "\n")
        with self.assertRaises(ValueError):
            self.check()


class GapBoundaries(unittest.TestCase):
    def test_touching_sets_do_not_qualify(self):
        self.assertEqual(
            report.verdict("goodput_bps", [2, 3, 4, 5, 6], [1, 1, 1, 1, 2], 0), "no gap"
        )

    def test_submillisecond_and_exactly_one_millisecond(self):
        self.assertEqual(
            report.verdict("qdelay_p99_ms", [0.75] * 5, [0.25] * 5, 0),
            "gap (below resolution)",
        )
        self.assertEqual(
            report.verdict("qdelay_p50_ms", [1.25] * 5, [0.25] * 5, 0), "gap"
        )

    def test_retransmission_increase_only_and_loss_cutoffs(self):
        self.assertEqual(
            report.verdict("retrans_pct", [0.05] * 5, [0] * 5, 0.1), "no gap"
        )
        self.assertEqual(
            report.verdict("retrans_pct", [0.051] * 5, [0] * 5, 0.1), "gap"
        )
        self.assertEqual(
            report.verdict("retrans_pct", [0.15] * 5, [0] * 5, 1), "no gap"
        )
        self.assertEqual(report.verdict("retrans_pct", [0] * 5, [1] * 5, 1), "no gap")


if __name__ == "__main__":
    unittest.main()
