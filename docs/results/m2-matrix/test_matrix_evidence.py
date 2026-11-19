"""Targeted regressions for an enabled trace sink emitting zero filtered events and for gap boundaries."""

import gzip
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit
import loss_replay as loss
import report


class FilteredTrace(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.path = Path(scratch.name) / "trace.jsonl"
        self.path.touch()
        self.sender_rows = [
            dict(ev="sample", role="sender", t=t, total_retrans=0, bytes_retrans=0)
            for t in (1, 10, 15)
        ]
        self.sender_rows.append(dict(ev="summary", role="sender", total_retrans=0))
        self.path.with_name("snd.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in self.sender_rows)
        )
        self.meta = {"trace": True, "rcv_ip": "198.19.12.5"}
        self.stats = dict(
            trace_events=0, trace_blocks=1, **dict.fromkeys(audit.ELIGIBLE_COUNTERS, 0)
        )
        self.summary = dict(
            capture={"r1-in": {"retrans_segs": 0}},
            trace_events=0,
            sender_counters=dict.fromkeys(audit.ELIGIBLE_COUNTERS, 0),
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

    def test_empty_trace_contradicts_ingress_capture(self):
        self.summary["capture"]["r1-in"]["retrans_segs"] = 1
        with self.assertRaises(AssertionError):
            self.check()

    def test_empty_trace_rejects_lifetime_socket_contradictions(self):
        for index, key in (
            (0, "total_retrans"),
            (2, "bytes_retrans"),
            (3, "total_retrans"),
        ):
            with self.subTest(index=index, key=key):
                rows = [dict(row) for row in self.sender_rows]
                rows[index][key] = 1
                self.path.with_name("snd.jsonl").write_text(
                    "".join(json.dumps(row) + "\n" for row in rows)
                )
                with self.assertRaisesRegex(AssertionError, "lifetime sender"):
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


class LossWire(unittest.TestCase):
    def test_sequence_high_wrap_overlap_and_repeat(self):
        self.assertEqual(loss.advance(0xFFFFFFF0, 0xFFFFFFF0, 32), (16, 32))
        self.assertEqual(loss.advance(16, 0xFFFFFFF0, 32), (16, 0))
        self.assertEqual(loss.advance(16, 8, 16), (24, 8))

    def test_transition_bounds_never_imply_continuous_loss(self):
        records = [
            dict(t=t, ca_state=state)
            for t, state in (
                (10, "open"),
                (20, "loss"),
                (30, "loss"),
                (40, "open"),
                (50, "loss"),
                (60, "open"),
            )
        ]
        spans = loss.sample_spans(records)
        starts = [r["first_loss_ns"] for r in spans]
        self.assertEqual(loss.locate(spans, starts, 12), (0, "leading boundary"))
        self.assertEqual(loss.locate(spans, starts, 25), (0, "interior"))
        self.assertEqual(loss.locate(spans, starts, 32), (0, "trailing boundary"))
        self.assertEqual(loss.locate(spans, starts, 40), (None, None))
        self.assertEqual(loss.locate(spans, starts, 50), (1, "isolated sample"))

    def test_full_report_distinguishes_previous_data_and_phase(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            rd = root / "campaign/fixture"
            rd.mkdir(parents=True)
            inputs = root / "inputs"
            inputs.mkdir()
            offset = 100 * 10**9
            t0 = 10**9
            lo = t0 + 5 * 10**9
            sender = [dict(ev="clock", monotonic_ns=t0, realtime_ns=t0 + offset)]
            for delta, state in (
                (-20, "open"),
                (-10, "loss"),
                (0, "loss"),
                (10, "loss"),
                (20, "open"),
            ):
                sender.append(dict(ev="sample", t=lo + delta * 10**6, ca_state=state))
            (rd / "snd.jsonl").write_text("".join(json.dumps(r) + "\n" for r in sender))
            (rd / "summary.json").write_text(
                json.dumps(dict(t0_ns=t0, window_end_ns=lo + 8 * 10**6))
            )
            source = dict(
                run="fixture",
                valid="1",
                counted="1",
                timeouts=2,
                spurious_rtos=0,
                capture_complete=1,
                capture_sha256="test",
                input="fixture.csv.gz",
                segments=5,
                status="captured",
            )
            audit.write_csv(inputs / "index.csv", loss.INDEX, [source])
            with gzip.open(inputs / source["input"], "wt") as fh:
                for dt, seq, length in (
                    (-21, 1, 100),
                    (-15, 101, 20),
                    (-5, 1, 100),
                    (5, 121, 25),
                    (15, 146, 20),
                ):
                    fh.write(f"{offset + lo + dt * 10**6},{seq},{length}\n")
            loss.report(root / "campaign", inputs, root / "result")
            spans = loss.rows(root / "result/kernel-loss-spans.csv")
            result = loss.rows(root / "result/kernel-rto-runs.csv")[0]
            self.assertEqual(
                (result["interior_new_segments"], result["boundary_new_segments"]),
                ("1", "2"),
            )
            self.assertTrue(
                any(
                    r["phase"] == "measurement"
                    and r["position"] == "interior"
                    and r["new_sequence_bytes"] == "25"
                    for r in spans
                )
            )
            self.assertTrue(
                any(
                    r["phase"] == "drain" and r["position"] == "trailing boundary"
                    for r in spans
                )
            )
            for r in sender:
                if r["ev"] == "sample":
                    r["ca_state"] = "open"
            (rd / "snd.jsonl").write_text("".join(json.dumps(r) + "\n" for r in sender))
            loss.report(root / "campaign", inputs, root / "no-sample")
            self.assertIn(
                "no sampled Loss",
                loss.rows(root / "no-sample/kernel-rto-runs.csv")[0]["summary"],
            )


class AttemptLedger(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.campaign = Path(scratch.name)
        self.planned = {}
        self.members = []
        for index, impl in enumerate(("utcp", "linux")):
            run = f"100-20-0.1-2-bbr-r0-{impl}"
            self.planned[run] = dict(
                run=run,
                seed=33,
                rep=0,
                group=0,
                in_group=index,
                cell="100-20-0.1-2",
                algo="bbr",
                impl=impl,
            )

    def path(self, spec, retry, archive):
        name = spec["run"] + (f"-rerun{retry}" if retry else "")
        if archive is None:
            return self.campaign / name
        return self.campaign / "aside" / f"{name}.{archive:08d}" / "raw"

    def pair(self, stamp, *, retry=0, archive=None, good=True, started=True):
        for name, spec in self.planned.items():
            side = spec["in_group"]
            d = self.path(spec, retry, archive)
            d.mkdir(parents=True)
            member = dict(
                spec, rerun=retry, run=name + (f"-rerun{retry}" if retry else "")
            )
            summary = dict(
                valid=good or not side,
                flags=["foreign_cpu"],
                invalid=[] if good or not side else ["missing terminal"],
            )
            (d / "meta.json").write_text(json.dumps(member))
            (d / "summary.json").write_text(json.dumps(summary))
            if started:
                t = stamp + side * 20
                records = [
                    dict(ev="start", t=t),
                    dict(ev="sample", t=t + 1, bytes_sent=9),
                ]
                if summary["valid"]:
                    records.append(dict(ev="summary", t=t + 2, bytes=9, ok=True))
                (d / "snd.jsonl").write_text(
                    "".join(json.dumps(x) + "\n" for x in records)
                )
            if archive is None:
                self.members.append((member, summary))

    def ledger(self):
        history = audit.preserved_attempts(self.campaign, self.planned)
        order = audit.attempts.timeline(
            self.campaign, {("100-20-0.1-2", "bbr"): self.members}, history
        )
        _, ledger = audit.attempts.qualify(
            self.members, history, audit.checkpoint.independently_count, order
        )
        return history, ledger

    def test_preserved_failed_pairs_count_even_when_later_same_id_succeeds(self):
        for i in range(3):
            self.pair(100 * i, archive=i, good=False)
        self.pair(500)
        history, ledger = self.ledger()
        self.assertEqual((len(ledger["bad_pairs"]), ledger["counted_pairs"]), (3, 1))
        self.assertTrue(all("foreign_cpu" in h["flags"] for h in history))
        self.pair(300, archive=3, good=False)
        _, ledger = self.ledger()
        self.assertEqual(
            (ledger["status"], len(ledger["bad_pairs"]), ledger["counted_pairs"]),
            ("invalid (rerun cap)", 4, 0),
        )

    def test_shape_only_nested_raw_retains_decimal_cell_and_seed(self):
        spec = next(iter(self.planned.values()))
        d = self.path(spec, 0, 12)
        d.mkdir(parents=True)
        (d / "shape.txt").write_text("setup\n")
        (d / "pre").mkdir()
        (d / "pre/record.txt").touch()
        (h,), ledger = self.ledger()
        self.assertEqual((h["run"], h["group"], h["seed"]), (spec["run"], 0, 33))
        self.assertEqual(h["physical"], "setup only; transfer unobserved")
        self.assertIn("pre/record.txt", h["available_inputs"])
        self.assertEqual(ledger["bad_pairs"], [])

    def test_rerun_requires_supported_invalid_predecessors(self):
        self.pair(200, retry=1)
        _, ledger = self.ledger()
        self.assertEqual(ledger["status"], "indeterminate (attempt association)")
        self.pair(100, good=False)
        _, ledger = self.ledger()
        self.assertEqual((ledger["counted_pairs"], len(ledger["bad_pairs"])), (1, 1))
        self.pair(300, retry=2)
        _, ledger = self.ledger()
        self.assertEqual(
            (ledger["status"], ledger["counted_pairs"]),
            ("indeterminate (attempt association)", 0),
        )

    def test_hole_and_outside_cap(self):
        self.pair(100, retry=4)
        _, ledger = self.ledger()
        self.assertEqual(
            (ledger["status"], ledger["counted_pairs"]), ("invalid (rerun cap)", 0)
        )

    def test_failed_summary_without_endpoint_activity_cannot_authorize_retry(self):
        self.pair(100, good=False, started=False)
        self.pair(200, retry=1)
        _, ledger = self.ledger()
        self.assertEqual(
            (ledger["status"], len(ledger["bad_pairs"]), ledger["counted_pairs"]),
            ("indeterminate (attempt association)", 0, 0),
        )

    def test_prior_completed_archived_pair_and_overlaps_are_unresolved(self):
        self.pair(100, archive=1)
        self.pair(200)
        _, ledger = self.ledger()
        self.assertEqual(ledger["counted_pairs"], 0)
        self.assertTrue(
            any("possibly valid" in msg for msg in ledger["association_issues"])
        )
        self.pair(101, archive=2, good=False)
        _, ledger = self.ledger()
        self.assertEqual(ledger["counted_pairs"], 0)
        self.assertTrue(any("overlap" in msg for msg in ledger["association_issues"]))

    def test_archive_rejects_path_meta_mismatch_and_survives_truncated_bytes(self):
        spec = next(iter(self.planned.values()))
        d = self.path(spec, 0, 1)
        d.mkdir(parents=True)
        (d / "snd.jsonl").write_bytes(b'{"ev":"sample","t":4,"bytes_sent":8}\n\xff{')
        (h,), ledger = self.ledger()
        self.assertTrue(h["malformed_endpoint"])
        self.assertEqual(
            (h["physical"], len(ledger["bad_pairs"])), ("payload observed", 1)
        )
        (d / "meta.json").write_text('{"run":"unregistered"}')
        with self.assertRaises(ValueError):
            self.ledger()


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
