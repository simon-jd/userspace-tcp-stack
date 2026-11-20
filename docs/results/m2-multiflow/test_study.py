"""Offline study fixtures. All timestamps are monotonic nanoseconds."""

import copy
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import study as S

N = S.A.NS


def flow(i, accept, connect, seconds, slope):
    return dict(
        id=f"f{i}",
        accept_ns=int(accept * N),
        connect_ns=int(connect * N),
        duration_s=seconds,
        release_ns=int((connect - 0.01) * N),
        series=[
            (int(accept * N) + tick * N // 10, tick * slope // 10)
            for tick in range(10 * (seconds + 2) + 1)
        ],
    )


class Windows(unittest.TestCase):
    def test_hand_window(self):
        # 100, 300 bytes/s => Jain 0.8. Last writer stops at 59.875.
        f = [flow(0, 0, -0.125, 60, 100), flow(1, 20.25, 20.125, 40, 300)]
        r, rows = S.windows(f, 60, 3200)
        self.assertEqual(
            (r["nominal_end_ns"], r["active_end_ns"], r["fair_start_ns"]),
            (60 * N, int(59.875 * N), int(40.25 * N)),
        )
        self.assertEqual([x["warm_start_ns"] for x in rows], [5 * N, int(25.25 * N)])
        self.assertEqual([x["goodput_bps"] for x in rows], [800, 2400])
        self.assertEqual((r["jain_nominal"], r["jain_active"]), (0.8, 0.8))
        self.assertEqual(r["convergence_status"], "right-censored")
        self.assertIsNone(r["convergence_s"])
        self.assertEqual(r["observed_horizon_s"], 39.625)

    def test_boundary_and_capacity(self):
        f = [flow(0, 0, 0, 60, 100), flow(1, 20, 20, 40, 100)]
        self.assertEqual(S.windows(f, 60, 1600)[0]["convergence_s"], 1)
        self.assertEqual(
            S.windows(f, 60, 3200)[0]["convergence_status"], "right-censored"
        )
        self.assertEqual(
            S.windows(f, 60, None)[0]["convergence_status"], "unobserved-calibration"
        )
        f[1]["series"] = [p for p in f[1]["series"] if p[0] < 60 * N]
        with self.assertRaisesRegex(ValueError, "bracket"):
            S.windows(f, 60, 1600)

    def test_late_start_without_artificial_zero(self):
        f = [flow(0, 0, 0, 60, 100), flow(1, 20, 20, 40, 100)]
        f[-1]["series"].pop(0)
        run, _ = S.windows(f, 60, 1600)
        self.assertAlmostEqual(run["convergence_s"], 1.1)
        self.assertEqual(run["unbracketed_initial_checks"], 1)

    def test_missing_data_can_hide_convergence(self):
        f = [flow(0, 0, 0, 60, 100), flow(1, 20, 20, 40, 100)]
        f[-1]["series"] = f[-1]["series"][20:]
        with self.assertRaisesRegex(ValueError, "initial receiver"):
            S.windows(f, 60, 1600)

    def test_real_median(self):
        rows = [
            dict(rep=i, aggregate_active_bps=x, run=f"physical-{i}")
            for i, x in enumerate([100, 300, 300, 100, 950], 1)
        ]
        self.assertEqual(S.overlay_run(rows)["run"], "physical-2")
        with self.assertRaises(ValueError):
            S.overlay_run(rows[:4])


class MissingIntervals(unittest.TestCase):
    def test_blind_hold_is_unobserved(self):
        # A 12-second hole in both traces could conceal an event anywhere in it.
        flows = [flow(0, 0, 0, 60, 20), flow(1, 20, 20, 40, 20)]
        for f in flows:
            f["series"] = [p for p in f["series"] if not 25 * N < p[0] < 37 * N]
        run, _ = S.windows(flows, 60, 1600)
        self.assertEqual(run["convergence_status"], "unobserved-sampling")
        self.assertIsNone(run["convergence_s"])
        self.assertGreater(run["unknown_rate_checks"], 50)

    def test_blind_part_followed_by_real_hold(self):
        flows = [flow(0, 0, 0, 60, 100), flow(1, 20, 20, 40, 100)]
        for f in flows:
            f["series"] = [
                p for p in f["series"] if p[0] == 25 * N or not 21 * N < p[0] < 32 * N
            ]
        run, _ = S.windows(flows, 60, 1600)
        self.assertEqual(run["convergence_status"], "converged")
        self.assertEqual(run["earliest_possible_s"], 1)
        self.assertEqual(run["convergence_s"], 13)

    def test_one_observed_violator_excludes_hold_in_blind_period(self):
        flows = [flow(0, 0, 0, 60, 20), flow(1, 20, 20, 40, 100)]
        flows[1]["series"] = [
            p for p in flows[1]["series"] if not 25 * N < p[0] < 37 * N
        ]
        run, _ = S.windows(flows, 60, 1600)
        self.assertEqual(run["convergence_status"], "right-censored")
        self.assertEqual(run["unknown_rate_checks"], 0)

    def test_hold_requires_51_points(self):
        ss = [[(k * N // 10, k * 10) for k in range(71)]] * 2
        with self.assertRaisesRegex(ValueError, "insufficient horizon"):
            S.convergence_result(ss, 0, 6 * N - 1, 1600)
        self.assertEqual(S.convergence_result(ss, 0, 6 * N, 1600)["convergence_s"], 1)


class PhysicalIdentity(unittest.TestCase):
    def setUp(self):
        self.fs = [
            dict(
                id=f"f{i}",
                source_ip=f"198.18.{i}.2",
                port=5201 + i,
                destination_ip="198.19.12.5",
                bytes=100 + i,
            )
            for i in range(2)
        ]
        rows = [
            dict(
                src=f["source_ip"],
                sport=40000,
                dst=f["destination_ip"],
                dport=f["port"],
                isn=4,
                data_segments=5,
                retrans_segments=1,
                stream_bytes=f["bytes"],
            )
            for f in self.fs
        ]
        self.cap = {
            name: dict(
                records=10,
                captured=10,
                filtered=10,
                dropped=0,
                tuples=copy.deepcopy(rows),
            )
            for name in ("r1-in", "r2-out")
        }

    def test_shared_ephemeral_different_tuples(self):
        self.assertEqual(len(S.wire_check(self.cap, self.fs)), 2)

    def test_swapped_sources_missing_and_changed_bytes(self):
        for kind in ("ip", "payload", "missing", "isn"):
            cap = copy.deepcopy(self.cap)
            rows = cap["r2-out"]["tuples"]
            if kind == "ip":
                rows[0]["src"], rows[1]["src"] = rows[1]["src"], rows[0]["src"]
            elif kind == "payload":
                rows[1]["stream_bytes"] += 1
            elif kind == "missing":
                rows.pop()
            else:
                rows[0]["isn"] += 1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                S.wire_check(cap, self.fs)

    def test_incomplete_capture_can_still_establish_identity(self):
        self.cap["r2-out"].update(filtered=13, dropped=3)
        self.assertEqual(len(S.wire_check(self.cap, self.fs)), 2)


class LatenessExposure(unittest.TestCase):
    def test_reopens_histogram_count_bucket_ceiling_and_clamped_max(self):
        st = {
            "loop_lateness_bucket_4": 98,
            "loop_lateness_bucket_5": 2,
            "loop_lateness_count": 100,
            "loop_lateness_max_ns": 29,
        }
        end = {"lateness_count": 100, "lateness_p99_ns": 29, "lateness_max_ns": 29}
        self.assertEqual(
            S.lateness_evidence(st, end)["lateness_histogram"], {4: 98, 5: 2}
        )
        for field, value in [
            ("lateness_count", 101),
            ("lateness_p99_ns", 28),
            ("lateness_max_ns", 30),
        ]:
            with self.assertRaisesRegex(ValueError, "disagree"):
                S.lateness_evidence(st, {**end, field: value})


class RoleReports(unittest.TestCase):
    def build(self):
        rows = []
        for side in ("test", "baseline"):
            for rep in range(1, 6):
                rows.append(
                    dict(
                        rep=rep,
                        side=side,
                        scenario=1,
                        reuse_key="x",
                        run=f"{side}-{rep}",
                        flags=["foreign_cpu"] if rep == 4 else [],
                        convergence_status="converged"
                        if rep == 3
                        else "right-censored",
                        observed_horizon_s=40,
                        convergence_s=3 if rep == 3 else None,
                        jain_nominal=0.8 if side == "baseline" else 0.9,
                        jain_active=0.85,
                        aggregate_active_bps=[15, 14, 12, 13, 11][rep - 1],
                        flows=[
                            dict(
                                id="f0",
                                port=5201,
                                backend="stack" if side == "test" else "linux",
                                cc="cubic",
                                goodput_bps=(200 if side == "test" else 100) + rep,
                            )
                        ],
                    )
                )
        return rows

    def test_pairing_flags_censoring_and_selected_observations(self):
        import study_tables as T

        rows = self.build()
        r, roles, sel = T.aggregate(1, rows, 0)
        self.assertEqual(r["test_converged"], 1)
        self.assertEqual(r["test_conditional_convergence_s_n"], 1)
        self.assertEqual(r["test_censored_horizons_s"], [40] * 4)
        self.assertEqual(r["test_flagged_runs"], ["test-4"])
        self.assertEqual(roles[0]["goodput_gap"], "gap")
        self.assertEqual(roles[0]["test_goodput_bps_median"], 203)
        self.assertEqual([x["rep"] for x in sel], [4, 4])
        self.assertTrue(r["jain_nominal_difference_gt_0.05"])
        self.assertEqual(T.aggregate(1, rows, 4)[0]["status"], "invalid")
        self.assertEqual(T.aggregate(1, rows[:-1], 0)[0]["status"], "incomplete")
        rows[-1]["flows"][0]["cc"] = "bbr"
        with self.assertRaisesRegex(ValueError, "role"):
            T.aggregate(1, rows, 0)

    def test_exact_jain_threshold(self):
        import study_tables as T

        rows = self.build()
        for r in rows:
            r["jain_nominal"] = 0.9 if r["side"] == "test" else 0.85
        self.assertFalse(T.aggregate(1, rows, 0)[0]["jain_nominal_difference_gt_0.05"])
        for r in rows:
            if r["side"] == "test":
                r["jain_nominal"] += 1e-10
        self.assertTrue(T.aggregate(1, rows, 0)[0]["jain_nominal_difference_gt_0.05"])

    def test_written_report_names_real_selection_and_conditional_count(self):
        import tempfile
        from study_report import report
        import study_tables as T

        rows = self.build()
        scenario, roles, choices = T.aggregate(1, rows, 0)
        with tempfile.TemporaryDirectory() as dest:
            report(Path(dest), [scenario], roles, choices, [])
            text = (Path(dest) / "tables.md").read_text()
        self.assertIn("test-4", text)
        self.assertIn("baseline-4", text)
        self.assertIn("1/5", text)
        self.assertIn("203", str(roles[0]["test_goodput_bps_median"]))


class PairInventory(unittest.TestCase):
    def test_complete_retry_does_not_inherit_interrupted_partner(self):
        import json
        import tempfile
        from unittest import mock
        import study_tables as T

        sched = {1: dict(side_first="baseline", rep="2", scenario="1")}
        with tempfile.TemporaryDirectory() as dest:
            root = Path(dest)
            for i, (name, sealed) in enumerate(
                [
                    ("p001-a01-baseline", True),
                    ("p001-a02-baseline", True),
                    ("p001-a02-test", True),
                ]
            ):
                rd = root / name
                rd.mkdir()
                (rd / "meta.json").write_text(
                    json.dumps(
                        dict(
                            start_utc=f"2026-01-01T00:{i:02}:00+00:00",
                            end_utc=f"2026-01-01T00:{i:02}:20+00:00",
                        )
                    )
                )
                (rd / "summary.json").write_text('{"valid":true}')
                (rd / "qualification.json").write_text(
                    json.dumps(
                        dict(
                            name=name,
                            summary_sha256=S.sha(rd / "summary.json"),
                            valid=sealed,
                            reuse_key="K",
                        )
                    )
                )

            def observed(rd, *args):
                return dict(
                    run=rd.name,
                    valid=True,
                    reuse_key="K",
                    pair_seed=44,
                    boot_id="B",
                    slot=0,
                )

            with mock.patch.object(S, "verdict", side_effect=observed):
                rows, errors = T.chronology(root, sched, None)
                self.assertEqual(
                    [r["run"] for r in rows if r["counted"]],
                    ["p001-a02-baseline", "p001-a02-test"],
                )
                self.assertEqual(errors[1], 1)
                p = root / "p001-a02-test" / "meta.json"
                x = json.loads(p.read_text())
                x["start_utc"] = "2025-12-31T23:59:00+00:00"
                p.write_text(json.dumps(x))
                with self.assertRaisesRegex(ValueError, "order"):
                    T.chronology(root, sched, None)


class CalibratedCapacity(unittest.TestCase):
    def test_identical_but_subcapacity_rates_never_converge(self):
        fs = [flow(0, 0, 0, 60, 3_750_000), flow(1, 20, 20, 40, 3_750_000)]
        self.assertEqual(
            S.windows(fs, 60, 100e6)[0]["convergence_status"], "right-censored"
        )
        self.assertEqual(S.windows(fs, 60, 60e6)[0]["convergence_s"], 1)

    def test_wrong_key_and_slot_rejected(self):
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as name:
            p = Path(name)
            (p / "gate.json").write_text(json.dumps(dict(slot=0, reuse_keys=["abc"])))
            for slot, key in [(1, "abc"), (0, "wrong")]:
                with self.assertRaisesRegex(ValueError, "calibration gate"):
                    S.calibration(p, key, slot, 100, 20)


if __name__ == "__main__":
    unittest.main()
