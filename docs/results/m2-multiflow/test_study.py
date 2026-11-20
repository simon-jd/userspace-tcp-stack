"""Offline study fixtures. All timestamps are monotonic nanoseconds."""
import copy
import unittest

import study as S

N = S.A.NS


def flow(i, accept, connect, seconds, slope):
    return dict(id=f"f{i}", accept_ns=int(accept*N), connect_ns=int(connect*N),
                duration_s=seconds, release_ns=int((connect - 0.01)*N),
                series=[(int(accept*N) + tick*N//10, tick*slope//10)
                        for tick in range(10*(seconds+2)+1)])


class Windows(unittest.TestCase):
    def test_hand_window(self):
        # 100, 300 bytes/s => Jain 0.8. Last writer stops at 59.875.
        f = [flow(0, 0, -.125, 60, 100), flow(1, 20.25, 20.125, 40, 300)]
        r, rows = S.windows(f, 60, 3200)
        self.assertEqual((r["nominal_end_ns"], r["active_end_ns"], r["fair_start_ns"]),
                         (60*N, int(59.875*N), int(40.25*N)))
        self.assertEqual([x["warm_start_ns"] for x in rows], [5*N, int(25.25*N)])
        self.assertEqual([x["goodput_bps"] for x in rows], [800, 2400])
        self.assertEqual((r["jain_nominal"], r["jain_active"]), (.8, .8))
        self.assertEqual(r["convergence_status"], "right-censored")
        self.assertIsNone(r["convergence_s"])
        self.assertEqual(r["observed_horizon_s"], 39.625)

    def test_boundary_and_capacity(self):
        f = [flow(0, 0, 0, 60, 100), flow(1, 20, 20, 40, 100)]
        self.assertEqual(S.windows(f, 60, 1600)[0]["convergence_s"], 1)
        self.assertEqual(S.windows(f, 60, 3200)[0]["convergence_status"], "right-censored")
        self.assertEqual(S.windows(f, 60, None)[0]["convergence_status"], "unobserved-calibration")
        f[1]["series"] = [p for p in f[1]["series"] if p[0] < 60*N]
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
        rows = [dict(rep=i,aggregate_active_bps=x,run=f"physical-{i}")
                for i,x in enumerate([100,300,300,100,950],1)]
        self.assertEqual(S.overlay_run(rows)["run"], "physical-2")
        with self.assertRaises(ValueError):
            S.overlay_run(rows[:4])


if __name__ == "__main__":
    unittest.main()

