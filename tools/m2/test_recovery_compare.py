"""Functional full-episode controls for the M2 recovery comparison."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import recovery_compare as C


class DirectedRecovery(unittest.TestCase):
    def test_actual_offset_sack_wrap(self):
        isn = 0xfffffff0
        opt = b"\x01\x01\x05\x0a" + struct.pack(">II", 0xfffffff8, 0x15)
        self.assertEqual(C.sack_blocks(opt, isn), [[7, 36]])
        with self.assertRaises(ValueError):
            C.sack_blocks(opt[:-1], isn)

    def test_hole_repair_and_ack_order(self):
        # (time, type, offset, length/SACK) on r1's sender-facing interface.
        rows = [(10, "tx", 0, 100), (11, "tx", 100, 100), (12, "tx", 200, 100),
                (20, "ack", 100, [[200, 300]]), (21, "tx", 100, 60),
                (22, "tx", 160, 40), (23, "tx", 300, 100), (30, "ack", 300, [])]
        e = C.wire_episode(rows, [100], 400)
        self.assertEqual(e["repair_ns"], 21)
        self.assertEqual(e["recovery_ack_ns"], 30)
        self.assertEqual(e["high_at_repair"], 300)
        group = next(a for a in e["ack_groups"] if a["t_ns"] == 20)
        self.assertEqual([(x["off"], x["copy"], x["repeat_bytes"]) for x in group["tx"]],
                         [(100, 2, 60), (160, 1, 40), (300, 1, 0)])

    def test_tail_rejects_not_last_two_and_burst_rejects_gap(self):
        originals = [(0, 1448), (1448, 1448), (2896, 217), (3113, 1448), (4561, 50)]
        self.assertTrue(C.valid_targets("tail", [3113, 4561], originals, 4611))
        self.assertFalse(C.valid_targets("tail", [2896, 3113], originals, 4611))
        self.assertFalse(C.valid_targets("burst", [0, 1448, 2896, 3200, 4561], originals, 4611))

    def test_phase_uses_bracketing_samples(self):
        def s(t, w, th, ca="open"):
            return {"t": t, "cwnd": w, "ssthresh": th, "ca_state": ca}
        # Typical Linux first sample, including its initial large ssthresh.
        self.assertEqual(C.bracket_phase([s(10, 10, 2147483647), s(20, 20, 2147483647)], 14)["phase"], "slow")
        self.assertEqual(C.bracket_phase([s(10, 20, 20), s(20, 20, 20)], 14)["phase"], "avoidance")
        self.assertEqual(C.bracket_phase([s(10, 10, 20), s(20, 20, 20)], 14)["phase"], "unresolved")
        self.assertEqual(C.bracket_phase([s(10, 10, 20), s(20, 10, 100, "loss")], 14)["phase"], "unresolved")

    def test_state_duration_is_bounded_by_observations(self):
        rows = [{"t": t, "ca_state": ca, "cwnd": 10} for t, ca in
                ((0, "open"), (10, "open"), (20, "recovery"), (30, "loss"), (40, "open"))]
        obs = C.state_interval(rows, 13, 40, 1)
        self.assertEqual(obs["entry_bracket_ns"], [13, 20])
        self.assertEqual(obs["exit_bracket_ns"], [30, 40])
        self.assertEqual(obs["duration_rtts"], [0.01, 0.027])
        self.assertIsNone(C.state_interval([rows[0], rows[-1]], 13, 40, 1)["duration_rtts"])
        self.assertIsNone(C.state_interval(rows[:-1], 13, 35, 1)["duration_rtts"])

    def test_tail_probe_before_first_hole_repair(self):
        rows = [(1, "tx", 0, 100), (2, "tx", 100, 100), (3, "tx", 200, 50),
                (4, "ack", 100, []), (5, "tx", 200, 50), (6, "ack", 100, [[200, 250]]),
                (7, "tx", 100, 100), (8, "ack", 250, [])]
        e = C.wire_episode(rows, [100, 200], 250)
        self.assertEqual((e["drop_ns"], e["repair_ns"], e["recovery_ack_ns"]), (2, 5, 8))

    def test_complete_paired_plan(self):
        p = list(C.plan("smoke/wire", C.CASES, C.CCS, C.IMPLS, [1, 2]))
        self.assertEqual(len({name for name, _ in p}), 40)
        self.assertTrue(all(spec["extra_capture"] and spec["profile"] == "linux" for _, spec in p))
        self.assertTrue(all(spec["bytes"] == 100000 for _, spec in p if spec["case"] == "tail"))
        self.assertTrue(all(spec["stack_args"] == "--trace-kinds ack,tx,rto" for _, spec in p))
        with self.assertRaises(ValueError):
            list(C.plan("../bad", C.CASES, C.CCS, C.IMPLS, [1]))

if __name__ == "__main__":
    unittest.main()
