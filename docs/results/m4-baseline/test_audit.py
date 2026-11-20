import unittest

from audit import overlap_cpu, replay_endpoint


class AuditTest(unittest.TestCase):
    def test_separate_endpoint_receipt(self):
        app = {"ev": "summary", "ok": True, "role": "receiver", "backend": "kernel",
               "cc": "cubic", "bytes": 1_000_000_000, "sha256": "a" * 64,
               "duration_us": 1_000_000, "goodput_bps": 8_000_000_000,
               "total_retrans": 2}
        usage = {"argv": ["/bin/kernel"], "affinity": [10], "status": 0,
                 "timed_out": False, "user_s": 0.69, "sys_s": 0.31}
        row = replay_endpoint(app, usage, "receiver", "kernel", 10, "/bin/kernel",
                              1_000_000_000, "a" * 64)
        self.assertEqual(row["total_s_per_gb"], 1.0)
        self.assertEqual(row["total_retrans"], 2)
        usage["argv"] = ["/bin/stack"]
        with self.assertRaises(ValueError):
            replay_endpoint(app, usage, "receiver", "kernel", 10, "/bin/kernel",
                            1_000_000_000, "a" * 64)

    def test_host_remainder_keeps_interrupt_time_distinct(self):
        a = {"stat": "cpu8 0 0 0 0 0 0 0 0\n", "softirqs": ""}
        b = {"stat": "cpu8 5 0 5 10 0 2 3 0\n", "softirqs": ""}
        row = overlap_cpu(a, b, [8], 80_000, 100)
        self.assertAlmostEqual(row["slot_nonirq_remainder_pct"], 8.0)
        self.assertAlmostEqual(row["slot_irq_inclusive_remainder_pct"], 28.0)


if __name__ == "__main__":
    unittest.main()
