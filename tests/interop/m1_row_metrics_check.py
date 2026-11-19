"""M1 bulk measurements use the endpoint's integer microseconds and bit rate."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from m1_row import bulk_metrics


class BulkMetrics(unittest.TestCase):
    def test_rate_and_elapsed_time_quantization(self):
        # 1,000 bytes over 10,999 ns. Both published fields truncate.
        rate = int(1000 * 8e9 / 10999)
        self.assertEqual(bulk_metrics(dict(bytes=1000, duration_us=10, goodput_bps=rate)), (10, rate))

    def test_unavailable_and_inconsistent(self):
        valid = dict(bytes=1000, duration_us=1000, goodput_bps=8000000)
        for bad in (None, 0, -1, float("nan"), float("inf")):
            with self.subTest(value=bad):
                self.assertEqual(bulk_metrics(dict(valid, duration_us=bad)), (None, None))
                self.assertIsNone(bulk_metrics(dict(valid, goodput_bps=bad))[1])
        self.assertEqual(bulk_metrics(dict(valid, goodput_bps=20000000)), (None, None))
        self.assertEqual(bulk_metrics({"duration_us": 1000}), (1000, None))


if __name__ == "__main__":
    unittest.main()
