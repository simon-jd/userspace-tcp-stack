import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from model import measure, schedule
from run import ethernet_settings, functional_pair, tun_features


def endpoint(role, backend, cpu):
    return {
        "summary": {
            "ev": "summary", "role": role, "backend": backend, "cc": "cubic",
            "ok": True, "bytes": 2_000_000_000, "sha256": "a" * 64,
            "duration_us": 2_000_000, "goodput_bps": 8_000_000_000,
            "total_retrans": 0, "bytes_retrans": 0,
        },
        "usage": {"status": 0, "timed_out": False, "user_s": 0.5,
                  "sys_s": 0.25, "affinity": [cpu]},
    }


class ModelTest(unittest.TestCase):
    def test_schedule_alternates_control_and_direction(self):
        first, second = schedule(2, "stack")[:4], schedule(2, "stack")[4:]
        self.assertEqual(first, [
            (1, "dut-to-peer", "kernel"), (1, "dut-to-peer", "stack"),
            (1, "peer-to-dut", "kernel"), (1, "peer-to-dut", "stack"),
        ])
        self.assertEqual(second, [
            (2, "peer-to-dut", "stack"), (2, "peer-to-dut", "kernel"),
            (2, "dut-to-peer", "stack"), (2, "dut-to-peer", "kernel"),
        ])
        self.assertEqual(len(schedule(5, "tcpv4", "checksum")), 30)

    def test_cpu_and_goodput_are_receiver_normalized(self):
        sender, receiver = endpoint("sender", "utcp", 8), endpoint("receiver", "kernel", 10)
        sender["summary"]["duration_us"] = 3_000_000
        sender["summary"]["goodput_bps"] = 5_333_333_333
        result = measure(sender, receiver, 2_000_000_000, "a" * 64, ("utcp", "kernel"), (8, 10))
        self.assertEqual(result["receiver_gbps"], 8)
        self.assertEqual(result["send_user_s_per_gb"], 0.25)
        self.assertEqual(result["send_sys_s_per_gb"], 0.125)
        self.assertEqual(result["recv_total_s_per_gb"], 0.375)

    def test_rejects_corrupt_or_mismatched_process_evidence(self):
        for target, key, value in [
            ("summary", "bytes", 1), ("summary", "sha256", "b" * 64),
            ("summary", "ok", False), ("summary", "role", "receiver"),
            ("summary", "backend", "kernel"), ("summary", "cc", "reno"),
            ("summary", "duration_us", 0), ("usage", "status", 9),
            ("usage", "affinity", [9]), ("usage", "timed_out", True),
            ("usage", "user_s", math.inf), ("usage", "sys_s", -1),
        ]:
            with self.subTest(target=target, key=key):
                sender, receiver = endpoint("sender", "utcp", 8), endpoint("receiver", "kernel", 10)
                sender[target][key] = value
                with self.assertRaises(ValueError):
                    measure(sender, receiver, 2_000_000_000, "a" * 64, ("utcp", "kernel"), (8, 10))


class TopologyTest(unittest.TestCase):
    def test_functional_pair_requires_two_distinct_e_cores(self):
        self.assertEqual(functional_pair("16,18"), (16, 18))
        for spec in ("8,10", "16,16", "31,32", "16", "16,17,18"):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                functional_pair(spec)

    def test_aggregation_uses_same_tso_and_gso_policy_on_both_endpoints(self):
        self.assertEqual(list(ethernet_settings(False).values()), ["off", "off", "off"])
        self.assertEqual(list(ethernet_settings(True).values()), ["on", "on", "off"])

    def test_tun_flags_keep_matching_ioctl_mode(self):
        self.assertEqual(tun_features(0x1801), [])
        self.assertEqual(tun_features(0x5801), ["vnet_hdr"])
        self.assertEqual(tun_features(0x1901), ["multi_queue"])
        self.assertEqual(tun_features(0x5901), ["vnet_hdr", "multi_queue"])


class EndpointTest(unittest.TestCase):
    def run_endpoint(self, *arguments):
        with tempfile.TemporaryDirectory() as path:
            proc = subprocess.run([
                sys.executable, str(Path(__file__).with_name("endpoint.py")),
                path, "send", *arguments,
            ], check=False)
            prefix = Path(path)
            return (proc.returncode, json.loads((prefix / "send.usage.json").read_text()),
                    (prefix / "send.stdout").read_text())

    def test_wait4_reports_exact_process_and_affinity(self):
        status, usage, stdout = self.run_endpoint("3", sys.executable, "-c",
            "import os, time; print(os.getpid()); end = time.process_time() + .05\n"
            "while time.process_time() < end: pass")
        self.assertEqual(status, 0)
        self.assertEqual(usage["pid"], int(stdout))
        self.assertGreaterEqual(usage["user_s"] + usage["sys_s"], 0.05)
        self.assertFalse(usage["timed_out"])
        self.assertTrue(usage["affinity"])

    def test_timed_out_child_keeps_a_receipt(self):
        status, usage, _ = self.run_endpoint(
            "0.1", sys.executable, "-c", "import time; time.sleep(5)")
        self.assertNotEqual(status, 0)
        self.assertTrue(usage["timed_out"])
        self.assertLess(usage["status"], 0)


if __name__ == "__main__":
    unittest.main()
