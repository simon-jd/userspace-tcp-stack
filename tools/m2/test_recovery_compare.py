"""Functional full-episode controls for the M2 recovery comparison."""
import hashlib
import json
import struct
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import recovery_compare as C
from test_analyze import ip_packet, pcap_records


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

    def test_record_order_at_both_boundaries(self):
        # µs timestamps can tie across multiple ACKs and data transmissions.
        rows = [(2, "tx", 0, 100), (3, "ack", 100, []), (4, "tx", 100, 100),
                (4, "ack", 100, []), (5, "tx", 200, 100), (6, "ack", 100, [[200, 300]]),
                (7, "tx", 100, 100), (8, "ack", 100, [[200, 300]]), (8, "ack", 300, []),
                (8, "tx", 300, 100)]
        groups = C.wire_episode(rows, [100], 400)["ack_groups"]
        self.assertEqual([(g["t_ns"], g["ack"], [p["off"] for p in g["tx"]]) for g in groups],
                         [(3, 100, [100]), (4, 100, [200]), (6, 100, [100]),
                          (8, 100, []), (8, 300, [])])

    def test_same_group_before_drop_and_after_closing_ack(self):
        rows = [(1, "tx", 0, 100), (1, "tx", 100, 100), (2, "ack", 100, []),
                (3, "tx", 100, 100), (4, "ack", 200, []), (4, "tx", 200, 100)]
        groups = C.wire_episode(rows, [100], 300)["ack_groups"]
        self.assertEqual([p["off"] for p in groups[0]["tx"]], [100])
        self.assertEqual(groups[-1]["tx"], [])

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


class SavedTail(unittest.TestCase):
    def test_cli_verifies_observed_copies_and_effective_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            rd = Path(tmp) / "tail-cubic-r1-utcp"
            rd.mkdir()
            def jsonl(name, items):
                (rd / name).write_text("".join(json.dumps(r) + "\n" for r in items))
            def analyze(expected):
                cmd = [sys.executable, "-I", C.__file__, "analyze", str(rd)]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                self.assertEqual(proc.returncode, expected, proc.stdout + proc.stderr)
                return json.loads(proc.stdout)
            _, meta = next(C.plan("fixture", ["tail"], ["cubic"], ["utcp"], [1]))
            meta.update(slot=2, timing=False, sender_exit=0, cpusets={s: "16-31" for s in C.IMPLS + ("r1","r2")},
                        rcv_ip="198.19.1.2", commit="source", bulk_sha256="binary")
            C.json_write(rd / "meta.json", meta)
            endpoint = dict(ev="summary", ok=True, bytes=100000, sha256="a" * 64, cc="cubic")
            state = dict(cwnd=10, ssthresh=100, ca="open")
            sample = dict(ev="sample", srtt_us=10, ca_state="open", bytes_acked=100001, cc_name="cubic", **state)
            sender = [dict(ev="clock", monotonic_ns=0, realtime_ns=0), dict(ev="config", **C.LINUX_RECOVERY_CONFIG),
                      dict(sample,t=0), dict(sample,t=1000), dict(endpoint,backend="utcp")]
            jsonl("snd.jsonl", sender)
            jsonl("rcv.jsonl", [dict(endpoint, backend="kernel")])
            sequence = [("syn",0,0), ("tx",0,50000), ("tx",50000,48464), ("ack",98464,0),
                        ("tx",98464,1448), ("tx",99912,88), ("tx",99912,88), ("ack",98464,0),
                        ("tx",98464,1448), ("ack",100000,0)]
            packets, trace = [], []
            for t, (kind, off, length) in enumerate(sequence, 1):
                ack = kind == "ack"
                seq = 0 if ack or kind == "syn" else 1 + off
                tcp = struct.pack(">HHIIBBHHH", 5201 if ack else 40000, 40000 if ack else 5201,
                                  seq, 1 + off if ack else 0, 0x50, 2 if kind == "syn" else 16, 100, 0, 0)
                src, dst = ("198.19.1.2", "198.19.1.1") if ack else ("198.19.1.1", "198.19.1.2")
                ip = bytearray(ip_packet(src, dst, 6, tcp + bytes(length)))
                struct.pack_into(">H", ip, 4, t)  # distinguish original and retry
                packets.append((t, ip))
                if kind == "tx":
                    trace.append(dict(ev=kind,t=t,seq=seq,len=length,tx="data",**state))
                if ack:
                    trace.append(dict(ev=kind,t=t,snd_una_off=off,**state))
            jsonl("trace.jsonl", trace)
            jsonl("stats.json", [dict.fromkeys(C.COUNTERS, 0)])
            (rd / "drop-r1.txt").write_text("counter packets 2 bytes 100 drop")
            (rd / "drop-r1.log").write_text("syn isn 0 armed 1.0 ms after it (nft rc 0)")
            capture = {}
            for name in ("r1-in", "r1-out", "r2-out"):
                observed = packets if name == "r1-in" else [p for p in packets if p[0] not in (5,6)]
                (rd / (name + ".pcap")).write_bytes(pcap_records(observed))
                capture[name] = dict(kernel_dropped=0, captured=len(observed), received_by_filter=len(observed))
            C.json_write(rd / "summary.json", dict(capture=capture,local_drops={},netem={"dropped":0},tbf={"dropped":0}))
            self.assertTrue(analyze(0)["valid"])
            config = sender[1]
            for value in ("rfc", None):
                config["cc_flavor"] = value
                if value is None:
                    del config["cc_flavor"]
                jsonl("snd.jsonl", sender)
                self.assertFalse(analyze(1)["checks"]["linux_config"])
            config["cc_flavor"] = "linux"
            sender[2]["cc_name"] = "newreno"
            jsonl("snd.jsonl", sender)
            self.assertFalse(analyze(1)["checks"]["sender_cc"])
            sender[2]["cc_name"] = "cubic"
            jsonl("snd.jsonl", sender)
            meta["case"] = "lost-retrans"
            C.json_write(rd / "meta.json", meta)
            self.assertFalse(analyze(1)["valid"])


class CampaignLedger(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        for name, spec in C.plan("fixture", C.CASES, C.CCS, C.IMPLS, (1, 2)):
            rd = self.base / name
            rd.mkdir()
            rows = [(1, "tx", 0, 100), (2, "tx", 100, 100), (3, "ack", 100, []),
                    (4, "tx", 100, 100), (6, "ack", 200, [])]
            if spec["impl"] == "linux":
                rows.insert(-1, (5, "ack", 100, []))  # One extra ACK triggers no send.
            episode = C.wire_episode(rows, [100], 200)
            groups = episode.pop("ack_groups")
            ledger = "".join(json.dumps(g) + "\n" for g in groups).encode()
            (rd / "recovery-acks.jsonl").write_bytes(ledger)
            result = {k: spec[k] for k in ("case", "cc", "rep", "impl")}
            result.update(run=name, valid=True, commit="source", bulk_sha256="binary", latched=[[100]],
                          counters={}, warmup=None, state_interval={}, stack_probe_rto_tx=[], undo_counters={},
                          srtt_before_drop_us=10, wire_rtts={"repair_ns": 1}, post_cwnd={"cwnd": 10},
                          ack_groups=len(groups), ledger_sha256=hashlib.sha256(ledger).hexdigest(), wire=episode)
            C.json_write(rd / "recovery.json", result)
        self.rd = self.base / "tail-cubic-r1-utcp"

    def report(self, status):
        cmd = [sys.executable, "-I", C.__file__, "report", str(self.base)]
        proc = subprocess.run(cmd, text=True, capture_output=True)
        self.assertEqual(proc.returncode, status, proc.stderr)
        report = json.loads((self.base / "recovery-pairs.json").read_text())
        self.assertEqual(report["complete"], status == 0)
        return next(p for p in report["pairs"] if p["runs"][0] == self.rd.name)

    def test_report_preserves_ack_without_send(self):
        pair = self.report(0)
        self.assertEqual(pair["ack_groups"], [3, 4])
        self.assertEqual(pair["first_ack_difference"]["index"], 2)
        self.assertIsNone(pair["first_repair_difference"])

    def test_truncated_empty_missing_and_substituted_ledgers(self):
        self.report(0)
        path = self.rd / "recovery-acks.jsonl"
        original = path.read_bytes()
        prefix = b"".join(original.splitlines(keepends=True)[:-1])
        for damaged in (prefix, b"", original.replace(b'"length": 100', b'"length": 99', 1), None):
            with self.subTest(damaged=damaged):
                if damaged is None:
                    path.unlink()
                else:
                    path.write_bytes(damaged)
                self.assertFalse(self.report(1)["comparable"])
        path.write_bytes(original)
        self.report(0)

    def test_original_format_checks_count_and_terminal_coverage(self):
        summary_path = self.rd / "recovery.json"
        row = json.loads(summary_path.read_text())
        del row["ledger_sha256"]
        C.json_write(summary_path, row)
        self.report(0)
        path = self.rd / "recovery-acks.jsonl"
        groups = C.A.read_jsonl(path)
        groups[-1]["ack"] -= 1
        path.write_text("".join(json.dumps(g) + "\n" for g in groups))
        self.assertFalse(self.report(1)["comparable"])
        path.write_text("")
        self.assertFalse(self.report(1)["comparable"])

if __name__ == "__main__":
    unittest.main()
