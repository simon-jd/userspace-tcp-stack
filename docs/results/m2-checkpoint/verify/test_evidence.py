"""Negative controls for the checkpoint archival checks. Run with Python's unittest entry point."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_profile_trace import BASE_SETS, check_profile, check_trace
from verify_endpoint_cc import endpoint

class EvidenceControls(unittest.TestCase):
    def setUp(self):
        self.ref = json.loads((Path(__file__).resolve().parent/"linux-profile.json").read_text())
        self.meta = dict(profile="linux",stack_set=BASE_SETS,algo="cubic",cc="cubic",rcv_ip="198.19.12.5",trace=True)
        self.sample = dict(ev="sample",role="sender",cc_name="cubic",t=6*10**9,conn_id=1)
        self.summ = dict(t0_ns=0,window_end_ns=7*10**9)

    def test_profile_and_overrides(self):
        self.assertEqual(check_profile(self.meta,[self.ref,self.sample],self.summ,self.ref),(1,1))
        for key,value in (("cc_flavor","rfc"),("set","pacing=off"),("pacing","off")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_profile(self.meta,[dict(self.ref,**{key:value}),self.sample],self.summ,self.ref)

    def test_sample_and_terminal_cc(self):
        for side in ("sender","receiver"):
            rows = [dict(ev="start",role=side),*(dict(ev="sample",cc_name="cubic",role=side,t=t) for t in (0,5,10)),
                    dict(ev="summary",role=side,backend="kernel",ok=True,cc="cubic")]
            self.assertEqual(endpoint(rows,side,"kernel","cubic",1,9)[-1],"cubic")
            for index,key in ((1,"cc_name"),(2,"cc_name"),(3,"cc_name"),(4,"cc")):
                corrupt = list(rows)
                corrupt[index] = dict(rows[index], **{key:"newreno"})
                with self.subTest(side=side,index=index), self.assertRaises(ValueError):
                    endpoint(corrupt,side,"kernel","cubic",1,9)

    def test_missing_malformed_and_incomplete_trace(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"trace.jsonl"
            rec=dict(t=3,conn=1,ev="cwnd",cwnd=10,tuple="198.18.0.2:60000>198.19.12.5:5201")
            for content in (None, "", "{broken}", json.dumps(rec)+"\n"):
                if content is not None:
                    p.write_text(content)
                with self.subTest(content=content), self.assertRaises(ValueError):
                    check_trace(p,self.meta,1,2)
            self.assertEqual(check_trace(p,self.meta,1,1)[0]["cwnd"],1)

if __name__ == "__main__":
    unittest.main()
