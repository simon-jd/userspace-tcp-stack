"""Exercise the offline checker with a completed, multi-batch stream smoke receipt."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
import xml.etree.ElementTree as ET

CHECKER = Path(__file__).resolve().parents[2] / "tools/valid_soak.py"


class ReceiptCheck(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.copy = Path(temp.name) / "receipt"
        shutil.copytree(sample, self.copy)

    def check(self, error=None):
        proc = subprocess.run([sys.executable, CHECKER, "check", self.copy],
                              capture_output=True, text=True)
        if error is None:
            self.assertEqual(proc.returncode, 0, proc.stderr)
        else:
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(error, proc.stderr)

    def test_complete_receipt(self):
        self.check()

    def test_last_xml_properties(self):
        for key in ("seed", "reads"):
            with self.subTest(key=key):
                xml = ET.parse(sample / "test.xml")
                prop = xml.find(f"./testsuite/testcase/properties/property[@name='{key}']")
                prop.set("value", str(int(prop.attrib["value"]) + 1))
                xml.write(self.copy / "test.xml")
                self.check("XML properties differ from final batch")

    def test_earlier_dynamic_count(self):
        path = self.copy / "test.log"
        log = path.read_text()
        self.assertGreaterEqual(log.count("UTCP_VALID_BATCH "), 2)
        changed, n = re.subn(r" reads=(\d+)", lambda m: f" reads={int(m[1]) + 1}", log, count=1)
        self.assertEqual(n, 1)
        path.write_text(changed)
        self.check("stored summary differs")

    def test_raw_file_hashes(self):
        for name in ("test.log", "test.xml"):
            with self.subTest(name=name):
                path = self.copy / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                self.check("stored summary differs")
                path.write_bytes(original)

    def test_stored_total(self):
        path = self.copy / "summary.json"
        summary = json.loads(path.read_text())
        summary["totals"]["reads"] += 1
        path.write_text(json.dumps(summary))
        self.check("stored summary differs")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: valid_soak_receipt.py SHORT_STREAM_RECEIPT")
    sample = Path(sys.argv.pop(1))
    unittest.main()
