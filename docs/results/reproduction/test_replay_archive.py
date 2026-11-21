"""Checks for archive corruption, schedule provenance and safe restore boundaries."""

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from replay_archive import copy_plan, extract, read_manifest, sha256, verify


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.archive = self.root / "compact.tar.gz"
        self.output = self.root / "restored"

    def write_archive(self, *members):
        with tarfile.open(self.archive, "w:gz") as archive:
            for name in members:
                item = tarfile.TarInfo(name)
                item.size = 4
                archive.addfile(item, io.BytesIO(b"data"))

    def test_outer_archive_hash_rejects_corruption(self):
        self.write_archive("campaign/entry")
        expected = sha256(self.archive)
        with self.archive.open("ab") as f:
            f.write(b"modified bytes")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            verify(self.archive, expected)

    def test_archive_rejects_duplicate_and_escaped_members(self):
        for bad_members in (("campaign/entry", "campaign/entry"), ("../outside",),
                            ("campaign/input.pcap.gz",)):
            with self.subTest(bad_members=bad_members):
                self.write_archive(*bad_members)
                with tempfile.TemporaryDirectory(dir=self.root) as tmp:
                    with self.assertRaisesRegex(ValueError, "unexpected compact archive member"):
                        extract(self.archive, Path(tmp) / "restored", "campaign")
                self.assertFalse((self.root / "outside").exists())

    def test_archive_refuses_overwrite(self):
        self.write_archive("campaign/entry")
        self.output.mkdir()
        saved = self.output / "saved"
        saved.write_text("keep")
        with self.assertRaises(FileExistsError):
            extract(self.archive, self.output, "campaign")
        self.assertEqual(saved.read_text(), "keep")

    def test_missing_or_changed_original_plan_is_rejected(self):
        source = self.root / "source.json"
        target = self.root / "plan.json"
        with self.assertRaises(FileNotFoundError):
            copy_plan(source, target, "0" * 64)
        source.write_text("{}")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            copy_plan(source, target, "0" * 64)
        self.assertFalse(target.exists())

    def test_plan_refuses_overwrite_even_with_matching_checksum(self):
        source = self.root / "source.json"
        target = self.root / "plan.json"
        source.write_text("{}")
        target.write_text("keep")
        with self.assertRaises(FileExistsError):
            copy_plan(source, target, sha256(source))
        self.assertEqual(target.read_text(), "keep")

    def test_manifest_rejects_ambiguous_entries(self):
        source = self.root / "MANIFEST.sha256"
        line = "0" * 64 + "  "
        source.write_text(f"{line}first\n{line}./first\n")
        with self.assertRaisesRegex(ValueError, "invalid manifest entry"):
            read_manifest(source)


if __name__ == "__main__":
    unittest.main()
