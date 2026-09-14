"""Regression tests for Stage 4 validation counting (src.validate).

Builds a tiny rule + labeled fixtures at runtime and checks TP/FP/FN, the
memory-mapped scanner, and the --benign-dir loader.
"""
import json
import tempfile
import unittest
from pathlib import Path

from src import validate


MARKER = b"INJECT3D_SIGNATURE_BYTES_ABCDEF"       # unlikely to occur by chance
RULE = ('rule marker_rule { strings: $m = "INJECT3D_SIGNATURE_BYTES_ABCDEF" '
        'condition: $m }')


class Validate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.rules = self.root / "rules"
        self.rules.mkdir()
        (self.rules / "marker.yar").write_text(RULE, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name: str, data: bytes) -> str:
        p = self.root / name
        p.write_bytes(data)
        return str(p)

    def _manifest(self, entries) -> str:
        p = self.root / "corpus.json"
        p.write_text(json.dumps(entries), encoding="utf-8")
        return str(p)

    def test_clean_tp_fp_fn(self):
        mal = self._write("mal.bin", b"\x00" * 100 + MARKER + b"\x00" * 100)
        ben = self._write("ben.bin", b"harmless benign content, no marker here")
        manifest = self._manifest([
            {"id": "m", "path": mal, "label": "malicious"},
            {"id": "b", "path": ben, "label": "benign"},
        ])
        r = validate.validate(str(self.rules), manifest)
        self.assertEqual((r["tp"], r["fp"], r["fn"]), (1, 0, 0))
        self.assertEqual(r["precision"], 1.0)
        self.assertEqual(r["recall"], 1.0)

    def test_false_positive_is_counted_and_listed(self):
        # a benign file that (wrongly) contains the marker -> FP, documented.
        ben = self._write("ben_fp.bin", b"benign but " + MARKER)
        manifest = self._manifest([{"id": "bfp", "path": ben, "label": "benign"}])
        r = validate.validate(str(self.rules), manifest)
        self.assertEqual(r["fp"], 1)
        self.assertEqual(r["false_positives"][0]["region"], "bfp")
        self.assertIn("marker_rule", r["false_positives"][0]["matched_rules"])

    def test_false_negative_is_counted(self):
        mal = self._write("mal_miss.bin", b"malicious but no signature present")
        manifest = self._manifest([{"id": "mm", "path": mal, "label": "malicious"}])
        r = validate.validate(str(self.rules), manifest)
        self.assertEqual((r["tp"], r["fn"]), (0, 1))
        self.assertIn("mm", r["false_negatives"])

    def test_benign_dir_loader(self):
        bdir = self.root / "clean"
        bdir.mkdir()
        (bdir / "a.bin").write_bytes(b"clean file a")
        (bdir / "b.bin").write_bytes(b"clean file b")
        r = validate.validate(str(self.rules), None, str(bdir))
        self.assertEqual(r["corpus"]["benign"], 2)
        self.assertEqual(r["fp"], 0)

    def test_scan_file_mmap_roundtrip(self):
        import yara_x
        rules = yara_x.compile(RULE)
        hit = self._write("h.bin", MARKER)
        miss = self._write("n.bin", b"nothing")
        empty = self._write("e.bin", b"")
        self.assertEqual(validate.scan_file(rules, Path(hit)), ["marker_rule"])
        self.assertEqual(validate.scan_file(rules, Path(miss)), [])
        self.assertEqual(validate.scan_file(rules, Path(empty)), [])   # no mmap of 0 bytes


if __name__ == "__main__":
    unittest.main()
