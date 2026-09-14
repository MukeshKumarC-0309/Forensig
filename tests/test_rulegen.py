"""Regression tests for Stage 2/3 rule generation (src.rulegen).

Fast + hermetic: no Volatility, no real images. A synthetic 32-bit "injected
PE" blob is built at runtime so byte-pattern extraction, arch detection,
string filtering and the compile/self-match gate are all exercised.

Run: python -m unittest discover -s tests   (from the project root)
"""
import struct
import tempfile
import unittest
from pathlib import Path

from capstone import CS_MODE_32, CS_MODE_64

from src import rulegen


def _synthetic_injected_pe() -> bytes:
    """MZ+PE (machine=x86), real x86 code at 0x1000, a distinctive string."""
    b = bytearray(0x1400)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)          # e_lfanew -> 0x80
    b[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", b, 0x84, 0x014C)        # Machine = IMAGE_FILE_MACHINE_I386
    code = bytes.fromhex("558bec83ec108b45088b4d0c5051e80000000083c4085dc3")
    b[0x1000:0x1000 + len(code)] = code
    s = b"EVILMUTEX_test_12345\x00"                # distinctive, survives stoplist
    b[0x400:0x400 + len(s)] = s
    return bytes(b)


class ArtifactFilter(unittest.TestCase):
    def test_ascii_table_is_artifact(self):
        self.assertTrue(rulegen._is_artifact(
            " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"))

    def test_distinctive_string_kept(self):
        self.assertFalse(rulegen._is_artifact("EVILMUTEX_test_12345"))

    def test_pe_section_name_dropped(self):
        self.assertTrue(rulegen._is_artifact(".text"))

    def test_library_boilerplate_dropped(self):
        self.assertTrue(rulegen._is_artifact("Corrupt JPEG data near marker"))


class PeArch(unittest.TestCase):
    def test_x86_machine(self):
        self.assertEqual(rulegen.pe_arch(_synthetic_injected_pe()), CS_MODE_32)

    def test_non_pe_returns_none(self):
        self.assertIsNone(rulegen.pe_arch(b"not a pe" * 10))


class BytePattern(unittest.TestCase):
    def test_pattern_has_wildcards_and_compiles(self):
        import yara_x
        pat = rulegen.byte_pattern(_synthetic_injected_pe(), CS_MODE_32)
        self.assertIsNotNone(pat)
        self.assertIn("??", pat)                    # operands wildcarded
        yara_x.compile(f"rule t {{ strings: $b = {{ {pat} }} condition: $b }}")


class BuildRule(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _cand(self, blob: bytes, rid="1234-0x400000"):
        p = self.d / "region.dmp"
        p.write_bytes(blob)
        return {"region_id": rid, "Process": "evil.exe", "sha256": "abc",
                "dump_path": str(p), "_image": "test.mem"}

    def test_resident_pe_yields_compiling_self_matching_rule(self):
        rec = rulegen.build_rule(self._cand(_synthetic_injected_pe()), CS_MODE_64)
        self.assertTrue(rec["compiled"])
        self.assertFalse(rec["indicator_only"])
        self.assertTrue(rec["elements_used"]["byte_patterns"])
        self.assertIn("self-match=True", rec["note"])
        self.assertEqual(rec["match_threshold"], "$bp")   # byte-pattern REQUIRED

    def test_all_zero_region_is_indicator_only(self):
        rec = rulegen.build_rule(self._cand(bytes(4096)), CS_MODE_64)
        self.assertTrue(rec["indicator_only"])
        self.assertFalse(rec["compiled"])

    def test_missing_dump_is_indicator_only(self):
        rec = rulegen.build_rule(
            {"region_id": "1-0x1", "Process": "x", "dump_path": None}, CS_MODE_64)
        self.assertTrue(rec["indicator_only"])


if __name__ == "__main__":
    unittest.main()
