"""
tests/test_bridge.py
====================
Unit test suite for aegis.bridge.AegisBridge.
Verifies IPC bridge functionality between JavaScript and Python engines.
"""

import tempfile
import unittest
from pathlib import Path

from aegis.bridge import AegisBridge
from tests.test_checksec import _ELFBuilder, _PEBuilder, _write_tmp


class TestBridgeChecksec(unittest.TestCase):
    """Test AegisBridge.inspect_binary."""

    def setUp(self):
        self.bridge = AegisBridge()

    def test_inspect_valid_pe(self):
        blob = _PEBuilder(pe_plus=True, dll_chars=0x0140, with_canary=True).build()
        p = _write_tmp(blob, suffix=".exe")
        try:
            res = self.bridge.inspect_binary(str(p))
            self.assertTrue(res["success"])
            self.assertEqual(res["format"], "PE32+")
            self.assertIn("sha256", res)
            self.assertTrue(any(m["name"] == "NX" and m["status"] == "enabled" for m in res["mitigations"]))
            self.assertTrue(any(m["name"] == "Canary" and m["status"] == "enabled" for m in res["mitigations"]))
        finally:
            p.unlink()

    def test_inspect_valid_elf(self):
        blob = _ELFBuilder(bits=64, has_gnu_stack=True, stack_executable=False, has_relro=True, bind_now=True).build()
        p = _write_tmp(blob, suffix=".so")
        try:
            res = self.bridge.inspect_binary(str(p))
            self.assertTrue(res["success"])
            self.assertEqual(res["format"], "ELF64")
            self.assertTrue(any(m["name"] == "RELRO" and m["status"] == "enabled" for m in res["mitigations"]))
        finally:
            p.unlink()

    def test_inspect_nonexistent_binary(self):
        res = self.bridge.inspect_binary("C:\\fake\\path\\to\\nonexistent.exe")
        self.assertFalse(res["success"])
        self.assertIn("error", res)

    def test_inspect_empty_path(self):
        res = self.bridge.inspect_binary("")
        self.assertFalse(res["success"])


class TestBridgeCyclic(unittest.TestCase):
    """Test AegisBridge cyclic generation and offset resolution."""

    def setUp(self):
        self.bridge = AegisBridge()

    def test_cyclic_generate_valid(self):
        res = self.bridge.cyclic_generate(64)
        self.assertTrue(res["success"])
        self.assertEqual(len(res["pattern"]), 64)
        self.assertEqual(res["length"], 64)
        self.assertIn("hex_preview", res)

    def test_cyclic_generate_invalid_length(self):
        res = self.bridge.cyclic_generate(0)
        self.assertFalse(res["success"])

    def test_cyclic_resolve_hex(self):
        # Sample pattern slice at offset 42
        res_gen = self.bridge.cyclic_generate(100)
        pat = res_gen["pattern"]
        # Extract 4-byte chunk at offset 42
        chunk = pat[42:46]
        val = int.from_bytes(chunk.encode("ascii"), "little")
        hex_val = f"0x{val:X}"

        res = self.bridge.cyclic_resolve(hex_val, arch=32)
        self.assertTrue(res["success"])
        self.assertEqual(res["offset"], 42)

    def test_cyclic_resolve_not_found(self):
        res = self.bridge.cyclic_resolve("0x00000000", arch=32)
        self.assertFalse(res["success"])


class TestBridgeStackFrame(unittest.TestCase):
    """Test AegisBridge.calculate_stack_frame layout and overflow simulation."""

    def setUp(self):
        self.bridge = AegisBridge()

    def test_stack_frame_safe_state(self):
        # Buffer 64, payload 32 -> completely within buffer
        res = self.bridge.calculate_stack_frame(buffer_size=64, payload_len=32, arch=64, has_canary=True)
        self.assertTrue(res["success"])
        self.assertFalse(res["canary_triggered"])
        self.assertFalse(res["control_flow_hijacked"])
        self.assertEqual(res["segments"]["buffer"]["state"]["bytes_overwritten"], 32)
        self.assertFalse(res["segments"]["canary"]["state"]["overwritten"])

    def test_stack_frame_canary_smashed(self):
        # Buffer 64, payload 68 -> buffer overflowed into canary!
        res = self.bridge.calculate_stack_frame(buffer_size=64, payload_len=68, arch=64, has_canary=True)
        self.assertTrue(res["success"])
        self.assertTrue(res["canary_triggered"])
        self.assertFalse(res["control_flow_hijacked"])
        self.assertTrue(res["segments"]["canary"]["state"]["overwritten"])

    def test_stack_frame_rip_hijacked(self):
        # Overwrite reaches and passes saved RIP
        # With buffer=64, word=8, canary=8 -> padding=8 -> rbp=80..88, rip=88..96
        res = self.bridge.calculate_stack_frame(buffer_size=64, payload_len=96, arch=64, has_canary=True)
        self.assertTrue(res["success"])
        self.assertTrue(res["control_flow_hijacked"])
        self.assertTrue(res["segments"]["saved_rip"]["state"]["full_overwrite"])

    def test_stack_frame_32bit(self):
        res = self.bridge.calculate_stack_frame(buffer_size=32, payload_len=20, arch=32, has_canary=False)
        self.assertTrue(res["success"])
        self.assertEqual(res["word_size"], 4)
        self.assertEqual(res["offset_to_rbp"], 32)


class TestBridgeSourceScanner(unittest.TestCase):
    """Test AegisBridge.scan_source."""

    def setUp(self):
        self.bridge = AegisBridge()

    def test_scan_source_with_vuln(self):
        code = "void f(char *s) { char b[16]; strcpy(b, s); printf(s); }"
        f = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".c", encoding="utf-8")
        f.write(code)
        f.close()
        p = Path(f.name)
        try:
            res = self.bridge.scan_source(str(p), min_severity="info")
            self.assertTrue(res["success"])
            self.assertEqual(res["files_scanned"], 1)
            self.assertTrue(res["total_findings"] >= 2)
            self.assertTrue(res["critical_count"] >= 2)
        finally:
            p.unlink()

    def test_scan_source_nonexistent(self):
        res = self.bridge.scan_source("C:\\fake\\nonexistent.c")
        self.assertFalse(res["success"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
