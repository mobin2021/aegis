"""
tests/test_pipeline.py
======================
Unit tests for aegis.core.pipeline.
Verifies autonomous orchestration across recon, AST scanning, stack modeling,
PoC synthesis, and patch synthesis.
"""

import tempfile
import unittest
from pathlib import Path

from aegis.core.pipeline import (
    extract_buffer_size,
    format_triage_report,
    run_triage,
)
from tests.test_checksec import _ELFBuilder, _PEBuilder, _write_tmp


class TestPipelineOrchestration(unittest.TestCase):
    """Test full autonomous triage orchestration."""

    def test_extract_buffer_size(self):
        c_code = "void f() { char buf[128]; strcpy(buf, input); }"
        size = extract_buffer_size(c_code, "buf")
        self.assertEqual(size, 128)

        # Fallback to generic
        generic_code = "void f() { unsigned char workspace[256]; gets(workspace); }"
        size_gen = extract_buffer_size(generic_code, "missing")
        self.assertEqual(size_gen, 256)

        # Default fallback
        size_default = extract_buffer_size("void f() { int x = 10; }", "none")
        self.assertEqual(size_default, 64)

    def test_triage_vulnerable_source(self):
        c_code = """
        #include <stdio.h>
        #include <string.h>

        void vulnerable_function(char *user_input) {
            char local_buffer[64];
            strcpy(local_buffer, user_input);
            printf(user_input);
        }
        """
        f = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".c", encoding="utf-8")
        f.write(c_code)
        f.close()
        p = Path(f.name)

        try:
            res = run_triage(p, arch=64)
            self.assertEqual(res.target_type, "source")
            self.assertEqual(res.arch, 64)
            self.assertTrue(len(res.findings) >= 2)
            self.assertIsNotNone(res.frame_model)
            self.assertEqual(res.frame_model.buffer_size, 64)
            self.assertIsNotNone(res.offset_to_rip)
            self.assertTrue(res.offset_to_rip >= 64)

            # PoC script must be valid Python
            self.assertIn("def main():", res.poc_script)
            compile(res.poc_script, "<poc>", "exec")

            # Patch must be synthesized
            self.assertIsNotNone(res.patch_result)
            self.assertTrue(res.patch_result.patches_applied >= 1)
            self.assertIn("--- a/target.c", res.patch_result.diff)

            # Serialization to dict
            d = res.to_dict()
            self.assertTrue(d["success"])
            self.assertIn("findings", d)
            self.assertIn("frame_model", d)
            self.assertIn("patch", d)

            # Report formatting
            report_color = format_triage_report(res, color=True)
            report_plain = format_triage_report(res, color=False)
            self.assertIn("AUTONOMOUS TRIAGE & MITIGATION REPORT", report_plain)
            self.assertIn("VULNERABILITY SINK DISCOVERY", report_plain)
            self.assertIn("STACK FRAME MEMORY BOUNDARY MODEL", report_plain)
            self.assertIn("\033[", report_color)
        finally:
            p.unlink()

    def test_triage_buffer_override(self):
        c_code = "void f(char *s) { char b[32]; strcpy(b, s); }"
        f = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".c", encoding="utf-8")
        f.write(c_code)
        f.close()
        p = Path(f.name)

        try:
            res = run_triage(p, arch=64, buffer_override=128)
            self.assertEqual(res.frame_model.buffer_size, 128)
            # Offset to RIP for 128 buffer + 16 alignment on 64-bit = 128 + 0 pad + 8 rbp = 136
            self.assertEqual(res.offset_to_rip, 136)
        finally:
            p.unlink()

    def test_triage_binary_pe(self):
        blob = _PEBuilder(pe_plus=True, dll_chars=0x0140, with_canary=True).build()
        p = _write_tmp(blob, suffix=".exe")
        try:
            res = run_triage(p, arch=64)
            self.assertEqual(res.target_type, "binary")
            self.assertEqual(res.recon["format"], "PE32+")
            self.assertTrue(res.frame_model.has_canary)
            self.assertIsNotNone(res.offset_to_rip)
            self.assertIn("def main():", res.poc_script)
        finally:
            p.unlink()

    def test_triage_binary_elf(self):
        blob = _ELFBuilder(bits=32, has_gnu_stack=True, stack_executable=False).build()
        p = _write_tmp(blob, suffix=".elf")
        try:
            res = run_triage(p)
            self.assertEqual(res.target_type, "binary")
            self.assertEqual(res.arch, 32)
            self.assertEqual(res.recon["format"], "ELF32")
        finally:
            p.unlink()

    def test_triage_nonexistent_raises(self):
        with self.assertRaises(FileNotFoundError):
            run_triage("C:\\fake\\nonexistent_file.c")


if __name__ == "__main__":
    unittest.main()
