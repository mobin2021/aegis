"""
tests/test_poc_synthesizer.py
=============================
Unit tests for aegis.core.poc_synthesizer.
Verifies autonomous PoC script synthesis, syntax validity, and terminology compliance.
"""

import unittest
from aegis.core.poc_synthesizer import synthesize_poc


class TestPoCSynthesizer(unittest.TestCase):
    """Test PoC generation functionality."""

    def test_synthesizes_syntactically_valid_python(self):
        code = synthesize_poc(
            cwe="CWE-121",
            offset_to_rip=72,
            arch=64,
            target_name="test_target",
            sink_function="strcpy",
            detail="Unbounded stack copy",
        )
        # compile() raises SyntaxError if invalid Python code
        compiled = compile(code, "<test_poc>", "exec")
        self.assertIsNotNone(compiled)

    def test_contains_correct_offsets_and_arch(self):
        code = synthesize_poc(
            cwe="CWE-120",
            offset_to_rip=136,
            arch=32,
            target_name="vuln_app",
            sink_function="gets",
        )
        self.assertIn("136", code)
        self.assertIn("0x88", code)
        self.assertIn("x86_32", code)
        self.assertIn("vuln_app", code)
        self.assertIn("CWE-120", code)

    def test_scientific_terminology_compliance(self):
        code = synthesize_poc(
            cwe="CWE-121",
            offset_to_rip=80,
            arch=64,
        )
        self.assertIn("Deterministic Crash Test Vector", code)
        self.assertIn("instruction pointer offset verification", code)
        self.assertIn("Zero Cloud Filter Blocks", code)


if __name__ == "__main__":
    unittest.main()
