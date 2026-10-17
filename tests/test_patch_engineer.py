"""
tests/test_patch_engineer.py
============================
Unit tests for aegis.core.patch_engineer.
Verifies automated source code mitigation patching, diff generation, and compiler hardening flags.
"""

import unittest
from aegis.core.patch_engineer import (
    get_compiler_hardening_flags,
    patch_vulnerable_source,
)
from aegis.core.source_scanner import Finding


class TestPatchEngineer(unittest.TestCase):
    """Test patch synthesis for unsafe C memory sinks."""

    def test_patch_strcpy(self):
        source = 'void vuln(char *src) {\n    char buf[64];\n    strcpy(buf, src);\n}\n'
        finding = Finding(
            file="test.c",
            line=3,
            col=5,
            cwe="CWE-120",
            severity="critical",
            sink="strcpy",
            detail="Unbounded strcpy",
            snippet="strcpy(buf, src);",
        )
        res = patch_vulnerable_source(source, [finding])
        self.assertEqual(res.patches_applied, 1)
        self.assertIn('snprintf(buf, sizeof(buf), "%s", src)', res.patched_source)
        self.assertIn("--- a/target.c", res.diff)
        self.assertIn("+    snprintf(buf, sizeof(buf), \"%s\", src);", res.diff)

    def test_patch_gets(self):
        source = 'int main() {\n    char input[128];\n    gets(input);\n    return 0;\n}\n'
        finding = Finding(
            file="test.c",
            line=3,
            col=5,
            cwe="CWE-120",
            severity="critical",
            sink="gets",
            detail="Banned gets",
            snippet="gets(input);",
        )
        res = patch_vulnerable_source(source, [finding])
        self.assertEqual(res.patches_applied, 1)
        self.assertIn("fgets(input, sizeof(input), stdin)", res.patched_source)

    def test_patch_sprintf(self):
        source = 'void log_msg(char *user) {\n    char out[100];\n    sprintf(out, "User: %s", user);\n}\n'
        finding = Finding(
            file="test.c",
            line=3,
            col=5,
            cwe="CWE-120",
            severity="critical",
            sink="sprintf",
            detail="Unbounded sprintf",
            snippet='sprintf(out, "User: %s", user);',
        )
        res = patch_vulnerable_source(source, [finding])
        self.assertEqual(res.patches_applied, 1)
        self.assertIn("snprintf(out, sizeof(out),", res.patched_source)

    def test_patch_strcat(self):
        source = 'void append(char *tail) {\n    char buf[128] = "init:";\n    strcat(buf, tail);\n}\n'
        finding = Finding(
            file="test.c",
            line=3,
            col=5,
            cwe="CWE-120",
            severity="critical",
            sink="strcat",
            detail="Unbounded strcat",
            snippet="strcat(buf, tail);",
        )
        res = patch_vulnerable_source(source, [finding])
        self.assertEqual(res.patches_applied, 1)
        self.assertIn("strncat(buf, tail, sizeof(buf) - strlen(buf) - 1)", res.patched_source)

    def test_patch_format_string(self):
        source = 'void print_user(char *name) {\n    printf(name);\n}\n'
        finding = Finding(
            file="test.c",
            line=2,
            col=5,
            cwe="CWE-134",
            severity="critical",
            sink="printf",
            detail="Non-literal format string",
            snippet="printf(name);",
        )
        res = patch_vulnerable_source(source, [finding])
        self.assertEqual(res.patches_applied, 1)
        self.assertIn('printf("%s", name)', res.patched_source)

    def test_compiler_hardening_flags(self):
        flags = get_compiler_hardening_flags()
        self.assertIn("gcc_clang", flags)
        self.assertIn("msvc", flags)
        self.assertTrue(any("-fstack-protector-strong" in f for f in flags["gcc_clang"]))
        self.assertTrue(any("-D_FORTIFY_SOURCE=2" in f for f in flags["gcc_clang"]))
        self.assertTrue(any("/GS" in f for f in flags["msvc"]))
        self.assertTrue(any("/NXCOMPAT" in f for f in flags["msvc"]))


if __name__ == "__main__":
    unittest.main()
