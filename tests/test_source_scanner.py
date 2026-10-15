"""
tests/test_source_scanner.py
============================
Unit test suite for aegis.core.source_scanner.

Tests cover:
  - Comment stripping and line-number preservation
  - Unsafe memory copy sinks (CWE-120: strcpy, gets, sprintf, scanf %s, etc.)
  - Stack boundary overflows (CWE-121: alloca, memcpy+strlen, VLA)
  - Uncontrolled format string analysis (CWE-134: literal vs variable detection)
  - Command injection (CWE-78: system, popen)
  - Dangerous legacy functions (CWE-676: tmpnam, mktemp, rand)
  - Severity threshold filtering and directory recursion
  - Report formatting and error handling
"""

import tempfile
import unittest
from pathlib import Path

from aegis.core.source_scanner import (
    Finding,
    ScanResult,
    _extract_format_arg,
    _is_string_literal,
    _strip_comments,
    format_scan_report,
    scan,
)


def _write_c_file(content: str, suffix: str = ".c") -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=suffix, encoding="utf-8")
    f.write(content)
    f.close()
    return Path(f.name)


class TestCommentStripping(unittest.TestCase):
    """Pass 0: Comment stripping and line preservation."""

    def test_single_line_comment_stripped(self):
        code = "int a = 1; // strcpy(dest, src);\nint b = 2;\n"
        stripped = _strip_comments(code)
        self.assertNotIn("strcpy", stripped)
        self.assertIn("int a = 1;", stripped)
        self.assertIn("int b = 2;", stripped)

    def test_block_comment_preserves_line_numbers(self):
        code = (
            "int a = 1;\n"
            "/*\n"
            "   strcpy(dest, src);\n"
            "   gets(buffer);\n"
            "*/\n"
            "int b = 2;\n"
        )
        stripped = _strip_comments(code)
        self.assertNotIn("strcpy", stripped)
        self.assertNotIn("gets", stripped)
        lines = stripped.splitlines()
        # Line 1: int a = 1;
        # Line 6: int b = 2;
        self.assertIn("int a = 1;", lines[0])
        self.assertIn("int b = 2;", lines[5])
        self.assertEqual(len(lines), 6)


class TestFormatStringAnalysis(unittest.TestCase):
    """Pass 2: Format string literal check and argument extractor."""

    def test_is_string_literal(self):
        self.assertTrue(_is_string_literal('"Hello world"'))
        self.assertTrue(_is_string_literal(' "Format: %s\\n" '))
        self.assertTrue(_is_string_literal('(const char *)"Literal"'))
        self.assertTrue(_is_string_literal('(char *)"Literal"'))
        self.assertTrue(_is_string_literal('L"Wide literal"'))
        self.assertTrue(_is_string_literal('u8"UTF-8 literal"'))

        self.assertFalse(_is_string_literal('user_input'))
        self.assertFalse(_is_string_literal('buf'))
        self.assertFalse(_is_string_literal('(char *)ptr'))
        self.assertFalse(_is_string_literal('get_format()'))

    def test_extract_format_arg_printf(self):
        line = 'printf(user_buffer);'
        # call_end is index right after '('
        call_end = line.index('(') + 1
        arg = _extract_format_arg(line, call_end, 'printf')
        self.assertEqual(arg, 'user_buffer')

    def test_extract_format_arg_fprintf_second_arg(self):
        line = 'fprintf(stderr, user_buffer);'
        call_end = line.index('(') + 1
        arg = _extract_format_arg(line, call_end, 'fprintf')
        self.assertEqual(arg, 'user_buffer')

    def test_extract_format_arg_nested_parens(self):
        line = 'printf(get_custom_string(1, 2), "extra");'
        call_end = line.index('(') + 1
        arg = _extract_format_arg(line, call_end, 'printf')
        self.assertEqual(arg, 'get_custom_string(1, 2)')


class TestCWE120BufferCopy(unittest.TestCase):
    """CWE-120: Classic Unbounded Buffer Copy."""

    def test_strcpy_detected(self):
        code = "void vuln() { char dst[32]; strcpy(dst, input); }"
        p = _write_c_file(code)
        try:
            results = scan(p)
            findings = results[0].findings
            sinks = [f.sink for f in findings]
            cwes = [f.cwe for f in findings]
            self.assertIn("strcpy", sinks)
            self.assertIn("CWE-120", cwes)
            f = next(item for item in findings if item.sink == "strcpy")
            self.assertEqual(f.severity, "critical")
        finally:
            p.unlink()

    def test_gets_detected(self):
        code = "void vuln() { char buf[64]; gets(buf); }"
        p = _write_c_file(code)
        try:
            results = scan(p)
            findings = results[0].findings
            self.assertTrue(any(f.sink == "gets" and f.severity == "critical" for f in findings))
        finally:
            p.unlink()

    def test_sprintf_detected(self):
        code = 'void vuln(int x) { char buf[32]; sprintf(buf, "Val: %d", x); }'
        p = _write_c_file(code)
        try:
            results = scan(p)
            findings = results[0].findings
            self.assertTrue(any(f.sink == "sprintf" and f.cwe == "CWE-120" for f in findings))
        finally:
            p.unlink()

    def test_scanf_unbounded_string(self):
        code = 'void vuln() { char buf[100]; scanf("%s", buf); }'
        p = _write_c_file(code)
        try:
            results = scan(p)
            findings = results[0].findings
            self.assertTrue(any(f.sink == "scanf(%s)" for f in findings))
        finally:
            p.unlink()

    def test_stpcpy_strcat_wcscpy(self):
        code = (
            "void vuln(char *s, wchar_t *ws) {\n"
            "    char d[64]; wchar_t wd[64];\n"
            "    stpcpy(d, s);\n"
            "    strcat(d, s);\n"
            "    wcscpy(wd, ws);\n"
            "}\n"
        )
        p = _write_c_file(code)
        try:
            results = scan(p)
            sinks = {f.sink for f in results[0].findings}
            self.assertIn("stpcpy", sinks)
            self.assertIn("strcat", sinks)
            self.assertIn("wcscpy", sinks)
        finally:
            p.unlink()


class TestCWE121StackOverflow(unittest.TestCase):
    """CWE-121: Stack-based buffer overflow risks."""

    def test_alloca_detected(self):
        code = "void vuln(int n) { void *p = alloca(n); }"
        p = _write_c_file(code)
        try:
            results = scan(p)
            findings = results[0].findings
            self.assertTrue(any(f.sink == "alloca" and f.cwe == "CWE-121" for f in findings))
        finally:
            p.unlink()

    def test_memcpy_with_strlen(self):
        code = "void vuln(char *s) { char d[16]; memcpy(d, s, strlen(s)); }"
        p = _write_c_file(code)
        try:
            results = scan(p)
            findings = results[0].findings
            self.assertTrue(any(f.sink == "memcpy(strlen)" and f.cwe == "CWE-121" for f in findings))
        finally:
            p.unlink()

    def test_vla_detected(self):
        code = "void vuln(int size) {\n    int stack_arr[size];\n}\n"
        p = _write_c_file(code)
        try:
            results = scan(p)
            findings = results[0].findings
            self.assertTrue(any(f.sink == "VLA" and f.cwe == "CWE-121" for f in findings))
        finally:
            p.unlink()


class TestCWE134FormatString(unittest.TestCase):
    """CWE-134: Format string vulnerabilities vs safe calls."""

    def test_safe_printf_literal_not_flagged_as_cwe134(self):
        code = 'void ok() { printf("Hello %s, code %d\\n", name, 42); }'
        p = _write_c_file(code)
        try:
            results = scan(p)
            cwe134 = [f for f in results[0].findings if f.cwe == "CWE-134"]
            self.assertEqual(len(cwe134), 0, "Safe literal printf should not trigger CWE-134")
        finally:
            p.unlink()

    def test_unsafe_printf_variable_flagged(self):
        code = "void vuln(char *user) { printf(user); }"
        p = _write_c_file(code)
        try:
            results = scan(p)
            findings = results[0].findings
            cwe134 = [f for f in findings if f.cwe == "CWE-134"]
            self.assertEqual(len(cwe134), 1)
            self.assertEqual(cwe134[0].severity, "critical")
            self.assertEqual(cwe134[0].sink, "printf")
        finally:
            p.unlink()

    def test_unsafe_fprintf_variable_flagged(self):
        code = "void vuln(FILE *fp, char *user) { fprintf(fp, user); }"
        p = _write_c_file(code)
        try:
            results = scan(p)
            findings = results[0].findings
            cwe134 = [f for f in findings if f.cwe == "CWE-134"]
            self.assertEqual(len(cwe134), 1)
            self.assertEqual(cwe134[0].sink, "fprintf")
        finally:
            p.unlink()

    def test_safe_fprintf_literal_not_flagged(self):
        code = 'void ok(FILE *fp) { fprintf(fp, "Status: %s\\n", status); }'
        p = _write_c_file(code)
        try:
            results = scan(p)
            cwe134 = [f for f in results[0].findings if f.cwe == "CWE-134"]
            self.assertEqual(len(cwe134), 0)
        finally:
            p.unlink()


class TestCWE78And676(unittest.TestCase):
    """CWE-78 Command Injection and CWE-676 Dangerous Functions."""

    def test_system_and_popen(self):
        code = 'void cmd(char *c) { system(c); popen(c, "r"); }'
        p = _write_c_file(code)
        try:
            results = scan(p)
            sinks = {f.sink for f in results[0].findings}
            self.assertIn("system", sinks)
            self.assertIn("popen", sinks)
        finally:
            p.unlink()

    def test_tmpnam_and_rand(self):
        code = "void test() { char *t = tmpnam(NULL); int r = rand(); }"
        p = _write_c_file(code)
        try:
            results = scan(p)
            sinks = {f.sink for f in results[0].findings}
            self.assertIn("tmpnam", sinks)
            self.assertIn("rand", sinks)
        finally:
            p.unlink()


class TestScanFilteringAndReporting(unittest.TestCase):
    """Directory scanning, severity thresholds, and reporting."""

    def test_severity_filter(self):
        code = (
            "void mixed() {\n"
            "    int r = rand(); // low\n"
            "    char dst[10];\n"
            "    strcpy(dst, \"x\"); // critical\n"
            "}\n"
        )
        p = _write_c_file(code)
        try:
            results_all = scan(p, min_severity="info")
            self.assertTrue(len(results_all[0].findings) >= 2)

            results_crit = scan(p, min_severity="critical")
            self.assertEqual(len(results_crit[0].findings), 1)
            self.assertEqual(results_crit[0].findings[0].sink, "strcpy")
        finally:
            p.unlink()

    def test_nonexistent_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan("this_file_does_not_exist_at_all.c")

    def test_format_scan_report(self):
        code = "void vuln() { char buf[10]; gets(buf); }"
        p = _write_c_file(code)
        try:
            results = scan(p)
            rep_plain = format_scan_report(results, color=False)
            self.assertIn("Aegis scan", rep_plain)
            self.assertIn("gets", rep_plain)
            self.assertIn("CWE-120", rep_plain)
        finally:
            p.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
