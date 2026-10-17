"""
aegis/core/patch_engineer.py
============================
Automated source-code mitigation patch engineer and compiler hardening synthesizer.
Translates identified CWE sinks into safe, bounded C/C++ implementations and emits
standard unified diffs alongside recommended compiler mitigation flags.

Protocol Standard: Systems & Security Engineering (Mitigation & Patch Verification).
Pure Python 3.12 stdlib — zero external dependencies.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from typing import Any

from aegis.core.source_scanner import Finding


@dataclass
class PatchResult:
    """Represents the synthesized mitigation patch and hardening advice."""
    patched_source: str
    diff: str
    patches_applied: int
    modifications: list[dict[str, Any]]
    compiler_flags: dict[str, list[str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": True,
            "patches_applied": self.patches_applied,
            "diff": self.diff,
            "modifications": self.modifications,
            "compiler_flags": self.compiler_flags,
        }


def get_compiler_hardening_flags() -> dict[str, list[str]]:
    """Return recommended compiler hardening flags for major toolchains."""
    return {
        "gcc_clang": [
            "-fstack-protector-strong",      # Stack canaries with heuristic coverage
            "-D_FORTIFY_SOURCE=2",           # Runtime and compile-time buffer bounds checking
            "-Wl,-z,relro,-z,now",           # Full RELRO (read-only GOT table)
            "-fPIE -pie",                    # Full Position Independent Executable (ASLR)
            "-Wformat -Wformat-security",    # Reject non-literal format strings
            "-fstack-clash-protection",      # Prevent stack-clash page skipping
            "-z noexecstack",                # Non-executable stack (NX/DEP)
        ],
        "msvc": [
            "/GS",                           # Buffer security check (stack canary)
            "/DYNAMICBASE",                  # Address Space Layout Randomization (ASLR)
            "/NXCOMPAT",                     # Data Execution Prevention (DEP/NX)
            "/guard:cf",                     # Control Flow Guard (CFG)
            "/sdl",                          # Additional Security Development Lifecycle checks
            "/W4",                           # Warning level 4
            "/permissive-",                  # Strict standards conformance
        ],
    }


def patch_vulnerable_source(source_code: str, findings: list[Finding]) -> PatchResult:
    """
    Synthesize safe C code patches for detected memory corruption and format string sinks.
    """
    lines = source_code.splitlines(keepends=True)
    modifications: list[dict[str, Any]] = []
    patches_applied = 0

    # Sort findings in reverse line order so modifications don't invalidate line numbers
    sorted_findings = sorted(findings, key=lambda f: f.line, reverse=True)
    
    # Track which lines have already been patched to avoid duplicate replacements
    patched_lines: set[int] = set()

    for f in sorted_findings:
        if f.line in patched_lines:
            continue

        idx = f.line - 1
        if idx < 0 or idx >= len(lines):
            continue

        orig_line = lines[idx]
        patched_line = orig_line

        # ── 1. gets(buf) ➔ fgets(buf, sizeof(buf), stdin) ──────────────────────
        if f.sink == "gets":
            m = re.search(r"\bgets\s*\(\s*([a-zA-Z0-9_]+)\s*\)", orig_line)
            if m:
                buf = m.group(1)
                replacement = (
                    f"if (fgets({buf}, sizeof({buf}), stdin) != NULL) {{ "
                    f"{buf}[strcspn({buf}, \"\\n\")] = '\\0'; }}"
                )
                patched_line = orig_line.replace(m.group(0), replacement)

        # ── 2. strcpy(dest, src) ➔ snprintf(dest, sizeof(dest), "%s", src) ────
        elif f.sink == "strcpy":
            m = re.search(r"\bstrcpy\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*([^)]+)\)", orig_line)
            if m:
                dest = m.group(1)
                src = m.group(2).strip()
                replacement = f"snprintf({dest}, sizeof({dest}), \"%s\", {src})"
                patched_line = orig_line.replace(m.group(0), replacement)

        # ── 3. sprintf(dest, ...) ➔ snprintf(dest, sizeof(dest), ...) ──────────
        elif f.sink == "sprintf":
            m = re.search(r"\bsprintf\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*", orig_line)
            if m:
                dest = m.group(1)
                replacement = f"snprintf({dest}, sizeof({dest}), "
                patched_line = orig_line.replace(m.group(0), replacement)

        # ── 4. strcat(dest, src) ➔ strncat(dest, src, sizeof(dest) - strlen(dest) - 1) ─
        elif f.sink == "strcat":
            m = re.search(r"\bstrcat\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*([^)]+)\)", orig_line)
            if m:
                dest = m.group(1)
                src = m.group(2).strip()
                replacement = f"strncat({dest}, {src}, sizeof({dest}) - strlen({dest}) - 1)"
                patched_line = orig_line.replace(m.group(0), replacement)

        # ── 5. printf(var) format string ➔ printf("%s", var) ──────────────────
        elif f.cwe == "CWE-134" and f.sink in ("printf", "fprintf", "vprintf", "vfprintf"):
            if f.sink == "printf":
                m = re.search(r"\bprintf\s*\(\s*([a-zA-Z0-9_]+)\s*\)", orig_line)
                if m:
                    var = m.group(1)
                    replacement = f'printf("%s", {var})'
                    patched_line = orig_line.replace(m.group(0), replacement)
            elif f.sink == "fprintf":
                m = re.search(r"\bfprintf\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*([a-zA-Z0-9_]+)\s*\)", orig_line)
                if m:
                    stream = m.group(1)
                    var = m.group(2)
                    replacement = f'fprintf({stream}, "%s", {var})'
                    patched_line = orig_line.replace(m.group(0), replacement)

        if patched_line != orig_line:
            lines[idx] = patched_line
            patched_lines.add(f.line)
            patches_applied += 1
            modifications.append({
                "line": f.line,
                "cwe": f.cwe,
                "sink": f.sink,
                "original": orig_line.strip(),
                "replacement": patched_line.strip(),
            })

    patched_source = "".join(lines)
    
    # Generate unified diff
    orig_lines = source_code.splitlines(keepends=True)
    new_lines = patched_source.splitlines(keepends=True)
    diff_generator = difflib.unified_diff(
        orig_lines,
        new_lines,
        fromfile="a/target.c",
        tofile="b/target.c",
        lineterm="",
    )
    diff = "\n".join(diff_generator)

    return PatchResult(
        patched_source=patched_source,
        diff=diff,
        patches_applied=patches_applied,
        modifications=modifications,
        compiler_flags=get_compiler_hardening_flags(),
    )
