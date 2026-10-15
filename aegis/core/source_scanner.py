"""
aegis/core/source_scanner.py
============================
Static C Source Vulnerability Scanner
--------------------------------------
Dual-pass regex + structural analyser for unsafe memory and format-string
sinks in C / C++ source files.  Zero external dependencies (pure stdlib).

SCANNER ARCHITECTURE
--------------------

Pass 0 — Pre-processing
    • Normalise line endings (\\r\\n → \\n).
    • Strip single-line comments  (// ... to end-of-line).
    • Strip block comments        (/* ... */) while preserving line numbers
      by replacing comment bodies with whitespace of equal line count.

Pass 1 — Unsafe Sink Detection (regex, per-line)
    For each source line, apply a catalogue of compiled regex patterns that
    match known unsafe C library function calls.  Each pattern carries:
      • cwe      : the CWE identifier (CWE-120, CWE-121, CWE-134, CWE-78)
      • severity : "critical" | "high" | "medium" | "info"
      • detail   : human-readable rationale

Pass 2 — Format String Argument Analysis (structural, per-call-site)
    printf-family functions (printf, fprintf, dprintf, syslog, vprintf …)
    are only dangerous when the FORMAT argument is not a string literal.
    We use a lightweight bracket-balancing argument extractor to pull the
    format argument out, then check:
        • Starts with '"'   → literal string → Skip (not flagged by this pass)
        • Any other token   → variable/expression → CWE-134 finding emitted

    This eliminates false positives from calls like printf("%s\\n", user_buf)
    while correctly catching printf(user_controlled_format).

COMMENT STRIPPING
-----------------
We must strip comments before pattern matching to avoid false positives
from commented-out code.  Block comments spanning multiple lines preserve
the newline count so line numbers remain accurate.

Algorithm for block comment stripping:
  While text contains /* ... */:
    1. Find the opening /*
    2. Find the matching */
    3. Count \\n chars in the comment body
    4. Replace the entire comment with ' ' + '\\n' * newline_count

CWE TAXONOMY IMPLEMENTED
------------------------
  CWE-120  Buffer Copy without Checking Size of Input ("Classic Buffer Overflow")
             strcpy, strcat, gets, sprintf, vsprintf, scanf(%s), strncpy misuse
  CWE-121  Stack-based Buffer Overflow
             alloca with dynamic argument, memcpy/memmove with strlen (off-by-one)
  CWE-122  Heap-based Buffer Overflow
             malloc/realloc without size validation (structural heuristic)
  CWE-134  Use of Externally-Controlled Format String
             printf/fprintf/syslog with non-literal format argument
  CWE-78   OS Command Injection
             system(), popen() calls (argument may be attacker-controlled)
  CWE-676  Use of Potentially Dangerous Function
             tmpnam, mktemp (race conditions on temp files)

USAGE
-----
  python -m aegis scan myfile.c
  python -m aegis scan src/
  python -m aegis scan src/ --severity high
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0,
}

# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    One identified vulnerability at a specific source location.

    Attributes
    ----------
    file     : source file path (absolute)
    line     : 1-indexed line number
    col      : 1-indexed column of the match start
    cwe      : CWE identifier string, e.g. "CWE-120"
    severity : "critical" | "high" | "medium" | "low" | "info"
    sink     : the dangerous function/pattern name (e.g. "strcpy")
    detail   : human-readable explanation of the risk
    snippet  : the matched source line (stripped)
    """
    file:     str
    line:     int
    col:      int
    cwe:      str
    severity: str
    sink:     str
    detail:   str
    snippet:  str


@dataclass
class ScanResult:
    """
    Aggregated scan output for one source file.

    Attributes
    ----------
    path       : absolute path of the scanned file
    findings   : list of Finding objects, in source order
    lines_total: total lines in the file
    errors     : non-fatal parse warnings
    """
    path:        str
    findings:    list[Finding] = field(default_factory=list)
    lines_total: int           = 0
    errors:      list[str]     = field(default_factory=list)

    # ── Convenience ───────────────────────────────────────────────────────────

    def by_severity(self, minimum: str = "info") -> list[Finding]:
        """Return findings at or above *minimum* severity, in source order."""
        threshold = _SEVERITY_RANK.get(minimum, 0)
        return [f for f in self.findings
                if _SEVERITY_RANK.get(f.severity, 0) >= threshold]

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")


# ---------------------------------------------------------------------------
# Pattern catalogue
# ---------------------------------------------------------------------------
# Each entry is a tuple:
#   (compiled_regex, cwe, severity, sink_name, detail_template)
#
# detail_template may contain {match} which is filled with the raw matched text.

@dataclass(frozen=True)
class _Rule:
    pattern:  re.Pattern
    cwe:      str
    severity: str
    sink:     str
    detail:   str


def _r(pattern: str, **kwargs) -> _Rule:
    """Build a _Rule with a pre-compiled pattern."""
    return _Rule(
        pattern  = re.compile(pattern, re.VERBOSE),
        **kwargs,
    )


# ── CWE-120: Buffer Copy without Checking Size ────────────────────────────────
_RULES_CWE120: list[_Rule] = [
    _r(
        r"\b strcpy \s* \(",
        cwe="CWE-120", severity="critical", sink="strcpy",
        detail=(
            "strcpy() copies until a null terminator with no bound on the "
            "destination buffer — classic stack/heap overflow vector. "
            "Replace with strlcpy() or strncpy() + explicit null termination."
        ),
    ),
    _r(
        r"\b stpcpy \s* \(",
        cwe="CWE-120", severity="critical", sink="stpcpy",
        detail=(
            "stpcpy() is strcpy() returning a pointer to the end — same "
            "unbounded copy risk. Replace with stpncpy()."
        ),
    ),
    _r(
        r"\b strcat \s* \(",
        cwe="CWE-120", severity="critical", sink="strcat",
        detail=(
            "strcat() concatenates without checking available space in the "
            "destination — overflow if dst is not large enough. Use strncat() "
            "with explicit remaining-space calculation."
        ),
    ),
    _r(
        r"\b wcscpy \s* \(",
        cwe="CWE-120", severity="critical", sink="wcscpy",
        detail=(
            "wcscpy() is the wide-character analogue of strcpy() — same "
            "unbounded copy risk on wide buffers. Use wcsncpy()."
        ),
    ),
    _r(
        r"\b wcscat \s* \(",
        cwe="CWE-120", severity="high", sink="wcscat",
        detail=(
            "wcscat() concatenates wide strings without bounds checking. "
            "Use wcsncat() with an explicit remaining-space count."
        ),
    ),
    _r(
        r"\b gets \s* \(",
        cwe="CWE-120", severity="critical", sink="gets",
        detail=(
            "gets() reads from stdin until newline with NO bound on the buffer — "
            "removed in C11 for this exact reason. Replace with fgets(buf, sizeof(buf), stdin)."
        ),
    ),
    _r(
        r"\b sprintf \s* \(",
        cwe="CWE-120", severity="high", sink="sprintf",
        detail=(
            "sprintf() writes to the destination with no length limit — "
            "overflow if formatted output exceeds buffer capacity. "
            "Replace with snprintf(buf, sizeof(buf), ...)."
        ),
    ),
    _r(
        r"\b vsprintf \s* \(",
        cwe="CWE-120", severity="high", sink="vsprintf",
        detail=(
            "vsprintf() is the variadic-pointer variant of sprintf — same "
            "unbounded output risk. Replace with vsnprintf()."
        ),
    ),
    # scanf/sscanf with %s and no width specifier
    _r(
        r'\b s?scanf \s* \( [^)]*? " [^"]*? %s [^"]*? "',
        cwe="CWE-120", severity="high", sink="scanf(%s)",
        detail=(
            "scanf/sscanf with %s (no width specifier) reads until whitespace "
            "with no bound — overflow if input exceeds buffer. "
            'Use %Ns where N = sizeof(buf)-1, e.g. scanf("%255s", buf).'
        ),
    ),
    # strncpy — common misuse: forgetting null terminator
    _r(
        r"\b strncpy \s* \(",
        cwe="CWE-120", severity="low", sink="strncpy",
        detail=(
            "strncpy() does not guarantee null termination when src length >= n. "
            "Always add buf[n-1] = '\\0' after the call, or prefer strlcpy()."
        ),
    ),
]

# ── CWE-121: Stack-based Buffer Overflow ─────────────────────────────────────
_RULES_CWE121: list[_Rule] = [
    _r(
        r"\b alloca \s* \(",
        cwe="CWE-121", severity="high", sink="alloca",
        detail=(
            "alloca() allocates on the stack at runtime — if the size argument "
            "is attacker-influenced, a large value can smash the stack frame "
            "or exhaust stack space. Prefer heap allocation with malloc()."
        ),
    ),
    # memcpy/memmove with strlen as size — classic off-by-one (missing +1 for \\0)
    _r(
        r"\b mem(?:cpy|move) \s* \( [^,]+ , [^,]+ , \s* strlen \s* \(",
        cwe="CWE-121", severity="high", sink="memcpy(strlen)",
        detail=(
            "memcpy/memmove sized with strlen() is off-by-one: strlen returns "
            "the number of chars WITHOUT the null terminator. A destination "
            "holding a C string needs strlen(src)+1 bytes. This can overflow "
            "the last byte into adjacent stack or heap memory."
        ),
    ),
    # VLA (variable-length arrays) with non-constant size
    _r(
        r"^\s* \w[\w\s\*]+ \[ \s* [a-zA-Z_]\w* \s* \] \s* ;",
        cwe="CWE-121", severity="medium", sink="VLA",
        detail=(
            "Variable-length array (VLA) allocated on the stack with a "
            "runtime-determined size. If the size is attacker-influenced, "
            "this can exhaust stack space or enable stack-based exploitation. "
            "Prefer fixed-size arrays or heap allocation."
        ),
    ),
]

# ── CWE-134: Uncontrolled Format String ──────────────────────────────────────
# Note: format-string PASS 2 handles the non-literal-format check.
# These rules catch the function names for context; Pass 2 filters them.
_FORMAT_FUNCTIONS: frozenset[str] = frozenset({
    "printf", "fprintf", "dprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vdprintf", "vsprintf", "vsnprintf",
    "wprintf", "fwprintf", "swprintf",
    "syslog", "vsyslog",
})

# Pre-built regex that matches any format function followed by '('
_FORMAT_FUNC_RE: re.Pattern = re.compile(
    r"\b(" + "|".join(re.escape(f) for f in _FORMAT_FUNCTIONS) + r")\s*\(",
    re.VERBOSE,
)

# ── CWE-78: OS Command Injection ─────────────────────────────────────────────
_RULES_CWE78: list[_Rule] = [
    _r(
        r"\b system \s* \(",
        cwe="CWE-78", severity="high", sink="system",
        detail=(
            "system() passes its argument directly to the OS shell — "
            "if any part of the argument is attacker-controlled, arbitrary "
            "commands can be injected. Use execve() with a fixed argv[]."
        ),
    ),
    _r(
        r"\b popen \s* \(",
        cwe="CWE-78", severity="high", sink="popen",
        detail=(
            "popen() spawns a shell to run a command — same injection risk "
            "as system(). Prefer posix_spawn() or pipe()+execve() directly."
        ),
    ),
    _r(
        r"\b execl[pe]? \s* \( [^,]+ , \s* \" [^\"]+? \" \s* ,",
        cwe="CWE-78", severity="medium", sink="execl/execlp",
        detail=(
            "execl()/execlp() with a string literal command is lower risk, "
            "but verify the path cannot be influenced by user input or "
            "environment variables (PATH hijacking)."
        ),
    ),
]

# ── CWE-676: Use of Potentially Dangerous Function ───────────────────────────
_RULES_CWE676: list[_Rule] = [
    _r(
        r"\b tmpnam \s* \(",
        cwe="CWE-676", severity="medium", sink="tmpnam",
        detail=(
            "tmpnam() has a TOCTOU race: another process can create the returned "
            "filename between the call and open(). Use mkstemp() or tmpfile() instead."
        ),
    ),
    _r(
        r"\b mktemp \s* \(",
        cwe="CWE-676", severity="medium", sink="mktemp",
        detail=(
            "mktemp() returns a unique name but does not atomically open it — "
            "race condition. Use mkstemp() for atomic creation."
        ),
    ),
    _r(
        r"\b rand \s* \( \s* \)",
        cwe="CWE-676", severity="low", sink="rand",
        detail=(
            "rand() is a non-cryptographic PRNG — output is predictable. "
            "Use a CSPRNG (e.g. getrandom(), BCryptGenRandom()) for "
            "security-sensitive randomness."
        ),
    ),
]

# ── Combine all pass-1 rules ─────────────────────────────────────────────────
_ALL_RULES: list[_Rule] = (
    _RULES_CWE120 +
    _RULES_CWE121 +
    _RULES_CWE78  +
    _RULES_CWE676
)

# ---------------------------------------------------------------------------
# Pass 0: comment stripping
# ---------------------------------------------------------------------------

_BLOCK_COMMENT_RE   = re.compile(r"/\*.*?\*/",  re.DOTALL)
_LINE_COMMENT_RE    = re.compile(r"//[^\n]*")
_STRING_LITERAL_RE  = re.compile(r'"(?:[^"\\]|\\.)*"')   # rough string literal


def _strip_comments(source: str) -> str:
    """
    Remove C/C++ comments while preserving line numbers.

    Block comments (/* ... */) are replaced by whitespace that contains the
    same number of newlines as the original, so every line's 1-indexed number
    remains unchanged.

    Single-line comments (// ...) are stripped to end-of-line.

    Parameters
    ----------
    source : str
        Raw C/C++ source text.

    Returns
    -------
    str
        Source with all comments removed and line numbers preserved.
    """
    def _replace_block(m: re.Match) -> str:
        # Count newlines inside the comment, emit that many to preserve line nums
        body = m.group(0)
        newlines = body.count("\n")
        return " " + "\n" * newlines

    stripped = _BLOCK_COMMENT_RE.sub(_replace_block, source)
    stripped = _LINE_COMMENT_RE.sub("", stripped)
    return stripped


# ---------------------------------------------------------------------------
# Pass 2 helpers: format string argument extraction
# ---------------------------------------------------------------------------

def _extract_format_arg(line: str, call_end: int, func_name: str) -> str | None:
    """
    Given a source line and the position just after the opening '(' of a
    format-function call, extract the format argument (the first argument for
    most functions, the second for fprintf/dprintf/syslog/fwprintf).

    Uses a paren-balancing scanner to correctly handle nested calls like:
        printf(get_fmt(), arg1, arg2)

    Parameters
    ----------
    line     : the (comment-stripped) source line
    call_end : index in `line` just after the '(' of the function call
    func_name: the matched function name (determines which arg is the format)

    Returns
    -------
    str or None
        The stripped text of the format argument, or None if extraction fails.
    """
    # Functions where the FORMAT argument is arg[1] (0-indexed), not arg[0]
    _SECOND_ARG_FUNCS: frozenset[str] = frozenset({
        "fprintf", "dprintf", "fwprintf", "syslog", "vsyslog", "vfprintf", "vdprintf",
    })

    text   = line[call_end:]    # everything after the opening '('
    depth  = 1                  # we're already inside the first '('
    pos    = 0
    args: list[str] = []
    current_arg_start = 0

    while pos < len(text) and depth > 0:
        ch = text[pos]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                args.append(text[current_arg_start:pos].strip())
                break
        elif ch == "," and depth == 1:
            args.append(text[current_arg_start:pos].strip())
            current_arg_start = pos + 1
        elif ch == '"':
            # Skip over string literals to avoid confusing ',' inside strings
            pos += 1
            while pos < len(text) and text[pos] != '"':
                if text[pos] == "\\" and pos + 1 < len(text):
                    pos += 1   # skip escaped char
                pos += 1
        pos += 1

    if not args:
        return None

    target_idx = 1 if func_name in _SECOND_ARG_FUNCS else 0
    if target_idx >= len(args):
        return None

    return args[target_idx]


def _is_string_literal(expr: str) -> bool:
    """
    Return True if *expr* (trimmed format argument text) is a string literal.

    Handles:
      - Simple literals:          "hello %s\\n"
      - Adjacent string literals: "part1" "part2"
      - String with cast:         (const char *)"hello"
      - L-prefix wide strings:    L"hello"
      - Macros that expand to string literals heuristically:
          PRIu64, PRId32, … (all-caps identifier adjacent to a literal)
    """
    # Strip leading cast like (const char *) or (char *)
    cast_stripped = re.sub(r"^\s*\(\s*(?:const\s+)?\w[\w\s\*]+\)\s*", "", expr)

    # Strip optional L prefix for wide strings
    s = cast_stripped.strip().lstrip("Lu8")

    # After stripping, must start with '"'
    return s.startswith('"')


# ---------------------------------------------------------------------------
# Core scanner functions
# ---------------------------------------------------------------------------

def _scan_lines(
    lines: list[str],
    filepath: str,
) -> list[Finding]:
    """
    Run pass-1 and pass-2 scans over a list of (comment-stripped) source lines.

    Parameters
    ----------
    lines    : list of source lines (1-indexed by their position in the list)
    filepath : absolute path of the file being scanned

    Returns
    -------
    list[Finding]
        All findings from both passes, in source order.
    """
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()   # (lineno, sink) de-duplication

    def _add(lineno: int, col: int, rule_cwe: str, rule_sev: str,
             rule_sink: str, rule_detail: str, raw_line: str) -> None:
        key = (lineno, rule_sink)
        if key in seen:
            return
        seen.add(key)
        findings.append(Finding(
            file     = filepath,
            line     = lineno,
            col      = col + 1,   # 1-indexed
            cwe      = rule_cwe,
            severity = rule_sev,
            sink     = rule_sink,
            detail   = rule_detail,
            snippet  = raw_line.rstrip(),
        ))

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        # ── Pass 1: apply all unsafe-sink rules ───────────────────────────────
        for rule in _ALL_RULES:
            m = rule.pattern.search(line)
            if m:
                _add(lineno, m.start(), rule.cwe, rule.severity,
                     rule.sink, rule.detail, line)

        # ── Pass 2: format string argument analysis ───────────────────────────
        for m in _FORMAT_FUNC_RE.finditer(line):
            func_name = m.group(1)
            call_open = m.end()    # index just after '('

            fmt_arg = _extract_format_arg(line, call_open, func_name)
            if fmt_arg is None:
                # Multi-line call or extraction failed — conservative: skip
                continue

            if not _is_string_literal(fmt_arg):
                # Format argument is NOT a string literal → CWE-134
                _add(
                    lineno, m.start(),
                    "CWE-134", "critical",
                    func_name,
                    (
                        f"{func_name}() called with a non-literal format argument "
                        f"'{fmt_arg}' — if this value is attacker-controlled, they "
                        "can read arbitrary stack memory (%x/%p), write to arbitrary "
                        "addresses (%n), or crash the process. "
                        f'Fix: always use a literal format string: {func_name}("%s", {fmt_arg}).'
                    ),
                    line,
                )

    return findings


def _scan_file(path: Path) -> ScanResult:
    """
    Scan a single C/C++ source file.

    Parameters
    ----------
    path : Path to the source file.

    Returns
    -------
    ScanResult
    """
    result = ScanResult(path=str(path.resolve()))

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result.errors.append(f"Cannot read file: {exc}")
        return result

    stripped = _strip_comments(raw)
    lines    = stripped.splitlines()
    result.lines_total = len(lines)

    findings = _scan_lines(lines, result.path)

    # Sort by line number, then column
    findings.sort(key=lambda f: (f.line, f.col))
    result.findings = findings
    return result


# ---------------------------------------------------------------------------
# Public API: scan
# ---------------------------------------------------------------------------

_C_EXTENSIONS: frozenset[str] = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".c++",
    ".h", ".hh", ".hpp", ".hxx", ".h++",
})


def scan(
    target: str | Path,
    *,
    recursive: bool = True,
    min_severity: str = "info",
    extensions: frozenset[str] = _C_EXTENSIONS,
) -> list[ScanResult]:
    """
    Scan a C/C++ source file or directory for unsafe patterns.

    Parameters
    ----------
    target       : path to a single file or a directory.
    recursive    : if True (default), scan subdirectories recursively.
    min_severity : only return findings at or above this severity level.
                   One of "critical", "high", "medium", "low", "info".
    extensions   : set of file extensions to scan (default: C/C++ extensions).

    Returns
    -------
    list[ScanResult]
        One ScanResult per scanned file, in filesystem order.
        Files with no findings are included (empty findings list).

    Raises
    ------
    FileNotFoundError
        If *target* does not exist.
    ValueError
        If *target* is not a file or directory.

    Examples
    --------
    >>> results = scan("src/vuln.c")
    >>> for r in results:
    ...     for f in r.by_severity("high"):
    ...         print(f.line, f.sink, f.cwe)
    """
    p = Path(target)
    if not p.exists():
        raise FileNotFoundError(f"Target not found: {p}")

    files: list[Path] = []

    if p.is_file():
        files = [p]
    elif p.is_dir():
        glob_fn = p.rglob if recursive else p.glob
        files = sorted(
            f for f in glob_fn("*")
            if f.is_file() and f.suffix.lower() in extensions
        )
    else:
        raise ValueError(f"Target is neither a file nor a directory: {p}")

    results: list[ScanResult] = []
    threshold = _SEVERITY_RANK.get(min_severity, 0)

    for file in files:
        r = _scan_file(file)
        # Filter findings by severity
        r.findings = [f for f in r.findings
                      if _SEVERITY_RANK.get(f.severity, 0) >= threshold]
        results.append(r)

    return results


# ---------------------------------------------------------------------------
# Public API: format_report
# ---------------------------------------------------------------------------

_SEV_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

_SEV_COLOR = {
    "critical": "\033[91m",
    "high":     "\033[33m",
    "medium":   "\033[93m",
    "low":      "\033[94m",
    "info":     "\033[37m",
}


def format_scan_report(
    results: list[ScanResult],
    *,
    color: bool = True,
    show_snippet: bool = True,
) -> str:
    """
    Render scan results as a human-readable terminal report.

    Parameters
    ----------
    results      : list of ScanResult objects from scan().
    color        : emit ANSI escape codes (default True).
    show_snippet : include the source snippet for each finding (default True).

    Returns
    -------
    str
        Multi-line formatted report.
    """
    BOLD  = "\033[1m"  if color else ""
    RESET = "\033[0m"  if color else ""
    DIM   = "\033[2m"  if color else ""
    RED   = "\033[91m" if color else ""

    total_findings = sum(len(r.findings) for r in results)
    total_critical = sum(r.critical_count for r in results)
    total_high     = sum(r.high_count for r in results)
    total_files    = len(results)
    files_with_findings = sum(1 for r in results if r.findings)

    lines: list[str] = [
        f"{BOLD}{'─' * 68}{RESET}",
        f"{BOLD}  Aegis scan — Static Source Analysis{RESET}",
        f"  Files scanned : {total_files}  ({files_with_findings} with findings)",
        f"  Total findings: {RED if total_critical else ''}{total_findings}{RESET}  "
        f"({total_critical} critical, {total_high} high)",
        f"{BOLD}{'─' * 68}{RESET}",
    ]

    for result in results:
        if not result.findings and not result.errors:
            continue

        rel_path = result.path
        lines.append(f"\n{BOLD}  {rel_path}{RESET}  {DIM}({result.lines_total} lines){RESET}")

        for e in result.errors:
            lines.append(f"    {RED}! {e}{RESET}")

        for f in result.findings:
            sev_col = _SEV_COLOR.get(f.severity, "") if color else ""
            icon    = _SEV_ICON.get(f.severity, "•")
            lines.append(
                f"    {icon}  {sev_col}{f.severity.upper():<8}{RESET}  "
                f"L{f.line:<5}  {BOLD}{f.sink}{RESET}  "
                f"{DIM}[{f.cwe}]{RESET}"
            )
            if show_snippet:
                lines.append(f"           {DIM}{f.snippet.strip()[:72]}{RESET}")
            lines.append(f"           {f.detail[:80]}")
            lines.append("")

    lines.append(f"{BOLD}{'─' * 68}{RESET}")
    return "\n".join(lines)
