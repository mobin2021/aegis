# Aegis 2.0 — Binary Security Analysis Framework & Studio

[![Tests](https://github.com/mobin2021/aegis/actions/workflows/test.yml/badge.svg)](https://github.com/mobin2021/aegis/actions/workflows/test.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2011%20%7C%20Linux-lightgrey.svg)]()

> A real-engineering, zero-fluff binary security analysis toolkit built on pure Python 3.12 stdlib — plus a native **Windows 11 Liquid Glass** desktop GUI (Aegis Studio).

---

## Features

| Engine | What it does |
|--------|-------------|
| **`cyclic`** | Mathematically-sound De Bruijn B(26,4) pattern generator + crash-value → byte-offset resolver (32-bit & 64-bit) |
| **`checksec`** | Raw PE32/PE32+/ELF32/ELF64 byte-header parser — audits NX/DEP, ASLR/PIE, Stack Canary, RELRO, SafeSEH, CFG |
| **`scan`** | Dual-pass C/C++ static AST+regex analyser — catches CWE-120, CWE-121, CWE-134, CWE-78, CWE-676 sinks |
| **`gui`** | Frameless acrylic Aegis Studio (pywebview + Edge WebView2) with drag-and-drop binary ingestion, live SHA-256, mitigation matrix, and interactive stack-overflow visualiser |

---

## Quick Start

### 1 · Install (editable local install)

```bash
# Core CLI only (zero third-party deps)
pip install -e .

# Core + GUI support
pip install -e ".[gui]"

# Core + GUI + dev/test tools
pip install -e ".[dev]"
```

### 2 · Verify

```bash
aegis --help
```

---

## CLI Usage

### Generate a De Bruijn cyclic pattern

```bash
aegis cyclic 200
```

### Resolve a crash register value to byte offset

```bash
aegis cyclic --find 0x61616264 --arch 32
# [+] Offset: 3  (0x3)
```

### Inspect binary mitigations

```bash
aegis checksec /path/to/binary.exe
aegis checksec /usr/bin/ls --no-color
```

```
╔══════════════════════════════════════════════════╗
║            Aegis 2.0 · checksec Report           ║
╠══════════════════════════════════════════════════╣
║  Binary : /path/to/binary.exe                    ║
║  Format : PE32+                                  ║
║  SHA-256: a3f2...                                ║
╠══════════════════════════════════════════════════╣
║  NX / DEP    ✅ Enabled    (DllCharacteristics)  ║
║  ASLR        ✅ Full       (DYNAMIC_BASE+HEVA)   ║
║  Stack Canary✅ Present    (__security_cookie)    ║
║  CFG         ✅ Enabled    (Guard CF)             ║
║  RELRO       ➖ N/A        (PE binary)            ║
║  SafeSEH     ➖ N/A        (64-bit PE)            ║
╠══════════════════════════════════════════════════╣
║  Hardening Score: 4 / 4   ████████████ 100%      ║
╚══════════════════════════════════════════════════╝
```

### Scan C/C++ source for vulnerabilities

```bash
aegis scan ./src/
aegis scan ./src/ --severity high --no-color
```

```
[CRITICAL] CWE-120 · Buffer Copy Without Size Check
  File   : src/main.c : 42
  Sink   : strcpy
  Snippet: strcpy(dst, src);
```

### Launch Aegis Studio (Windows 11 GUI)

```bash
aegis gui
# or simply:
python -m aegis
```

---

## Architecture

```
aegis-studio/
├── aegis/
│   ├── __init__.py          # version = "2.0.0"
│   ├── __main__.py          # python -m aegis → cli.main()
│   ├── cli.py               # argparse entrypoint (gui/cyclic/checksec/scan)
│   ├── bridge.py            # Type-safe Python↔JavaScript IPC bridge
│   ├── core/
│   │   ├── cyclic.py        # De Bruijn generator + offset resolver
│   │   ├── checksec.py      # PE/ELF raw-byte mitigation parser
│   │   └── source_scanner.py# Dual-pass CWE static scanner
│   └── gui/
│       ├── __init__.py      # launch_studio() via pywebview
│       ├── index.html       # 3-tab frameless acrylic UI
│       ├── main.css         # Windows 11 Liquid Glass theme
│       └── app.js           # Runtime controller
└── tests/
    ├── test_cyclic.py        # 26 tests (11 subtests)
    ├── test_checksec.py      # 38 tests (synthetic PE/ELF blobs)
    ├── test_source_scanner.py# 23 tests (CWE-120/121/134/78/676)
    └── test_bridge.py        # 14 tests (IPC bridge)
```

**Design principles**

- **Zero external deps for core** — `struct`, `re`, `hashlib`, `pathlib`, `dataclasses` only
- **pywebview** is an *optional* dep, only loaded by `aegis gui`
- All test fixtures are 100% synthetic in-memory binary blobs — no real OS binaries required

---

## Running Tests

```bash
# Full suite (101 tests expected)
pytest

# With coverage
pip install pytest-cov
pytest --cov=aegis --cov-report=term-missing
```

Expected output:

```
101 passed, 11 subtests passed in 0.80s
```

---

## CI / GitHub Actions

Every push and pull request automatically runs the full test suite on:
- **Ubuntu** (Python 3.12)
- **Windows** (Python 3.12)

See [`.github/workflows/test.yml`](.github/workflows/test.yml) for the full pipeline.

> **Badge setup:** After pushing to GitHub, replace `YOUR_USERNAME` in the badge URLs at the top of this file with your actual GitHub username.

---

## CWE Coverage

| CWE | Name | Detected sinks |
|-----|------|---------------|
| CWE-120 | Buffer Copy Without Checking Size | `strcpy` `gets` `sprintf` `scanf %s` `strcat` `wcscpy` `stpcpy` `strncpy` |
| CWE-121 | Stack-Based Buffer Overflow | `alloca` `memcpy(…strlen…)` VLAs |
| CWE-134 | Uncontrolled Format String | `printf`/`fprintf`/`syslog` with non-literal format |
| CWE-78 | OS Command Injection | `system()` `popen()` |
| CWE-676 | Use of Potentially Dangerous Function | `tmpnam` `mktemp` `rand` |

---

## License

MIT © Aegis Project
