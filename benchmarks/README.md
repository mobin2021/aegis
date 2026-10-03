# Aegis Test Benchmarks 🎯

This directory contains standalone, reproducible C targets designed to validate Aegis's multi-agent vulnerability discovery, fuzzing triage, and PoC synthesis capabilities.

## Benchmark Matrix

| Target | Vulnerability Class | Trigger Condition | Exploit Primitive |
| :--- | :--- | :--- | :--- |
| `stack_overflow.c` | CWE-121: Stack-based Buffer Overflow | Unchecked `strcpy` with payload > 64 bytes | Return Address (`RIP`) Overwrite |
| `format_string.c` | CWE-134: Use of Externally-Controlled Format String | Direct user input passed to `printf(data)` | Stack Memory Disclosure / Arbitrary Read |
| `off_by_one.c` | CWE-193: Off-by-one Error | Single-byte out-of-bounds loop boundary (`<=`) | Frame Pointer (`RBP`) LSB Corruption |

## Compilation Instructions (GCC / AFL++)

### Standard Compilation (for Analysis & Decompilation):
```bash
gcc -fno-stack-protector -z execstack -no-pie stack_overflow.c -o stack_overflow.bin
gcc format_string.c -o format_string.bin
gcc -fno-stack-protector off_by_one.c -o off_by_one.bin
```

### Instrumented Fuzzing Build (AFL++):
```bash
afl-clang-fast -g -fsanitize=address stack_overflow.c -o stack_overflow.afl
```
