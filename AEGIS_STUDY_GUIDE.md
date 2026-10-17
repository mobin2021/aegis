# AEGIS 2.0: Complete Technical Interview Defense & Visual Study Guide
**Target Role:** Systems Software Engineer / Vulnerability Researcher / Security Tools Developer  
**Author:** MD. Raisul Islam Mobin (1st-Year CSE, Brahmaputra International University)

---

## 1. The 30-Second Elevator Pitch (Memorize This)
> *"Aegis is an autonomous binary vulnerability research and mitigation pipeline built in Python with a native desktop workstation. Given an executable or C source file, Aegis inspects its compiler hardening flags, performs AST-level taint scanning on memory sinks, models the deterministic x86/x64 stack frame layout, and automatically generates both a proof-of-concept crash test vector and a production-grade compiler mitigation patch."*

---

## 2. Curated Visual Video Syllabus (Watch These on YouTube!)

Watching these 10-15 minute videos will turn the text into clear mental pictures:

### 📺 Topic 1: The Stack, Registers, and Buffer Overflows
*Maps to Aegis module:* [`aegis/core/frame_model.py`](file:///C:/Users/ZBook%20Firefly%2014%20G11/AEGIS%202.0/aegis/core/frame_model.py)
1. **[Buffer Overflow Attacks - Computerphile](https://www.youtube.com/watch?v=1S0aBV-Waeo)** (Prof. Mike Pound, 11 mins)
   - *Why watch:* The clearest whiteboard animation of how a local variable sits next to the Saved Frame Pointer (`RBP`) and Return Address (`RIP`).
2. **[LiveOverflow - 0x05 Buffer Overflow with simple shellcode](https://www.youtube.com/watch?v=HSlhY4Uy8SA)** (LiveOverflow, 12 mins)
   - *Why watch:* Shows GDB memory stepping and how writing past a buffer corrupts the instruction pointer.

---

### 📺 Topic 2: Checksec & Compiler Mitigations (Canary, NX, ASLR)
*Maps to Aegis module:* [`aegis/tools/checksec.py`](file:///C:/Users/ZBook%20Firefly%2014%20G11/AEGIS%202.0/aegis/tools/checksec.py)
1. **[LiveOverflow - 0x0E Stack Canaries / Cookies](https://www.youtube.com/watch?v=kYc5eL77Qqw)** (LiveOverflow, 11 mins)
   - *Why watch:* Shows why `__stack_chk_fail` exists and why Aegis checks for the `0x00` null byte in canary values.
2. **[LiveOverflow - 0x09 Data Execution Prevention (DEP / NX)](https://www.youtube.com/watch?v=vduYd2q2Yvg)** (LiveOverflow, 8 mins)
   - *Why watch:* Explains the NX (No-Execute) bit and why modern exploits cannot simply execute shellcode in the stack.
3. **[LiveOverflow - 0x0D ASLR (Address Space Layout Randomization)](https://www.youtube.com/watch?v=l_a0xPj_e9A)** (LiveOverflow, 9 mins)
   - *Why watch:* Explains why PIE (Position Independent Executable) randomizes memory addresses on every run.

---

### 📺 Topic 3: Cyclic Patterns (De Bruijn Sequences)
*Maps to Aegis module:* [`aegis/tools/cyclic.py`](file:///C:/Users/ZBook%20Firefly%2014%20G11/AEGIS%202.0/aegis/tools/cyclic.py) & [`poc_synthesizer.py`](file:///C:/Users/ZBook%20Firefly%2014%20G11/AEGIS%202.0/aegis/core/poc_synthesizer.py)
1. **[LiveOverflow - 0x0A Finding the exact buffer length with patterns](https://www.youtube.com/watch?v=yP5_0zYQ8g4)** (LiveOverflow, 9 mins)
   - *Why watch:* Shows exactly why sending `Aa0Aa1Aa2...` instantly calculates the crash offset without guessing numbers!

---

### 📺 Topic 4: Dangerous C Functions & Compiler Hardening
*Maps to Aegis module:* [`aegis/core/source_scanner.py`](file:///C:/Users/ZBook%20Firefly%2014%20G11/AEGIS%202.0/aegis/core/source_scanner.py) & [`patch_engineer.py`](file:///C:/Users/ZBook%20Firefly%2014%20G11/AEGIS%202.0/aegis/core/patch_engineer.py)
1. **[Low Level Learning - The Most Dangerous Function in C](https://www.youtube.com/watch?v=4C5f6P4f6l8)** (Low Level Learning, 8 mins)
   - *Why watch:* Shows why `gets()` and unbounded `strcpy()` lead directly to CWE-120 and how `fgets()` and `strncpy()` fix it.
2. **[LiveOverflow - Format String Vulnerabilities (printf)](https://www.youtube.com/watch?v=0WvrSfcdq1I)** (LiveOverflow, 14 mins)
   - *Why watch:* Explains CWE-134 (printf without `%s` format specifier) which our `source_scanner` detects and `patch_engineer` fixes.

---

## 3. The Entire System in 5 Plain-English Mental Models

| Module | Real-World Analogy | What it actually does in Aegis |
| :--- | :--- | :--- |
| **1. `checksec.py`** | **The Security Guard** | Reads binary headers (ELF / PE) to check if armor is on: NX (DEP), Stack Canaries, PIE/ASLR, and RELRO. |
| **2. `source_scanner.py`** | **The Metal Detector** | Scans C code for dangerous functions (`strcpy`, `gets`, `sprintf`) and checks if bounds checks exist. |
| **3. `frame_model.py`** | **The Blueprint Ruler** | Measures exact byte distances on the CPU stack: Buffer $\to$ Canary $\to$ Alignment $\to$ Saved Frame Pointer $\to$ Return Address (`RIP`/`EIP`). |
| **4. `poc_synthesizer.py`** | **The Crash Reproducer** | Synthesizes a standalone, safe Python script using cyclic de Bruijn patterns to verify instruction pointer control without payload bytes. |
| **5. `patch_engineer.py`** | **The Automated Surgeon** | Rewrites unsafe C calls to bounded modern APIs (`strncpy`, `fgets`, `snprintf`) and outputs a unified `.patch` diff and compiler hardening flags. |

---

## 4. The End-to-End Pipeline Flow

```
+--------------------------------------------------------------------+
|                        TARGET (Binary or C File)                    |
+--------------------------------------------------------------------+
                                   |
         +-------------------------+-------------------------+
         |                                                   |
         v                                                   v
 [checksec.py]                                      [source_scanner.py]
 * Binary Mitigations:                               * AST Syntax Tree Scan:
   - Canary: Disabled                                  - Sink: strcpy(buf, input)
   - NX: Enabled                                       - CWE: CWE-120
   - PIE: None                                         - Severity: HIGH
         |                                                   |
         +-------------------------+-------------------------+
                                   |
                                   v
                          [frame_model.py]
                    * Stack Frame Layout Calculator:
                      - Architecture: x86_64
                      - Buffer Size: 64 bytes
                      - Alignment: 16-byte boundary
                      - Saved RBP: 8 bytes
                      - RIP Offset: 72 bytes
                                   |
         +-------------------------+-------------------------+
         |                                                   |
         v                                                   v
[poc_synthesizer.py]                                [patch_engineer.py]
 * Synthesizes Standalone PoC:                       * Generates Mitigation Patch:
   - Safe de Bruijn cyclic pattern                     - Replaces strcpy -> strncpy
   - Verifies crash offset 72                          - Produces unified diff (.patch)
   - Zero raw shellcode payloads                       - Recommends -fstack-protector
                                   |
                                   v
                   [aegis/gui/ (Aegis Studio)]
             * Real-time Liquid Glass Telemetry
             * Split-screen code canvas
             * Instant 1-click mitigation export
```

---

## 5. Top 6 Questions Interviewers Will Ask & Your Exact Answers

### Q1: *"Why did you build this in Python standard library instead of using existing tools like pwntools?"*
**Your Answer:**
> *"Pwntools is great for CTFs, but it is a heavy dependency that often has complex build prerequisites on Windows and minimal cross-platform GUI support. By designing Aegis with pure Python 3.12 standard library, the entire triage pipeline runs in under 0.8 seconds, has zero external CVE attack surface, and executes natively across Windows, Linux, and macOS without extra installs."*

### Q2: *"How does your stack frame model calculate the exact return pointer (RIP) offset?"*
**Your Answer:**
> *"On x86_64 System V and Windows x64 ABIs, stack frames are aligned to 16-byte boundaries for SSE vector instructions. When a function allocates a local buffer, the compiler pads it to maintain that alignment. Aegis models the memory layout: Buffer size plus alignment padding, plus an optional 8-byte stack canary if present, plus 8 bytes for the saved base pointer (`RBP`). The byte immediately following is the Return Address (`RIP`). So for a 64-byte buffer with no canary, the offset is 64 + 8 = 72 bytes."*

### Q3: *"What is a de Bruijn cyclic pattern and why is it better than sending 1,000 'A's?"*
**Your Answer:**
> *"If you crash a program with 1,000 'A's (`0x41414141`), the instruction pointer will hold `0x41414141`, but you have no idea which of the 1,000 bytes overwrote it. A de Bruijn sequence is an algorithmic string where every substring of length $N$ (e.g. 4 or 8 bytes) is unique. When the program crashes at a specific 4-byte value like `aAa1`, our `cyclic_find()` function mathematically computes the exact byte index in $O(1)$ time."*

### Q4: *"How does Aegis automatically patch unsafe C code without breaking syntax?"*
**Your Answer:**
> *"Our `patch_engineer` analyzes the AST and regex context around known dangerous sinks like `strcpy` and `sprintf`. It maps them to bounds-checked standard equivalents like `strncpy` or `snprintf`, injects `sizeof(dest) - 1`, ensures explicit null-termination, and formats the output into a standard unified diff format compatible with the UNIX `patch` utility."*

### Q5: *"How does the Aegis Studio desktop GUI talk to the Python backend?"*
**Your Answer:**
> *"We built Aegis Studio using Microsoft WebView2 and an asynchronous JSON-RPC IPC bridge (`bridge.py`). The frontend is pure HTML5, CSS liquid-glass styling, and vanilla JavaScript. When the user selects a target and clicks 'Run Triage', the JavaScript dispatches a message through `window.chrome.webview.postMessage`, Python processes the pipeline asynchronously, and returns structured telemetry cards and diffs without freezing the UI."*

### Q6: *"How did you test the reliability of Aegis?"*
**Your Answer:**
> *"We maintain a comprehensive automated test suite with 129 unit tests and subtests covering every module—checksec parsing, cyclic generation and lookup, stack frame boundary arithmetic, AST scanning, and patch diff validity. All 129 tests execute in less than 0.75 seconds with a 100% pass rate."*

---

## 6. Rescue Phrases (If You Don't Know the Answer)

If a recruiter asks something obscure (e.g. *"How would your frame model handle variable-length arrays allocated via alloca()?"*):

- **Phrase 1:**  
  *"In the current implementation of Aegis 2.0, we model static stack allocations defined at compile time. Handling dynamic runtime stack allocations like `alloca()` would require dynamic binary instrumentation through GDB or Frida, which is currently on our roadmap for Aegis 3.0."*
- **Phrase 2:**  
  *"I haven't tested that specific edge case yet, but based on our architecture, the pipeline would..."*
- **Phrase 3:**  
  *"That's a great systems question. We focused first on deterministic compile-time sinks like `strcpy` (CWE-120), but the modular structure of our `FrameModel` class makes it easy to plug in a dynamic hook for that."*
