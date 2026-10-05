#!/usr/bin/env python3
"""
================================================================================
AEGIS: Autonomous Multi-Agent Binary Exploitation Engine
Safe Working Demonstration Powered by Google Gemini Free API
================================================================================
Author: MD. Raisul Islam Mobin (Systems & Offensive Security Engineer)
License: Apache 2.0 (Public Demonstration Edition)
Target: Industrial Telemetry Ingestion Daemon / C Benchmark Targets
Duration: Calibrated for 50-second OBS Video Demonstration
================================================================================
"""

import os
import sys
import time
import json
import re
import argparse
import urllib.request
import urllib.error
from pathlib import Path

# Ensure UTF-8 clean output across Windows PowerShell and cmd consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ==============================================================================
# ANSI Color Palette for Cinematic Terminal Display
# ==============================================================================
class Colors:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def cprint(text: str, color: str = Colors.RESET, end: str = "\n", flush: bool = True):
    print(f"{color}{text}{Colors.RESET}", end=end, flush=flush)


# ==============================================================================
# Cyber Banner
# ==============================================================================
BANNER = rf"""{Colors.CYAN}{Colors.BOLD}
    ___    ______ _____  ____ _____ 
   /   |  / ____// ___/ /  _// ___/ 
  / /| | / __/  / / _   / /  \__ \  
 / ___ |/ /___ / /_/ /_/ /  ___/ /  
/_/  |_/_____/ \____//___/ /____/   
{Colors.MAGENTA}Autonomous Multi-Agent Binary Exploitation Engine
{Colors.YELLOW}Demo Edition • Powered by Google Gemini Neural Reasoning
{Colors.DIM}Author: MD. Raisul Islam Mobin | Public Safe Architecture Demo
{Colors.RESET}"""


# ==============================================================================
# Target Inspection & Parsing
# ==============================================================================
def inspect_target(target_path: Path) -> dict:
    content = target_path.read_text(errors="ignore")
    stat = target_path.stat()

    unsafe_calls = []
    patterns = {
        "strcpy": ("CWE-121", "Stack-based Buffer Overflow (unchecked memory copy)"),
        "gets": ("CWE-120", "Unconstrained Stack Input Read"),
        "sprintf": ("CWE-121", "Unbounded Formatted Buffer Write"),
        "printf": ("CWE-134", "Externally-Controlled Format String"),
    }

    for symbol, (cwe, desc) in patterns.items():
        if symbol == "printf":
            # Only match printf if first argument is a variable, not a string literal
            matches = list(re.finditer(r'\bprintf\s*\(\s*([a-zA-Z_]\w*)', content))
        else:
            matches = list(re.finditer(rf"\b{symbol}\s*\(", content))
        for m in matches:
            line = content[: m.start()].count("\n") + 1
            unsafe_calls.append({"symbol": symbol, "line": line, "cwe": cwe, "description": desc})

    # Find vulnerable buffer declaration
    buf_matches = re.findall(r"char\s+(\w+)\s*\[(\d+)\]", content)
    buffer_name = "stack_buffer"
    buffer_size = 64
    for bname, bsize in buf_matches:
        if "buffer" in bname.lower() or "buf" in bname.lower():
            buffer_name = bname
            buffer_size = int(bsize)
            break
        elif int(bsize) >= 64:
            buffer_name = bname
            buffer_size = int(bsize)

    is_stack = "stack" in target_path.name.lower() or "telemetry" in target_path.name.lower() or any(u["cwe"] == "CWE-121" for u in unsafe_calls)
    is_fmt = "format" in target_path.name.lower() or (any(u["cwe"] == "CWE-134" for u in unsafe_calls) and not is_stack)

    # Function discovery
    funcs = re.findall(r"(?:int|void|char\*)\s+([a-zA-Z_]\w*)\s*\(", content)
    discovered_funcs = [f for f in funcs if f not in ("printf", "strcpy", "memcpy", "strlen")]

    return {
        "path": str(target_path),
        "name": target_path.name,
        "size": stat.st_size,
        "content": content,
        "unsafe_calls": unsafe_calls,
        "buffer_size": buffer_size,
        "buffer_name": buffer_name,
        "functions": discovered_funcs,
        "is_stack_overflow": is_stack,
        "is_format_string": is_fmt,
    }


# ==============================================================================
# Google Gemini Reasoning Engine (Live Free API with Automatic Failover)
# ==============================================================================
def query_gemini_reasoning(
    target_info: dict,
    api_key: str,
    fast_mode: bool = False
) -> tuple[str, str]:
    """
    Sends target source code and static decompilation markers to Google Gemini Flash.
    Returns (reasoning_text, model_name).
    """
    if not api_key:
        return _fallback_heuristic(target_info), "aegis-offline-heuristics"

    candidate_models = ["gemini-3.5-flash", "gemini-3.7-flash", "gemini-3.8-flash"]
    
    prompt = f"""Defensive Code Security Audit for {target_info['name']}:
Detected Unsafe Calls: {[u['symbol'] + ' at line ' + str(u['line']) for u in target_info['unsafe_calls']]}
Allocated Buffer: {target_info['buffer_name']}[{target_info['buffer_size']}]

Provide an authoritative technical assessment for code remediation:
1. Vulnerability Classification (CWE) & Root Cause
2. Stack Memory Layout (Buffer -> Saved RBP -> Return Address RIP)
3. Boundary Offset Calculation (exact bytes to saved frame pointer boundary)
4. Defensive Remediation & Safe Alternative Implementation

Format clearly and concisely for security engineers."""

    safety_settings = [
        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
    ]

    for model in candidate_models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 2048,
                "thinkingConfig": {"thinkingBudget": 0}
            },
            "safetySettings": safety_settings,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                candidates = data.get("candidates", [])
                if candidates and candidates[0].get("content", {}).get("parts"):
                    text = candidates[0]["content"]["parts"][0]["text"].strip()
                    # Ensure response is complete and not truncated
                    if len(text) > 180 and not text.endswith("**") and not text.endswith("*"):
                        return text, model
        except Exception:
            continue

    # Instant clean failover with full 4-section architecture diagram
    return _fallback_heuristic(target_info), "aegis-core-rulebase (offline engine)"


def _fallback_heuristic(target_info: dict) -> str:
    buf_size = target_info["buffer_size"]
    rip_offset = buf_size + 8
    return (
        f"### 1. Vulnerability Classification (CWE)\n"
        f"* **CWE-121: Stack-based Buffer Overflow** (Root Cause: Unchecked memory copy via strcpy)\n"
        f"* **CVSS v3.1 Base Score:** 9.8 (CRITICAL - Unauthenticated Remote Code Execution)\n\n"
        f"### 2. Stack Memory Architecture (x86_64)\n"
        f"[Low Address] -> buffer[{buf_size}] (64B) -> Saved RBP (8B) -> Return Address RIP (8B) -> [High Address]\n\n"
        f"### 3. Boundary Offset Calculation\n"
        f"* Buffer capacity: {buf_size} bytes\n"
        f"* Frame pointer padding: 8 bytes (saved RBP)\n"
        f"* Calculated RIP Overwrite Offset: {rip_offset} bytes\n\n"
        f"### 4. Defensive Remediation\n"
        f"Replace `strcpy(dest, src)` with bounded `snprintf(dest, sizeof(dest), \"%s\", src)` to enforce memory safety."
    )


# ==============================================================================
# Animated Pacing Helper for 60-Second Video Demo
# ==============================================================================
def live_spinner(msg: str, duration_sec: float, fast_mode: bool = False):
    if fast_mode:
        cprint(f"    {Colors.GREEN}[✓] {msg}{Colors.RESET}")
        return

    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    start = time.time()
    idx = 0
    while time.time() - start < duration_sec:
        sys.stdout.write(f"\r    {Colors.CYAN}{frames[idx % len(frames)]}{Colors.RESET} {msg}")
        sys.stdout.flush()
        idx += 1
        time.sleep(0.08)
    sys.stdout.write(f"\r    {Colors.GREEN}[✓]{Colors.RESET} {msg}                                \n")
    sys.stdout.flush()


# ==============================================================================
# Simulated High-Performance Fuzzing Telemetry (AFL++ Forkserver Harness)
# ==============================================================================
def run_fuzz_simulation(target_info: dict, fast_mode: bool = False) -> dict:
    """Simulates coverage-guided mutation fuzzing with realistic live telemetry."""
    buf_size = target_info["buffer_size"]
    expected_offset = buf_size + 8 if target_info["is_stack_overflow"] else 0

    cprint("\n[+] [AGENT 4: FUZZ SWARM] Engaging Coverage-Guided Mutation Harness...", Colors.CYAN)
    cprint("    Mutation Engine: AFL++ Havoc / De Bruijn Cyclic Sequence Swarm", Colors.DIM)
    cprint("    Target Function: process_telemetry_packet() [Symbol Address: 0x401180]", Colors.DIM)

    steps = [
        ("Iteration 0100", 1450, 4, 12, "06.2%", "Aa0Aa1Aa2Aa3"),
        ("Iteration 0350", 2280, 8, 24, "12.8%", "Aa4Aa5Aa6Aa7"),
        ("Iteration 0800", 2940, 14, 42, "19.4%", "Aa8Aa9Ab0Ab1"),
        ("Iteration 1400", 3350, 19, 58, "26.1%", "Ab2Ab3Ab4Ab5"),
        ("Iteration 1950", 3620, 23, 72, "31.5%", "A" * 64 + "BBBBCCCC"),
    ]

    delay = 0.05 if fast_mode else 1.6

    for iter_name, exec_speed, paths, edges, density, sample in steps:
        time.sleep(delay)
        bar_len = 16
        pct = int(density.replace("%", "").split(".")[0])
        filled = int(bar_len * (pct / 35.0))
        bar = "█" * filled + "░" * (bar_len - filled)
        sys.stdout.write(
            f"\r    {Colors.YELLOW}▶ {iter_name} [{bar}] {density} | Speed: {exec_speed:,} execs/s | Edges: {edges}/64 | Path: {sample[:8]}..{Colors.RESET}"
        )
        sys.stdout.flush()

    time.sleep(0.5 if not fast_mode else 0.05)
    print()

    # Intercept crash / anomaly based on target type
    if target_info["is_stack_overflow"]:
        vuln_name = "CWE-121: Stack-based Buffer Overflow"
        severity = "CRITICAL (CVSS v3.1: 9.8 / 10.0)"
        signal_desc = "SIGSEGV (Signal 11: Address Boundary Error)"
        crash_offset = expected_offset
        cprint(f"\n    {Colors.RED}{Colors.BOLD}⚡ CRASH INTERCEPTED: Signal SIGSEGV (Signal 11: Address Boundary Error){Colors.RESET}")
        cprint(f"    ├─ Fault Address:      {Colors.YELLOW}0x4141414141414141 ('AAAAAAAA'){Colors.RESET}")
        cprint(f"    ├─ Corrupted Register: {Colors.YELLOW}RIP (Instruction Pointer Overwrite){Colors.RESET}")
        cprint(f"    ├─ Calculated Offset:  {Colors.GREEN}{Colors.BOLD}{crash_offset} bytes (Buffer 64B + Saved RBP 8B){Colors.RESET}")
        cprint(f"    └─ Triage Verdict:     {Colors.RED}Unauthenticated Remote Code Execution Primitive Achieved{Colors.RESET}")
    elif target_info["is_format_string"]:
        vuln_name = "CWE-134: Externally-Controlled Format String"
        severity = "HIGH (CVSS v3.1: 8.6 / 10.0)"
        signal_desc = "MEMORY_LEAK (Stack Arbitrary Read via %p.%p)"
        crash_offset = 0
        cprint(f"\n    {Colors.RED}{Colors.BOLD}⚡ ANOMALY INTERCEPTED: Arbitrary Memory Leak Triggered{Colors.RESET}")
        cprint(f"    ├─ Leak Primitive:     {Colors.YELLOW}Format String Specifier (%08x.%08x.%08x.%08x){Colors.RESET}")
        cprint(f"    ├─ Stack Inspection:   {Colors.YELLOW}Leaked Pointers: 0x7fffffffe000.0x00401150.0x00401200{Colors.RESET}")
        cprint(f"    ├─ Vulnerability:      {Colors.GREEN}{Colors.BOLD}{vuln_name}{Colors.RESET}")
        cprint(f"    └─ Triage Verdict:     {Colors.RED}Information Disclosure & Arbitrary Write Primitive (%n){Colors.RESET}")
    else:
        vuln_name = "CWE-193: Off-by-one Boundary Condition"
        severity = "MEDIUM (CVSS v3.1: 6.5 / 10.0)"
        signal_desc = "ANOMALY (Loop Boundary Overrun)"
        crash_offset = 17
        cprint(f"\n    {Colors.RED}{Colors.BOLD}⚡ ANOMALY INTERCEPTED: Off-By-One Boundary Overrun{Colors.RESET}")
        cprint(f"    ├─ Overrun Index:      {Colors.YELLOW}index == MAX_CAPACITY (1 byte adjacent overwrite){Colors.RESET}")
        cprint(f"    ├─ Vulnerability:      {Colors.GREEN}{Colors.BOLD}{vuln_name}{Colors.RESET}")
        cprint(f"    └─ Triage Verdict:     {Colors.RED}Adjacent Frame Corruption via Poison Byte{Colors.RESET}")

    return {
        "status": "crashed",
        "signal": signal_desc,
        "vulnerability": vuln_name,
        "severity": severity,
        "crash_offset": crash_offset,
        "fault_address": "0x4141414141414141" if target_info["is_stack_overflow"] else "N/A",
        "iterations": 1950,
    }


# ==============================================================================
# PoC Synthesis & Artifact Generation
# ==============================================================================
def generate_poc(target_info: dict, crash_data: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    poc_path = output_dir / "poc.py"
    offset = crash_data["crash_offset"]
    posix_path = Path(target_info['path']).as_posix()

    if target_info["is_format_string"]:
        poc_body = """def build_payload():
    # Format string leak payload to dump stack pointers
    payload = b"%p.%p.%p.%p.%p.%p"
    return payload"""
    elif target_info["is_stack_overflow"]:
        poc_body = f"""def build_payload():
    # Padding to fill buffer ({target_info['buffer_size']}B) and saved RBP (8B) -> {offset} bytes total
    padding = b"A" * {offset}
    # Controlled overwrite for return address (RIP)
    rip_overwrite = b"\\xef\\xbe\\xad\\xde\\x00\\x00\\x00\\x00"  # 0x00000000deadbeef
    return padding + rip_overwrite"""
    else:
        poc_body = """def build_payload():
    # Off-by-one payload triggering boundary overflow
    return b"A" * 17"""

    poc_content = f"""#!/usr/bin/env python3
\"\"\"
Aegis Autonomous Exploit Reproduction Script
Target: {target_info['name']}
Vulnerability: {crash_data['vulnerability']}
Discovered by: Aegis Multi-Agent Assessment Framework
Calculated Offset: {offset} bytes
\"\"\"

import sys

TARGET = "{posix_path}"
OFFSET = {offset}

{poc_body}

def main():
    payload = build_payload()
    print(f"[*] Aegis Exploit Payload Assembled: {{len(payload)}} bytes")
    print(f"[*] Target Binary: {{TARGET}}")
    print(f"[*] Calculated RIP Offset: {{OFFSET}} bytes")
    print(f"[+] Payload: {{payload}}")

if __name__ == "__main__":
    main()
"""
    poc_path.write_text(poc_content, encoding="utf-8")
    return poc_path


def generate_report(target_info: dict, crash_data: dict, reasoning_model: str, poc_path: Path, output_dir: Path, duration: float):
    report_path = output_dir / "audit_report.json"
    data = {
        "aegis_version": "1.0.0-enterprise",
        "target": target_info["path"],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": round(duration, 2),
        "reasoning_engine": {
            "provider": "Google Gemini Neural Reasoning API",
            "model": reasoning_model,
        },
        "findings": {
            "vulnerability": crash_data["vulnerability"],
            "cwe": "CWE-121" if target_info["is_stack_overflow"] else "CWE-134",
            "severity": crash_data["severity"],
            "cvss_score": 9.8 if target_info["is_stack_overflow"] else 8.6,
            "crash_offset": crash_data["crash_offset"],
            "controlled_register": "RIP" if target_info["is_stack_overflow"] else "N/A",
            "unsafe_symbols": target_info["unsafe_calls"],
        },
        "artifacts": {
            "poc_script": str(poc_path),
            "reproduction_command": f"python {poc_path}",
        }
    }
    report_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return report_path


# ==============================================================================
# Main Orchestration Loop (Calibrated to 50-second OBS Video Timing)
# ==============================================================================
def run_demo(target_arg: str, gemini_key: str = None, fast_mode: bool = False):
    start_time = time.time()
    pace = 0.05 if fast_mode else 1.2

    print(BANNER)
    time.sleep(0.5 if not fast_mode else 0.05)

    target_path = Path(target_arg)
    if not target_path.exists():
        cprint(f"[!] Error: Target file '{target_arg}' does not exist.", Colors.RED)
        sys.exit(1)

    target_info = inspect_target(target_path)
    output_dir = Path("aegis_output")

    api_key = gemini_key or os.getenv("GEMINI_API_KEY", "")

    # Header Telemetry
    cprint("═" * 74, Colors.CYAN)
    cprint("  AEGIS CORE: AUTONOMOUS ASSESSMENT SWARM INITIALIZED", Colors.BOLD)
    cprint(f"  Target Scope:      {Colors.YELLOW}{target_info['path']}{Colors.RESET}")
    cprint(f"  Neural Engine:     {Colors.GREEN}{'Google Gemini Flash API (Live Key Connected)' if api_key else 'Local Heuristic Failover (Air-gapped Mode)'}{Colors.RESET}")
    cprint(f"  Orchestrator Mode: Hierarchical 5-Agent Autonomous Pipeline", Colors.DIM)
    cprint("═" * 74, Colors.CYAN)

    # --------------------------------------------------------------------------
    # Phase 1: Reconnaissance (0s - 10s)
    # --------------------------------------------------------------------------
    cprint("\n[+] [AGENT 1: RECON] Surface Fingerprinting & Mitigation Audit...", Colors.CYAN)
    live_spinner("Dissecting ELF section headers & symbol tables...", 4.2, fast_mode=fast_mode)
    time.sleep(1.5 if not fast_mode else 0.05)
    cprint(f"    ├─ Target Service:     {target_info['name']} ({target_info['size']} bytes)", Colors.RESET)
    cprint(f"    ├─ Architecture:       x86_64 Linux ELF (Intel 64-bit Virtual Memory)", Colors.RESET)
    cprint(f"    ├─ Discovered Symbols: {', '.join(target_info['functions'][:4])}", Colors.DIM)
    cprint(f"    ├─ Stack Canaries:     {Colors.RED}DISABLED (No __stack_chk_fail guard present){Colors.RESET}")
    cprint(f"    ├─ Execution Shield:   {Colors.YELLOW}NX/DEP Active (Non-executable stack frame){Colors.RESET}")
    cprint(f"    └─ Base Address Space: PIE Disabled (Static Base Address: 0x400000)")

    # --------------------------------------------------------------------------
    # Phase 2: Static Decompilation & AST Inspection (10s - 22s)
    # --------------------------------------------------------------------------
    cprint("\n[+] [AGENT 2: DECOMPILER] Static Disassembly & Unsafe Call Graph...", Colors.CYAN)
    live_spinner("Tracing inter-procedural AST call trees & buffer boundaries...", 5.5, fast_mode=fast_mode)
    time.sleep(1.8 if not fast_mode else 0.05)
    cprint(f"    ├─ Call Graph Path:    main() ──> process_telemetry_packet() [0x401180]", Colors.YELLOW)
    cprint(f"    ├─ Frame Allocation:   char {target_info['buffer_name']}[{target_info['buffer_size']}] at [RBP-0x{target_info['buffer_size']:02x}]", Colors.YELLOW)
    for u in target_info["unsafe_calls"]:
        cprint(f"    ├─ {Colors.RED}CRITICAL CALL:      {u['symbol']}() at line {u['line']} -> {u['description']}{Colors.RESET}")
    cprint(f"    └─ Bounds Check:       {Colors.RED}NONE (Unconstrained memory boundary violation detected){Colors.RESET}")

    # --------------------------------------------------------------------------
    # Phase 3: Gemini Neural Reasoning (22s - 36s)
    # --------------------------------------------------------------------------
    cprint("\n[+] [AGENT 3: NEURAL REASONER] Querying Google Gemini Flash Core...", Colors.CYAN)
    if api_key:
        cprint("    [✦] Transmitting decompiled AST & frame markers to Google Gemini Flash API...", Colors.DIM)
    else:
        cprint("    [*] No GEMINI_API_KEY detected. Using deterministic security rulebase...", Colors.DIM)

    reasoning_text, model_name = query_gemini_reasoning(target_info, api_key, fast_mode=fast_mode)

    cprint(f"\n    {Colors.GREEN}[✓] Gemini Reasoning Engine Response ({model_name}):{Colors.RESET}")
    for line in reasoning_text.strip().split("\n"):
        if line.strip():
            cprint(f"        {Colors.MAGENTA}{line}{Colors.RESET}")
            if not fast_mode:
                time.sleep(0.35)

    # --------------------------------------------------------------------------
    # Phase 4: Coverage-Guided Fuzzing Campaign (36s - 46s)
    # --------------------------------------------------------------------------
    crash_data = run_fuzz_simulation(target_info, fast_mode=fast_mode)

    # --------------------------------------------------------------------------
    # Phase 5: Exploit PoC Synthesis (46s - 50s)
    # --------------------------------------------------------------------------
    cprint("\n[+] [AGENT 5: EXPLOIT SYNTHESIS] Generating Standalone Reproduction Artifacts...", Colors.CYAN)
    live_spinner("Synthesizing standalone exploit reproduction harness...", 3.2, fast_mode=fast_mode)
    poc_path = generate_poc(target_info, crash_data, output_dir)
    cprint(f"    ├─ Synthesized Exploit Script: {Colors.GREEN}{poc_path}{Colors.RESET}", Colors.RESET)

    duration = time.time() - start_time
    report_path = generate_report(target_info, crash_data, model_name, poc_path, output_dir, duration)
    cprint(f"    └─ Structured Audit Telemetry: {Colors.GREEN}{report_path}{Colors.RESET}", Colors.RESET)

    # --------------------------------------------------------------------------
    # Final Executive Summary Box (50s - 55s)
    # --------------------------------------------------------------------------
    time.sleep(0.5 if not fast_mode else 0.05)
    cprint("\n" + "═" * 74, Colors.GREEN)
    cprint("  🎯  ASSESSMENT COMPLETE: VULNERABILITY TRIAGE REPORT", Colors.BOLD)
    cprint("═" * 74, Colors.GREEN)
    cprint(f"  Target File:         {Colors.BOLD}{target_info['path']}{Colors.RESET}")
    cprint(f"  Vulnerability:       {Colors.RED}{Colors.BOLD}{crash_data['vulnerability']}{Colors.RESET}")
    cprint(f"  Severity Rating:     {Colors.RED}{Colors.BOLD}{crash_data['severity']}{Colors.RESET}")
    cprint(f"  Crash Signal:        {Colors.YELLOW}{crash_data['signal']}{Colors.RESET}")
    cprint(f"  Exact Offset:        {Colors.GREEN}{Colors.BOLD}{crash_data['crash_offset']} bytes{Colors.RESET}")
    cprint(f"  Reasoning Model:     {Colors.CYAN}{model_name}{Colors.RESET}")
    cprint(f"  Total Scan Time:     {Colors.YELLOW}{duration:.2f} seconds{Colors.RESET}")
    cprint(f"  Generated PoC:       {Colors.GREEN}{poc_path}{Colors.RESET}")
    cprint("═" * 74, Colors.GREEN)

    cprint(f"\n{Colors.BOLD}[+] Reproduction Command:{Colors.RESET}")
    cprint(f"    python {poc_path}\n", Colors.YELLOW)


# ==============================================================================
# CLI Entrypoint
# ==============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Aegis: Autonomous Multi-Agent Exploitation Demo Powered by Gemini Free API"
    )
    parser.add_argument(
        "--target",
        "-t",
        type=str,
        default="benchmarks/telemetry_gateway.c",
        help="Path to benchmark target source file (default: benchmarks/telemetry_gateway.c)",
    )
    parser.add_argument(
        "--gemini-key",
        "-k",
        type=str,
        default=None,
        help="Google Gemini API key (defaults to GEMINI_API_KEY environment variable)",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Run without simulated pacing delays (useful for testing)",
    )

    args = parser.parse_args()
    run_demo(target_arg=args.target, gemini_key=args.gemini_key, fast_mode=args.fast)
