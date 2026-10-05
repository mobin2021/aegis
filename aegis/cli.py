#!/usr/bin/env python3
"""
Aegis CLI: Terminal interface for autonomous vulnerability assessment.
"""

import sys
import argparse
from pathlib import Path

# Ensure UTF-8 output across Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from .config import AegisConfig
from .manager import AegisManager


BANNER = r"""
   ___         _     
  / _ \___ ___(_)__  
 / __ / -_) _ `/ (_-<
/_/ /_\__/\_, /_/__/
         /___/       
Autonomous Multi-Agent Vulnerability Assessment Framework
v1.0.0 • By MD. Raisul Islam Mobin
"""


def main():
    parser = argparse.ArgumentParser(
        description="Aegis: Autonomous Multi-Agent Vulnerability Assessment Framework"
    )
    parser.add_argument(
        "--target",
        "-t",
        type=str,
        default="benchmarks/stack_overflow.c",
        help="Path to target binary or source file to assess",
    )
    parser.add_argument(
        "--mode",
        "-m",
        choices=["gemini", "cloud", "ollama", "dual"],
        default="dual",
        help="Inference mode: Google Gemini API, cloud API, local Ollama, or dual automatic fallback",
    )
    parser.add_argument(
        "--gemini-key",
        type=str,
        default=None,
        help="Google Gemini API key (or set GEMINI_API_KEY environment variable)",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default="aegis_output",
        help="Directory to save audit reports and generated PoC scripts",
    )

    args = parser.parse_args()

    print(BANNER)

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"[!] Error: Target file '{args.target}' does not exist.")
        sys.exit(1)

    config = AegisConfig(
        target_path=str(target_path),
        inference_mode=args.mode,
        gemini_api_key=args.gemini_key or AegisConfig().gemini_api_key,
        output_dir=args.output_dir,
        poc_output_path=f"{args.output_dir}/poc.py",
        report_output_path=f"{args.output_dir}/audit_report.json",
    )

    manager = AegisManager(config)
    report = manager.assess_target(str(target_path))

    print("\n" + "=" * 70)
    print("🎯  ASSESSMENT COMPLETE: VULNERABILITY DISCOVERY SUMMARY")
    print("=" * 70)
    print(f"Target:             {report['target']}")
    print(f"Vulnerability:      {report['findings']['vulnerability']}")
    print(f"CWE Classification: {report['findings']['cwe']}")
    print(f"Severity:           {report['findings']['severity']}")
    print(f"Crash Offset:       {report['findings']['crash_offset']} bytes")
    print(f"Generated PoC:      {report['poc']['file']}")
    print(f"Execution Duration: {report['duration_seconds']}s")
    print("=" * 70)
    print(f"\n[+] To reproduce this exploit run:\n    python {report['poc']['file']}\n")


if __name__ == "__main__":
    main()
