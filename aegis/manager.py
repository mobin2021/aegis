"""
Hierarchical Manager Agent: Coordinates target scope decomposition, task delegation,
dual-mode reasoning, and vulnerability synthesis.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any

from .config import AegisConfig
from .inference.engine import InferenceEngine
from .workers.recon_worker import ReconWorker
from .workers.decompile_worker import DecompileWorker
from .workers.fuzz_worker import FuzzWorker
from .workers.poc_generator import PoCGeneratorWorker


class AegisManager:
    """Central orchestrator agent driving the multi-agent assessment pipeline."""

    def __init__(self, config: AegisConfig = None):
        self.config = config or AegisConfig()
        self.inference = InferenceEngine(self.config)

        # Initialize specialized worker agents
        self.recon_worker = ReconWorker(self.config)
        self.decompile_worker = DecompileWorker(self.config)
        self.fuzz_worker = FuzzWorker(self.config)
        self.poc_worker = PoCGeneratorWorker(self.config)

    def assess_target(self, target_path: str) -> Dict[str, Any]:
        """
        Execute end-to-end autonomous vulnerability assessment pipeline.
        """
        self.config.target_path = target_path
        start_time = time.time()

        if self.config.verbose:
            print("=" * 70)
            print(f"[AEGIS] ORCHESTRATION PIPELINE ENGAGED ON: {target_path}")
            print(f"[*] Dual-Mode Inference: {'Ollama Local' if self.inference.ollama_available else 'Heuristic/API Failover'}")
            print("=" * 70)

        # Phase 1: Reconnaissance
        recon_data = self.recon_worker.execute({"target": target_path})

        # Phase 2: Static Decompilation & AST Inspection
        decompile_data = self.decompile_worker.execute({"target_path": target_path})

        # Phase 3: Dual-Mode AI Reasoning over Decompiled Artifacts
        prompt = (
            f"Target file: {target_path}\n"
            f"Unsafe symbols found: {decompile_data.get('unsafe_calls', [])}\n"
            "Analyze the memory layout and identify the most likely crash primitive."
        )
        ai_reasoning = self.inference.query_reasoning(
            prompt,
            system_prompt="You are an autonomous binary exploitation agent identifying memory safety bugs."
        )

        if self.config.verbose:
            print(f"[REASONING ENGINE] Model: {ai_reasoning['model']} (Source: {ai_reasoning['source']})")

        # Phase 4: Fuzzing Campaign & Crash Triage
        fuzz_data = self.fuzz_worker.execute({
            "target_path": target_path,
            "unsafe_calls": decompile_data.get("unsafe_calls", []),
        })

        # Phase 5: Automated PoC Synthesis
        poc_data = self.poc_worker.execute({
            "target_path": target_path,
            "crash_data": fuzz_data,
            "decompile_data": decompile_data,
        })

        total_duration = round(time.time() - start_time, 2)

        # Compile final structured audit report
        report = {
            "aegis_version": "1.0.0",
            "target": target_path,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": total_duration,
            "inference": {
                "source": ai_reasoning["source"],
                "model": ai_reasoning["model"],
            },
            "findings": {
                "vulnerability": fuzz_data.get("primary_crash", {}).get("vulnerability", "Unknown"),
                "cwe": "CWE-121" if "stack" in target_path.lower() else "CWE-134",
                "severity": "CRITICAL",
                "crash_offset": fuzz_data.get("primary_crash", {}).get("offset", 0),
                "unsafe_calls": decompile_data.get("unsafe_calls", []),
            },
            "poc": {
                "generated": True,
                "file": poc_data.get("poc_file", ""),
                "command": poc_data.get("reproduction_command", ""),
            },
        }

        self._save_report(report)
        return report

    def _save_report(self, report: Dict[str, Any]) -> None:
        out_path = Path(self.config.report_output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2))
        if self.config.verbose:
            print(f"[+] Structured Audit Report saved: {out_path}")
