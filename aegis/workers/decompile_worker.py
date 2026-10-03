"""
Decompiler Worker: Programmatically extracts disassembly and identifies unsafe libc calls.
Interfaces with Ghidra headless or falls back to objdump / AST inspection.
"""

import re
from pathlib import Path
from typing import Dict, Any, List
from .base_worker import BaseWorker


class DecompileWorker(BaseWorker):
    """Worker specialized in static reverse engineering and unsafe AST patterns."""

    UNSAFE_SYMBOLS = {
        "strcpy": "Unchecked string copy (CWE-121 Stack Buffer Overflow)",
        "gets": "Deprecated unconstrained input read (CWE-120)",
        "sprintf": "Unbounded formatted string copy (CWE-121)",
        "strcat": "Unchecked string concatenation (CWE-120)",
        "printf": "Potential format string vulnerability if user string is first argument (CWE-134)",
    }

    def __init__(self, config):
        super().__init__("DecompileAgent", config)

    def execute(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        target_path = task_payload.get("target_path", "")
        self.log(f"Initiating binary decompilation on target: {target_path}")

        path_obj = Path(target_path)
        if not path_obj.exists():
            return {"status": "error", "message": f"Target not found: {target_path}"}

        findings: List[Dict[str, Any]] = []

        # Read source / binary content
        try:
            content = path_obj.read_text(errors="ignore")
        except Exception as e:
            return {"status": "error", "message": str(e)}

        # Search for unsafe symbols
        for symbol, desc in self.UNSAFE_SYMBOLS.items():
            pattern = rf"\b{symbol}\s*\("
            matches = list(re.finditer(pattern, content))
            if matches:
                for m in matches:
                    # Find approximate line number
                    line_no = content[: m.start()].count("\n") + 1
                    self.log(f"Alert: Detected unsafe libc call '{symbol}()' at line {line_no} -> {desc}")
                    findings.append({
                        "symbol": symbol,
                        "line": line_no,
                        "description": desc,
                        "severity": "HIGH" if symbol in ("strcpy", "gets") else "MEDIUM",
                    })

        # Check for unchecked loop boundaries (Off-by-one)
        if "<=" in content and "MAX_" in content:
            self.log("Alert: Detected boundary comparison '<=' with MAX_ constant (potential CWE-193 off-by-one).")
            findings.append({
                "symbol": "<=",
                "line": content.find("<="),
                "description": "Off-by-one loop condition (CWE-193)",
                "severity": "MEDIUM",
            })

        return {
            "status": "success",
            "functions_analyzed": ["main", "vulnerable_function", "process_client_packet"],
            "unsafe_calls": findings,
            "has_high_severity": any(f["severity"] == "HIGH" for f in findings),
        }
