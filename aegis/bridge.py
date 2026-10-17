"""
aegis/bridge.py
===============
Type-safe Python-to-JavaScript IPC Bridge for Aegis Studio GUI.
Connects Edge WebView2 to core engines: checksec, cyclic, and source_scanner.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any

from aegis.core import checksec, cyclic, frame_model, patch_engineer, pipeline, poc_synthesizer, source_scanner


class AegisBridge:
    """
    Exposed JS API object passed to pywebview.
    Methods on this class can be called directly from JavaScript via:
      window.pywebview.api.<method_name>(...)
    All methods return JSON-serializable dictionaries or primitives.
    """

    def __init__(self, window=None) -> None:
        self._window = window

    def set_window(self, window) -> None:
        self._window = window

    # ── Window Controls ───────────────────────────────────────────────────────

    def window_minimize(self) -> None:
        if self._window:
            self._window.minimize()

    def window_maximize(self) -> None:
        if self._window:
            if getattr(self._window, "is_maximized", False):
                self._window.restore()
                self._window.is_maximized = False
            else:
                self._window.maximize()
                self._window.is_maximized = True

    def window_close(self) -> None:
        if self._window:
            self._window.destroy()

    @staticmethod
    def _resolve_target_path(clean_path: str) -> Path | None:
        """
        Robustly locate a target file across development and frozen PyInstaller runtimes.
        """
        import sys
        p = Path(clean_path)
        if p.exists() and p.is_file():
            return p.resolve()

        # Check relative to Current Working Directory
        p_cwd = Path.cwd() / clean_path
        if p_cwd.exists() and p_cwd.is_file():
            return p_cwd.resolve()

        # Check relative to parent directory (if running inside dist/)
        p_parent = Path.cwd().parent / clean_path
        if p_parent.exists() and p_parent.is_file():
            return p_parent.resolve()

        # Check relative to executable folder
        if getattr(sys, "frozen", False):
            exe_dir = Path(sys.executable).parent
            p_exe = exe_dir / clean_path
            if p_exe.exists() and p_exe.is_file():
                return p_exe.resolve()
            p_exe_parent = exe_dir.parent / clean_path
            if p_exe_parent.exists() and p_exe_parent.is_file():
                return p_exe_parent.resolve()
            if hasattr(sys, "_MEIPASS"):
                p_mei = Path(sys._MEIPASS) / clean_path
                if p_mei.exists() and p_mei.is_file():
                    return p_mei.resolve()

        return None

    def open_file_dialog(self, file_types: str = "binary") -> str | None:
        """
        Open a native Windows file picker.
        file_types: 'binary' (executables/libraries), 'source' (C/C++ files), or 'any'
        """
        try:
            import importlib
            wv = importlib.import_module("webview")
            open_mode = getattr(wv, "OPEN_DIALOG", 10)
        except Exception:
            wv = None
            open_mode = 10

        # Pywebview's Windows filter regex: r'^([\w ]+)\((\*(?:\.(?:\w+|\*))*(?:;\*(?:\.(?:\w+|\*))*)*)\)$'
        # DO NOT use special characters like '/', '&', or '+' in descriptions!
        if file_types == "source":
            file_filter = (
                "C and Cpp Source Files (*.c;*.cpp;*.cc;*.h;*.hpp)",
                "All Files (*.*)",
            )
        elif file_types == "binary":
            file_filter = (
                "Executable Files (*.exe;*.dll;*.sys;*.bin)",
                "All Files (*.*)",
            )
        else:
            file_filter = (
                "All Supported Files (*.c;*.cpp;*.exe;*.dll;*.h;*.bin)",
                "All Files (*.*)",
            )

        # 1. Attempt pywebview native dialog
        if self._window and wv is not None:
            try:
                result = self._window.create_file_dialog(
                    open_mode,
                    allow_multiple=False,
                    file_types=file_filter,
                )
                if result and len(result) > 0:
                    return str(Path(result[0]).resolve())
            except Exception:
                pass

        # 2. Resilient fallback: tkinter native file dialog
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            if file_types == "source":
                patterns = [("C/C++ Source Files", "*.c *.cpp *.h *.cc *.hpp"), ("All Files", "*.*")]
            elif file_types == "binary":
                patterns = [("Executable Files", "*.exe *.dll *.sys *.bin"), ("All Files", "*.*")]
            else:
                patterns = [("All Supported Files", "*.c *.cpp *.h *.exe *.dll"), ("All Files", "*.*")]
            chosen = filedialog.askopenfilename(filetypes=patterns)
            root.destroy()
            if chosen:
                return str(Path(chosen).resolve())
        except Exception:
            pass

        return None

    # ── Checksec Service ──────────────────────────────────────────────────────

    def inspect_binary(self, file_path: str) -> dict[str, Any]:
        """
        Inspect a PE or ELF binary file and return structured mitigation telemetry.
        """
        clean_path = file_path.strip().strip('"').strip("'")
        if not clean_path:
            return {"success": False, "error": "No file path provided."}

        p = self._resolve_target_path(clean_path)
        if not p:
            return {"success": False, "error": f"File not found: {clean_path}"}

        try:
            res = checksec.inspect(p)
            mits_data = []
            for m in res.mitigations:
                mits_data.append({
                    "name": m.name,
                    "status": m.status,
                    "detail": m.detail,
                    "cwe": m.cwe,
                })

            return {
                "success": True,
                "path": res.path,
                "filename": p.name,
                "format": res.fmt,
                "sha256": res.sha256,
                "size_bytes": res.size_bytes,
                "score": res.score,
                "total_controls": len(res.mitigations),
                "mitigations": mits_data,
                "warnings": res.errors,
            }
        except Exception as exc:
            return {"success": False, "error": f"Failed to inspect binary: {exc}"}

    # ── Cyclic Pattern Lab ────────────────────────────────────────────────────

    def cyclic_generate(self, length: int) -> dict[str, Any]:
        """
        Generate a De Bruijn pattern of specified length with metadata.
        """
        try:
            length = int(length)
            if length < 1 or length > cyclic._MAX_SAFE:
                return {
                    "success": False,
                    "error": f"Length must be between 1 and {cyclic._MAX_SAFE:,} bytes.",
                }

            pat_bytes = cyclic.generate(length)
            info = cyclic.cyclic_metainfo(length)

            # ASCII representation and hex preview
            pat_str = pat_bytes.decode("ascii", errors="replace")
            hex_preview = " ".join(f"{b:02X}" for b in pat_bytes[:64])
            if length > 64:
                hex_preview += " ..."

            return {
                "success": True,
                "pattern": pat_str,
                "hex_preview": hex_preview,
                "length": info["length"],
                "unique_windows": info["unique_windows"],
                "coverage_pct": info["coverage_pct"],
                "alphabet_size": info["alphabet_size"],
                "window_width": info["window_width"],
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def cyclic_resolve(self, crash_str: str, arch: int = 64) -> dict[str, Any]:
        """
        Resolve a crash register hex value (e.g. '0x61616264' or '0x41414141')
        to its byte offset.
        """
        try:
            clean = crash_str.strip()
            if clean.lower().startswith("0x"):
                val = int(clean, 16)
            else:
                # If typed as letters like 'baad', convert to little-endian int
                if len(clean) in (4, 8) and clean.isalpha():
                    raw_b = clean.encode("ascii")
                    val = struct.unpack("<I" if len(clean) == 4 else "<Q", raw_b)[0]
                else:
                    val = int(clean, 16 if any(c in "abcdefABCDEF" for c in clean) else 10)

            offset = cyclic.find_offset(val, arch=int(arch))
            if offset is None:
                return {
                    "success": False,
                    "error": f"Value 0x{val:X} was not found within the De Bruijn sequence.",
                    "value_hex": f"0x{val:X}",
                }

            return {
                "success": True,
                "offset": offset,
                "offset_hex": f"0x{offset:X}",
                "value_hex": f"0x{val:X}",
                "arch": arch,
            }
        except Exception as exc:
            return {"success": False, "error": f"Resolution error: {exc}"}

    # ── Memory Stack Simulator ────────────────────────────────────────────────

    def calculate_stack_frame(
        self,
        buffer_size: int = 64,
        payload_len: int = 80,
        arch: int = 64,
        has_canary: bool = True,
    ) -> dict[str, Any]:
        """
        Calculate realistic x86 / x86-64 stack frame layout and overwrite boundaries.
        Returns block segments with exact byte offsets relative to buffer start.
        """
        try:
            layout = frame_model.model_stack_frame(
                buffer_size=int(buffer_size),
                payload_len=int(payload_len),
                arch=int(arch),
                has_canary=bool(has_canary),
            )
            data = layout.to_dict()
            try:
                payload_bytes = cyclic.generate(max(payload_len, 1))
            except Exception:
                payload_bytes = b"A" * payload_len
            data["payload_preview"] = payload_bytes[:payload_len].decode("ascii", errors="replace")
            return data
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    # ── Source Scanner Service ────────────────────────────────────────────────

    def scan_source(self, path_str: str, min_severity: str = "info") -> dict[str, Any]:
        """
        Scan a C/C++ source file or directory for memory and format-string sinks.
        """
        clean = path_str.strip().strip('"').strip("'")
        if not clean:
            return {"success": False, "error": "No source path provided."}

        p = self._resolve_target_path(clean)
        if not p:
            p_dir = Path(clean)
            if p_dir.exists() and p_dir.is_dir():
                p = p_dir
            elif (Path.cwd() / clean).exists() and (Path.cwd() / clean).is_dir():
                p = Path.cwd() / clean
            else:
                return {"success": False, "error": f"Path not found: {clean}"}

        try:
            results = source_scanner.scan(p, min_severity=min_severity)
            files_data = []
            total_findings = 0
            crit_count = 0
            high_count = 0

            for r in results:
                f_list = []
                for f in r.findings:
                    total_findings += 1
                    if f.severity == "critical":
                        crit_count += 1
                    elif f.severity == "high":
                        high_count += 1
                    f_list.append({
                        "file": f.file,
                        "line": f.line,
                        "col": f.col,
                        "cwe": f.cwe,
                        "severity": f.severity,
                        "sink": f.sink,
                        "detail": f.detail,
                        "snippet": f.snippet,
                    })

                files_data.append({
                    "path": r.path,
                    "filename": Path(r.path).name,
                    "lines_total": r.lines_total,
                    "findings": f_list,
                    "errors": r.errors,
                })

            return {
                "success": True,
                "target": str(p.resolve()),
                "files_scanned": len(results),
                "total_findings": total_findings,
                "critical_count": crit_count,
                "high_count": high_count,
                "files": files_data,
            }
        except Exception as exc:
            return {"success": False, "error": f"Scan failed: {exc}"}

    # ── Autonomous Triage Service ─────────────────────────────────────────────

    def run_triage(self, target_path: str, arch: int = 64) -> dict[str, Any]:
        """
        Execute full autonomous vulnerability research & mitigation triage on a target file.
        """
        clean = target_path.strip().strip('"').strip("'")
        if not clean:
            return {"success": False, "error": "No target path provided."}

        p = self._resolve_target_path(clean)
        if not p:
            return {"success": False, "error": f"File not found: {clean}"}

        try:
            res = pipeline.run_triage(p, arch=int(arch))
            return res.to_dict()
        except Exception as exc:
            return {"success": False, "error": f"Autonomous triage failed: {exc}"}
