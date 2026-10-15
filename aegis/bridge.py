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

from aegis.core import checksec, cyclic, source_scanner


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

    def open_file_dialog(self, file_types: str = "binary") -> str | None:
        """
        Open a native Windows file picker.
        file_types: 'binary' (executables/libraries) or 'source' (C/C++ files)
        """
        if not self._window:
            return None

        import webview

        if file_types == "source":
            file_filter = ("C/C++ Source Files (*.c;*.cpp;*.cc;*.h;*.hpp)", "All Files (*.*)")
        else:
            file_filter = ("Executables & Binaries (*.exe;*.dll;*.sys;*.so;*.bin;*)", "All Files (*.*)")

        result = self._window.create_file_dialog(
            webview.OPEN_DIALOG,
            allow_multiple=False,
            file_types=file_filter,
        )
        if result and len(result) > 0:
            return str(Path(result[0]).resolve())
        return None

    # ── Checksec Service ──────────────────────────────────────────────────────

    def inspect_binary(self, file_path: str) -> dict[str, Any]:
        """
        Inspect a PE or ELF binary file and return structured mitigation telemetry.
        """
        clean_path = file_path.strip().strip('"').strip("'")
        if not clean_path:
            return {"success": False, "error": "No file path provided."}

        p = Path(clean_path)
        if not p.exists() or not p.is_file():
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
        word_size = 8 if arch == 64 else 4
        canary_size = word_size if has_canary else 0

        # Memory alignment (typically 16-byte aligned frame on modern x86/x64 ABI)
        raw_locals = buffer_size + canary_size
        aligned_frame_size = (raw_locals + 15) & ~15
        padding_size = aligned_frame_size - raw_locals

        # Offset offsets from buffer start (0-indexed):
        buf_start = 0
        buf_end = buffer_size

        canary_start = buf_end
        canary_end = canary_start + canary_size

        padding_start = canary_end
        padding_end = padding_start + padding_size

        rbp_start = padding_end
        rbp_end = rbp_start + word_size

        rip_start = rbp_end
        rip_end = rip_start + word_size

        total_frame = rip_end

        # Generate sample payload slice for visual representation
        try:
            payload_bytes = cyclic.generate(max(payload_len, 1))
        except Exception:
            payload_bytes = b"A" * payload_len

        def segment_state(start: int, end: int) -> dict[str, Any]:
            size = end - start
            if size == 0:
                return {"overwritten": False, "bytes_overwritten": 0, "pct": 0}
            if payload_len <= start:
                bytes_hit = 0
            elif payload_len >= end:
                bytes_hit = size
            else:
                bytes_hit = payload_len - start
            return {
                "overwritten": bytes_hit > 0,
                "full_overwrite": bytes_hit == size,
                "bytes_overwritten": bytes_hit,
                "pct": round((bytes_hit / size) * 100, 1),
            }

        # Calculate exact crash offset: payload length needed to reach return address
        offset_to_rip = rip_start

        return {
            "success": True,
            "arch": arch,
            "word_size": word_size,
            "buffer_size": buffer_size,
            "payload_len": payload_len,
            "has_canary": has_canary,
            "offset_to_rbp": rbp_start,
            "offset_to_rip": rip_start,
            "segments": {
                "buffer": {
                    "label": "Local Buffer [buf]",
                    "start": buf_start,
                    "end": buf_end,
                    "size": buffer_size,
                    "state": segment_state(buf_start, buf_end),
                },
                "canary": {
                    "label": "Stack Canary (__stack_chk_guard)",
                    "start": canary_start,
                    "end": canary_end,
                    "size": canary_size,
                    "state": segment_state(canary_start, canary_end),
                },
                "padding": {
                    "label": "Compiler ABI Alignment Padding",
                    "start": padding_start,
                    "end": padding_end,
                    "size": padding_size,
                    "state": segment_state(padding_start, padding_end),
                },
                "saved_rbp": {
                    "label": f"Saved Frame Pointer ({'RBP' if arch == 64 else 'EBP'})",
                    "start": rbp_start,
                    "end": rbp_end,
                    "size": word_size,
                    "state": segment_state(rbp_start, rbp_end),
                },
                "saved_rip": {
                    "label": f"Return Address ({'RIP' if arch == 64 else 'EIP'})",
                    "start": rip_start,
                    "end": rip_end,
                    "size": word_size,
                    "state": segment_state(rip_start, rip_end),
                },
            },
            "control_flow_hijacked": payload_len >= rip_end,
            "canary_triggered": has_canary and (payload_len > canary_start),
            "payload_preview": payload_bytes[:payload_len].decode("ascii", errors="replace"),
        }

    # ── Source Scanner Service ────────────────────────────────────────────────

    def scan_source(self, path_str: str, min_severity: str = "info") -> dict[str, Any]:
        """
        Scan a C/C++ source file or directory for memory and format-string sinks.
        """
        clean = path_str.strip().strip('"').strip("'")
        if not clean:
            return {"success": False, "error": "No source path provided."}

        p = Path(clean)
        if not p.exists():
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
