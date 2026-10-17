"""
aegis/core/frame_model.py
=========================
Deterministic stack frame memory layout model for x86 (32-bit) and x86_64 (64-bit).
Calculates boundary offsets from local buffer through compiler alignment padding,
stack canaries, saved frame pointer (RBP/EBP), to return instruction pointer (RIP/EIP).

Pure Python 3.12 stdlib — zero external dependencies.
"""

from __future__ import annotations

import dataclasses
from typing import Any


@dataclasses.dataclass(frozen=True)
class FrameSegment:
    """A discrete block within a call stack frame."""
    name: str
    label: str
    start: int
    end: int
    size: int
    is_critical: bool = False
    
    def state_at(self, payload_len: int) -> dict[str, Any]:
        """Compute overwrite state given a payload length."""
        if self.size == 0:
            return {"overwritten": False, "full_overwrite": False, "bytes_overwritten": 0, "pct": 0.0}
        
        if payload_len <= self.start:
            bytes_hit = 0
        elif payload_len >= self.end:
            bytes_hit = self.size
        else:
            bytes_hit = payload_len - self.start
            
        return {
            "overwritten": bytes_hit > 0,
            "full_overwrite": bytes_hit == self.size,
            "bytes_overwritten": bytes_hit,
            "pct": round((bytes_hit / self.size) * 100, 1),
        }


@dataclasses.dataclass
class StackFrameLayout:
    """Complete modeled stack frame layout."""
    arch: int
    word_size: int
    buffer_size: int
    payload_len: int
    has_canary: bool
    alignment: int
    offset_to_canary: int | None
    offset_to_rbp: int
    offset_to_rip: int
    total_frame_size: int
    control_flow_hijacked: bool
    canary_triggered: bool
    segments: list[FrameSegment]

    def to_dict(self) -> dict[str, Any]:
        """Serialize layout for IPC bridge or JSON reporting."""
        seg_dict = {}
        for s in self.segments:
            seg_dict[s.name] = {
                "label": s.label,
                "start": s.start,
                "end": s.end,
                "size": s.size,
                "is_critical": s.is_critical,
                "state": s.state_at(self.payload_len),
            }
        return {
            "success": True,
            "arch": self.arch,
            "word_size": self.word_size,
            "buffer_size": self.buffer_size,
            "payload_len": self.payload_len,
            "has_canary": self.has_canary,
            "alignment": self.alignment,
            "offset_to_canary": self.offset_to_canary,
            "offset_to_rbp": self.offset_to_rbp,
            "offset_to_rip": self.offset_to_rip,
            "total_frame_size": self.total_frame_size,
            "control_flow_hijacked": self.control_flow_hijacked,
            "canary_triggered": self.canary_triggered,
            "segments": seg_dict,
        }


def model_stack_frame(
    buffer_size: int,
    payload_len: int = 0,
    arch: int = 64,
    has_canary: bool = False,
    alignment: int = 16,
) -> StackFrameLayout:
    """
    Model realistic x86 / x86_64 stack frame layout according to standard ABI calling conventions.
    
    Standard x86/x64 layout (growing downward from high memory to low memory):
      [ High Memory ]
      Return Address (RIP/EIP)             [word_size bytes]
      Saved Frame Pointer (RBP/EBP)        [word_size bytes]
      Compiler Alignment Padding (if any)  [padding_size bytes]
      Stack Canary (__stack_chk_guard)     [word_size bytes if enabled]
      Local Variables / Buffer             [buffer_size bytes]
      [ Low Memory (Stack Pointer RSP) ]

    When overflowing the local buffer upwards in memory:
      0..buffer_size: Local Buffer
      Canary (if present)
      Alignment Padding
      Saved RBP / EBP
      Saved RIP / EIP (Instruction Pointer Hijack)
    """
    if arch not in (32, 64):
        raise ValueError(f"Unsupported architecture bitness: {arch}. Must be 32 or 64.")
    if buffer_size < 1:
        raise ValueError(f"Buffer size must be at least 1 byte, got {buffer_size}.")
    if payload_len < 0:
        raise ValueError(f"Payload length cannot be negative, got {payload_len}.")

    word_size = 8 if arch == 64 else 4
    canary_size = word_size if has_canary else 0

    # Modern compilers (GCC/Clang/MSVC) align the stack frame to 16 bytes for SSE/AVX
    raw_locals = buffer_size + canary_size
    if alignment > 0:
        aligned_frame_size = (raw_locals + (alignment - 1)) & ~(alignment - 1)
        padding_size = aligned_frame_size - raw_locals
    else:
        padding_size = 0

    segments: list[FrameSegment] = []

    # 1. Local Buffer
    buf_start = 0
    buf_end = buffer_size
    segments.append(
        FrameSegment(
            name="buffer",
            label="Local Target Buffer [buf]",
            start=buf_start,
            end=buf_end,
            size=buffer_size,
            is_critical=False,
        )
    )

    # 2. Canary (optional)
    curr_offset = buf_end
    canary_offset = None
    if has_canary:
        canary_start = curr_offset
        canary_end = canary_start + canary_size
        canary_offset = canary_start
        segments.append(
            FrameSegment(
                name="canary",
                label="Stack Canary (__stack_chk_guard)",
                start=canary_start,
                end=canary_end,
                size=canary_size,
                is_critical=True,
            )
        )
        curr_offset = canary_end

    # 3. Alignment Padding
    if padding_size > 0:
        pad_start = curr_offset
        pad_end = pad_start + padding_size
        segments.append(
            FrameSegment(
                name="padding",
                label="Compiler ABI Alignment Padding",
                start=pad_start,
                end=pad_end,
                size=padding_size,
                is_critical=False,
            )
        )
        curr_offset = pad_end

    # 4. Saved Frame Pointer (RBP / EBP)
    rbp_start = curr_offset
    rbp_end = rbp_start + word_size
    rbp_label = f"Saved Frame Pointer ({'RBP' if arch == 64 else 'EBP'})"
    segments.append(
        FrameSegment(
            name="saved_rbp",
            label=rbp_label,
            start=rbp_start,
            end=rbp_end,
            size=word_size,
            is_critical=True,
        )
    )
    curr_offset = rbp_end

    # 5. Return Address (RIP / EIP)
    rip_start = curr_offset
    rip_end = rip_start + word_size
    rip_label = f"Return Instruction Pointer ({'RIP' if arch == 64 else 'EIP'})"
    segments.append(
        FrameSegment(
            name="saved_rip",
            label=rip_label,
            start=rip_start,
            end=rip_end,
            size=word_size,
            is_critical=True,
        )
    )
    curr_offset = rip_end

    total_frame_size = curr_offset
    control_flow_hijacked = payload_len >= rip_end
    canary_triggered = has_canary and (payload_len > buf_end)

    return StackFrameLayout(
        arch=arch,
        word_size=word_size,
        buffer_size=buffer_size,
        payload_len=payload_len,
        has_canary=has_canary,
        alignment=alignment,
        offset_to_canary=canary_offset,
        offset_to_rbp=rbp_start,
        offset_to_rip=rip_start,
        total_frame_size=total_frame_size,
        control_flow_hijacked=control_flow_hijacked,
        canary_triggered=canary_triggered,
        segments=segments,
    )


def format_frame_diagram(layout: StackFrameLayout, color: bool = True) -> str:
    """Render a clean ASCII/ANSI visual diagram of the stack frame layout."""
    c_cyan = "\033[96m" if color else ""
    c_green = "\033[92m" if color else ""
    c_red = "\033[91m" if color else ""
    c_amber = "\033[93m" if color else ""
    c_gray = "\033[90m" if color else ""
    c_bold = "\033[1m" if color else ""
    c_reset = "\033[0m" if color else ""

    lines = [
        f"{c_bold}Stack Frame Boundary Model ({layout.arch}-bit | Word Size: {layout.word_size}B | Alignment: {layout.alignment}B){c_reset}",
        f"{c_gray}{'=' * 68}{c_reset}",
    ]

    for seg in layout.segments:
        state = seg.state_at(layout.payload_len)
        if state["full_overwrite"]:
            status_tag = f"{c_red}[CRITICAL OVERWRITE 100%]{c_reset}"
        elif state["overwritten"]:
            status_tag = f"{c_amber}[PARTIAL OVERWRITE {state['pct']}%]{c_reset}"
        else:
            status_tag = f"{c_green}[INTACT]{c_reset}"

        range_str = f"+{seg.start:<3} .. +{seg.end:<3} ({seg.size:>2}B)"
        lines.append(f"  {c_cyan}{range_str}{c_reset} │ {c_bold}{seg.label:<34}{c_reset} │ {status_tag}")

    lines.append(f"{c_gray}{'-' * 68}{c_reset}")
    lines.append(
        f"  Offset to Saved Frame Pointer: {c_bold}+{layout.offset_to_rbp} bytes{c_reset} (0x{layout.offset_to_rbp:02X})"
    )
    lines.append(
        f"  Offset to Return Address (RIP): {c_red if layout.control_flow_hijacked else c_bold}+{layout.offset_to_rip} bytes{c_reset} (0x{layout.offset_to_rip:02X})"
    )
    if layout.has_canary:
        canary_status = f"{c_red}TRIGGERED{c_reset}" if layout.canary_triggered else f"{c_green}UNTRIGGERED{c_reset}"
        lines.append(f"  Canary Guard Status:           {canary_status}")
    if layout.control_flow_hijacked:
        lines.append(f"  {c_red}{c_bold}[!] INSTRUCTION POINTER HIJACK CONFIRMED at payload len >= {layout.offset_to_rip + layout.word_size} bytes{c_reset}")
    lines.append(f"{c_gray}{'=' * 68}{c_reset}")

    return "\n".join(lines)
