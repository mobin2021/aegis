"""
aegis/core/checksec.py
======================
Binary Mitigation Inspector — Raw PE & ELF Header Parser
---------------------------------------------------------

ARCHITECTURE OVERVIEW
---------------------
This module reads raw binary bytes (no external libraries) and reports
which security mitigations are present or absent in an executable.

Supported formats
  • PE32 / PE32+   — Windows EXE, DLL, SYS (MZ → NT headers)
  • ELF32 / ELF64 — Linux / Android shared objects and executables

Mitigations audited
  ┌──────────────┬────────────────────────────────────────────┐
  │ NX / DEP     │ Non-executable stack (hardware enforced)   │
  │ ASLR / PIE   │ Address-space layout randomisation         │
  │ Stack Canary │ __security_cookie / __stack_chk_fail       │
  │ RELRO        │ Read-only relocations (ELF only)           │
  │ SafeSEH      │ Structured Exception Handler validation    │
  │ CFG          │ Control Flow Guard (PE only, Win10+)       │
  └──────────────┴────────────────────────────────────────────┘

PE PARSING WALKTHROUGH
----------------------
DOS Header (64 bytes):
  Offset 0x00  WORD  e_magic    — must be 0x5A4D ("MZ")
  Offset 0x3C  DWORD e_lfanew  — byte offset to NT headers

NT Headers:
  e_lfanew + 0x00  DWORD Signature        — must be 0x00004550 ("PE\0\0")
  e_lfanew + 0x04  IMAGE_FILE_HEADER (20B)
    +0x12          WORD  Characteristics  — IMAGE_FILE_DLL etc.
  e_lfanew + 0x18  IMAGE_OPTIONAL_HEADER
    +0x00          WORD  Magic            — 0x010B = PE32, 0x020B = PE32+
    +0x46 (PE32)   WORD  DllCharacteristics
    +0x4E (PE32+)  WORD  DllCharacteristics

DllCharacteristics bitmask (key bits):
  0x0020  HIGH_ENTROPY_VA  — 64-bit ASLR with full 64-bit entropy
  0x0040  DYNAMIC_BASE     — ASLR (rebasing allowed)
  0x0100  NX_COMPAT        — DEP / NX compatible
  0x0400  NO_SEH           — binary does NOT use SEH (SafeSEH irrelevant)
  0x4000  GUARD_CF         — Control Flow Guard

Stack canary (PE):
  Scan the raw binary for the ASCII string "__security_cookie".
  This symbol is linked in by MSVC's /GS flag; its presence is a
  reliable (though not foolproof) indicator that stack cookies are active.

ELF PARSING WALKTHROUGH
-----------------------
ELF Identification (16 bytes at offset 0):
  Bytes 0–3   Magic         — 0x7F 'E' 'L' 'F'
  Byte  4     EI_CLASS      — 1 = ELF32, 2 = ELF64
  Byte  5     EI_DATA       — 1 = little-endian, 2 = big-endian

ELF Header:
  e_type   HALF  — ET_EXEC (2) = executable, ET_DYN (3) = shared obj / PIE
  e_phoff  —     byte offset to program header table
  e_phnum  —     number of program headers
  e_shoff  —     byte offset to section header table
  e_shnum  —     number of section headers

Program Headers (iterated):
  p_type  WORD:
    0x6474E551  PT_GNU_STACK  → flags field: PF_X=1 means executable stack
                                (NX = NX iff PF_X is NOT set)
    0x6474E552  PT_GNU_RELRO  → RELRO is at least partial

Dynamic Section (PT_DYNAMIC segment):
  DT_FLAGS  tag 0x1E  → value & DF_BIND_NOW (0x08) → BIND_NOW set
  DT_FLAGS_1 tag 0x6FFFFFFB → value & DF_1_NOW (0x01) → also BIND_NOW
  Full RELRO = PT_GNU_RELRO present AND (BIND_NOW set in dynamic flags)

PIE:
  e_type == ET_DYN (3) → binary is position-independent

Stack canary (ELF):
  Scan the .dynstr string table section for "__stack_chk_fail".
  This function is called by GCC/Clang -fstack-protector on function exit.

CWE MAPPINGS
------------
  CWE-119 — NX/DEP absent (improper restriction of buffer boundary)
  CWE-250 — ASLR absent   (execution with unnecessary privileges / no ASLR)
  CWE-121 — Stack canary absent (stack-based buffer overflow)
  CWE-693 — RELRO absent  (protection mechanism failure)
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Mitigation:
    """
    One security control with its detection result and evidence.

    Attributes
    ----------
    name    : short control name  ("NX", "ASLR", "Canary", "RELRO", "CFG")
    status  : "enabled" | "disabled" | "partial" | "unknown"
    detail  : human-readable explanation of the finding
    cwe     : CWE identifier if the control is absent/weakened, else ""
    """
    name:   str
    status: Literal["enabled", "disabled", "partial", "unknown"]
    detail: str
    cwe:    str = ""


@dataclass
class ChecksecResult:
    """
    Aggregated mitigation report for one binary.

    Attributes
    ----------
    path        : absolute path to the file
    fmt         : "PE32" | "PE32+" | "ELF32" | "ELF64" | "unknown"
    sha256      : hex digest of the file
    size_bytes  : file size
    mitigations : list of Mitigation entries (one per control)
    errors      : list of non-fatal parse warnings
    """
    path:        str
    fmt:         str
    sha256:      str
    size_bytes:  int
    mitigations: list[Mitigation] = field(default_factory=list)
    errors:      list[str]        = field(default_factory=list)

    # ── Convenience accessors ─────────────────────────────────────────────────

    def get(self, name: str) -> Mitigation | None:
        """Return the Mitigation with the given name, or None."""
        for m in self.mitigations:
            if m.name == name:
                return m
        return None

    @property
    def score(self) -> int:
        """
        Simple 0–N enabled-control count for at-a-glance risk ranking.
        Higher = more hardened.
        """
        return sum(1 for m in self.mitigations if m.status == "enabled")


# ---------------------------------------------------------------------------
# PE constants
# ---------------------------------------------------------------------------

_PE_MAGIC_DOS          = 0x5A4D           # "MZ"
_PE_SIGNATURE          = 0x00004550       # "PE\0\0"
_PE_OPT_MAGIC_PE32     = 0x010B
_PE_OPT_MAGIC_PE32PLUS = 0x020B

# DllCharacteristics bitmask
_DLL_CHAR_HIGH_ENTROPY_VA = 0x0020
_DLL_CHAR_DYNAMIC_BASE    = 0x0040
_DLL_CHAR_NX_COMPAT       = 0x0100
_DLL_CHAR_NO_SEH          = 0x0400
_DLL_CHAR_GUARD_CF        = 0x4000

# ---------------------------------------------------------------------------
# ELF constants
# ---------------------------------------------------------------------------

_ELF_MAGIC       = b"\x7fELF"
_ET_DYN          = 3            # position-independent executable or SO
_PT_GNU_STACK    = 0x6474E551
_PT_GNU_RELRO    = 0x6474E552
_PT_DYNAMIC      = 0x00000002
_PF_X            = 0x1          # segment executable flag
_DT_FLAGS        = 0x1E
_DT_FLAGS_1      = 0x6FFFFFFB
_DF_BIND_NOW     = 0x08
_DF_1_NOW        = 0x00000001

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _find_bytes(haystack: bytes, needle: bytes) -> bool:
    """Return True if *needle* appears anywhere in *haystack*."""
    return haystack.find(needle) != -1


# ---------------------------------------------------------------------------
# PE parser
# ---------------------------------------------------------------------------

def _parse_pe(data: bytes) -> ChecksecResult:
    """
    Parse a PE32 / PE32+ binary and return mitigation findings.

    Raises
    ------
    ValueError
        If the file is not a valid PE binary.
    """
    errors: list[str] = []
    mits:   list[Mitigation] = []

    # ── DOS header ────────────────────────────────────────────────────────────
    if len(data) < 64:
        raise ValueError("File too small to be a valid PE binary.")

    e_magic: int = struct.unpack_from("<H", data, 0)[0]
    if e_magic != _PE_MAGIC_DOS:
        raise ValueError(f"Invalid DOS magic: 0x{e_magic:04X} (expected 0x5A4D).")

    e_lfanew: int = struct.unpack_from("<I", data, 0x3C)[0]

    # ── NT signature ─────────────────────────────────────────────────────────
    if e_lfanew + 4 > len(data):
        raise ValueError("e_lfanew points beyond file bounds.")

    pe_sig: int = struct.unpack_from("<I", data, e_lfanew)[0]
    if pe_sig != _PE_SIGNATURE:
        raise ValueError(f"Invalid PE signature at 0x{e_lfanew:X}: 0x{pe_sig:08X}.")

    # ── File Header (20 bytes, starts at e_lfanew+4) ─────────────────────────
    fh_offset: int = e_lfanew + 4
    if fh_offset + 20 > len(data):
        raise ValueError("File Header truncated.")

    # WORD Machine, WORD NumberOfSections, DWORD TimeDateStamp,
    # DWORD PointerToSymbolTable, DWORD NumberOfSymbols,
    # WORD SizeOfOptionalHeader, WORD Characteristics
    fh_chars: int = struct.unpack_from("<H", data, fh_offset + 18)[0]

    # ── Optional Header ───────────────────────────────────────────────────────
    oh_offset: int = fh_offset + 20
    if oh_offset + 2 > len(data):
        raise ValueError("Optional Header missing.")

    oh_magic: int = struct.unpack_from("<H", data, oh_offset)[0]

    if oh_magic == _PE_OPT_MAGIC_PE32:
        fmt = "PE32"
        # DllCharacteristics is at Optional Header offset 0x46 (decimal 70)
        dll_chars_offset: int = oh_offset + 0x46
    elif oh_magic == _PE_OPT_MAGIC_PE32PLUS:
        fmt = "PE32+"
        # DllCharacteristics is at Optional Header offset 0x4E (decimal 78)
        dll_chars_offset = oh_offset + 0x4E
    else:
        raise ValueError(f"Unknown Optional Header magic: 0x{oh_magic:04X}.")

    if dll_chars_offset + 2 > len(data):
        raise ValueError("DllCharacteristics field truncated.")

    dll_chars: int = struct.unpack_from("<H", data, dll_chars_offset)[0]

    # ── Mitigation: NX / DEP ─────────────────────────────────────────────────
    nx_on = bool(dll_chars & _DLL_CHAR_NX_COMPAT)
    mits.append(Mitigation(
        name   = "NX",
        status = "enabled" if nx_on else "disabled",
        detail = (
            "NX_COMPAT set in DllCharacteristics — stack/heap are non-executable."
            if nx_on else
            "NX_COMPAT absent — DEP/NX not requested; shellcode may execute on stack."
        ),
        cwe = "" if nx_on else "CWE-119",
    ))

    # ── Mitigation: ASLR ─────────────────────────────────────────────────────
    aslr_on      = bool(dll_chars & _DLL_CHAR_DYNAMIC_BASE)
    highentropy  = bool(dll_chars & _DLL_CHAR_HIGH_ENTROPY_VA)

    if aslr_on and highentropy:
        aslr_status  = "enabled"
        aslr_detail  = "DYNAMIC_BASE + HIGH_ENTROPY_VA — full 64-bit ASLR entropy."
    elif aslr_on:
        aslr_status  = "partial"
        aslr_detail  = "DYNAMIC_BASE set but HIGH_ENTROPY_VA absent — 32-bit ASLR entropy only."
    else:
        aslr_status  = "disabled"
        aslr_detail  = "DYNAMIC_BASE absent — image loads at fixed base address."

    mits.append(Mitigation(
        name   = "ASLR",
        status = aslr_status,
        detail = aslr_detail,
        cwe    = "" if aslr_on else "CWE-250",
    ))

    # ── Mitigation: Stack Canary ──────────────────────────────────────────────
    # MSVC /GS links in __security_cookie.  Scan raw bytes for the symbol name.
    canary_on = _find_bytes(data, b"__security_cookie")
    mits.append(Mitigation(
        name   = "Canary",
        status = "enabled" if canary_on else "disabled",
        detail = (
            "__security_cookie symbol found — compiled with /GS stack protection."
            if canary_on else
            "__security_cookie absent — no MSVC /GS stack cookie detected."
        ),
        cwe = "" if canary_on else "CWE-121",
    ))

    # ── Mitigation: SafeSEH ───────────────────────────────────────────────────
    # NO_SEH bit means binary declares it does NOT use SEH at all.
    # SafeSEH = binary uses SEH AND the linker embedded a validated handler table.
    # We approximate: if NO_SEH is absent AND this is PE32, SafeSEH may apply.
    no_seh = bool(dll_chars & _DLL_CHAR_NO_SEH)
    if fmt == "PE32+":
        # x64 uses a different SEH mechanism (unwind tables); SafeSEH N/A
        seh_status = "unknown"
        seh_detail = "SafeSEH N/A on PE32+ (x64 uses structured unwind tables)."
    elif no_seh:
        seh_status = "disabled"
        seh_detail = "NO_SEH flag set — binary does not use SEH handlers."
    else:
        # Cannot determine SafeSEH without reading the load config directory;
        # mark as partial (SEH used, SafeSEH status indeterminate from headers).
        seh_status = "partial"
        seh_detail = (
            "SEH in use (NO_SEH absent). Full SafeSEH verification requires "
            "Load Configuration directory inspection."
        )

    mits.append(Mitigation(
        name   = "SafeSEH",
        status = seh_status,
        detail = seh_detail,
    ))

    # ── Mitigation: CFG ───────────────────────────────────────────────────────
    cfg_on = bool(dll_chars & _DLL_CHAR_GUARD_CF)
    mits.append(Mitigation(
        name   = "CFG",
        status = "enabled" if cfg_on else "disabled",
        detail = (
            "GUARD_CF set — Control Flow Guard active (requires Win10 kernel)."
            if cfg_on else
            "GUARD_CF absent — indirect call targets are not validated by the kernel."
        ),
    ))

    # ── RELRO — PE has no equivalent; always N/A ──────────────────────────────
    mits.append(Mitigation(
        name   = "RELRO",
        status = "unknown",
        detail = "RELRO is an ELF-only mitigation; not applicable to PE binaries.",
    ))

    return ChecksecResult(
        path        = "",           # caller fills this in
        fmt         = fmt,
        sha256      = _sha256(data),
        size_bytes  = len(data),
        mitigations = mits,
        errors      = errors,
    )


# ---------------------------------------------------------------------------
# ELF parser
# ---------------------------------------------------------------------------

def _parse_elf(data: bytes) -> ChecksecResult:
    """
    Parse an ELF32 / ELF64 binary and return mitigation findings.

    Raises
    ------
    ValueError
        If the file is not a valid ELF binary.
    """
    errors: list[str] = []
    mits:   list[Mitigation] = []

    if len(data) < 16:
        raise ValueError("File too small to be a valid ELF binary.")

    # ── ELF identification block ──────────────────────────────────────────────
    if data[:4] != _ELF_MAGIC:
        raise ValueError(f"Invalid ELF magic: {data[:4]!r}.")

    ei_class: int = data[4]   # 1 = 32-bit, 2 = 64-bit
    ei_data:  int = data[5]   # 1 = LE, 2 = BE

    if ei_class == 1:
        fmt = "ELF32"
        bits = 32
    elif ei_class == 2:
        fmt = "ELF64"
        bits = 64
    else:
        raise ValueError(f"Unknown EI_CLASS: {ei_class}.")

    if ei_data == 1:
        endian = "<"
    elif ei_data == 2:
        endian = ">"
    else:
        raise ValueError(f"Unknown EI_DATA: {ei_data}.")

    # ── ELF header fields ─────────────────────────────────────────────────────
    # ELF32 header = 52 bytes, ELF64 header = 64 bytes
    if bits == 32:
        # Offset 16: e_type(H) e_machine(H) e_version(I) e_entry(I)
        #            e_phoff(I) e_shoff(I) e_flags(I)
        #            e_ehsize(H) e_phentsize(H) e_phnum(H)
        #            e_shentsize(H) e_shnum(H) e_shstrndx(H)
        hdr_fmt = f"{endian}HHIIIIIHHHHHH"   # 36 bytes from offset 16
        (e_type, _e_machine, _e_version,
         _e_entry, e_phoff, e_shoff,
         _e_flags, _e_ehsize, e_phentsize,
         e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack_from(hdr_fmt, data, 16)
        ph_entry_size = 32    # Phdr32 size
    else:
        # ELF64 header from offset 16
        hdr_fmt = f"{endian}HHIQQQIHHHHHH"   # 48 bytes from offset 16
        (e_type, _e_machine, _e_version,
         _e_entry, e_phoff, e_shoff,
         _e_flags, _e_ehsize, e_phentsize,
         e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack_from(hdr_fmt, data, 16)
        ph_entry_size = 56    # Phdr64 size

    # ── PIE ───────────────────────────────────────────────────────────────────
    pie_on = (e_type == _ET_DYN)
    mits.append(Mitigation(
        name   = "ASLR",
        status = "enabled" if pie_on else "disabled",
        detail = (
            "ET_DYN — binary is position-independent (PIE); ASLR will randomise base."
            if pie_on else
            "ET_EXEC — binary loads at a fixed address; ASLR cannot randomise base."
        ),
        cwe = "" if pie_on else "CWE-250",
    ))

    # ── Walk program headers ──────────────────────────────────────────────────
    has_gnu_stack  = False
    nx_on          = False       # will be set by PT_GNU_STACK analysis
    has_relro      = False
    has_dynamic    = False
    dynamic_offset = 0           # file offset of PT_DYNAMIC segment
    dynamic_size   = 0

    if e_phoff == 0 or e_phnum == 0:
        errors.append("No program headers; NX/RELRO cannot be determined.")
    else:
        for ph_idx in range(e_phnum):
            ph_off = e_phoff + ph_idx * (e_phentsize or ph_entry_size)
            if ph_off + ph_entry_size > len(data):
                errors.append(f"Program header {ph_idx} truncated; stopping PH scan.")
                break

            if bits == 32:
                # Phdr32: p_type(I) p_offset(I) p_vaddr(I) p_paddr(I)
                #         p_filesz(I) p_memsz(I) p_flags(I) p_align(I)
                p_type, p_offset, _p_vaddr, _p_paddr, p_filesz, _p_memsz, p_flags, _ = \
                    struct.unpack_from(f"{endian}IIIIIIII", data, ph_off)
            else:
                # Phdr64: p_type(I) p_flags(I) p_offset(Q) p_vaddr(Q)
                #         p_paddr(Q) p_filesz(Q) p_memsz(Q) p_align(Q)
                p_type, p_flags, p_offset, _p_vaddr, _p_paddr, p_filesz, _p_memsz, _ = \
                    struct.unpack_from(f"{endian}IIQQQQQQ", data, ph_off)

            if p_type == _PT_GNU_STACK:
                has_gnu_stack = True
                nx_on = not bool(p_flags & _PF_X)   # NX = stack is NOT executable
            elif p_type == _PT_GNU_RELRO:
                has_relro = True
            elif p_type == _PT_DYNAMIC:
                has_dynamic    = True
                dynamic_offset = p_offset
                dynamic_size   = p_filesz

    # ── Mitigation: NX ───────────────────────────────────────────────────────
    if not has_gnu_stack:
        mits.append(Mitigation(
            name   = "NX",
            status = "unknown",
            detail = "PT_GNU_STACK segment absent — NX status cannot be determined from headers.",
            cwe    = "CWE-119",
        ))
    else:
        mits.append(Mitigation(
            name   = "NX",
            status = "enabled" if nx_on else "disabled",
            detail = (
                "PT_GNU_STACK present without PF_X — stack is non-executable."
                if nx_on else
                "PT_GNU_STACK has PF_X set — stack is executable (NX disabled)."
            ),
            cwe = "" if nx_on else "CWE-119",
        ))

    # ── Dynamic section: check BIND_NOW for full RELRO ────────────────────────
    bind_now = False
    if has_dynamic and dynamic_size > 0:
        dyn_end = dynamic_offset + dynamic_size
        if dyn_end <= len(data):
            if bits == 32:
                dyn_entry_size = 8    # Elf32_Dyn: d_tag(I) d_val(I)
                dyn_fmt        = f"{endian}Ii"
            else:
                dyn_entry_size = 16   # Elf64_Dyn: d_tag(Q) d_val(Q)
                dyn_fmt        = f"{endian}Qq"

            pos = dynamic_offset
            while pos + dyn_entry_size <= dyn_end:
                d_tag, d_val = struct.unpack_from(dyn_fmt, data, pos)
                if d_tag == 0:        # DT_NULL — end of dynamic section
                    break
                if d_tag == _DT_FLAGS and (d_val & _DF_BIND_NOW):
                    bind_now = True
                if d_tag == _DT_FLAGS_1 and (d_val & _DF_1_NOW):
                    bind_now = True
                pos += dyn_entry_size
        else:
            errors.append("PT_DYNAMIC segment extends beyond file; skipping BIND_NOW scan.")

    # ── Mitigation: RELRO ────────────────────────────────────────────────────
    if not has_relro:
        mits.append(Mitigation(
            name   = "RELRO",
            status = "disabled",
            detail = "PT_GNU_RELRO segment absent — GOT/PLT are writable after startup.",
            cwe    = "CWE-693",
        ))
    elif bind_now:
        mits.append(Mitigation(
            name   = "RELRO",
            status = "enabled",
            detail = "PT_GNU_RELRO present + BIND_NOW/DF_1_NOW set — Full RELRO (GOT read-only).",
        ))
    else:
        mits.append(Mitigation(
            name   = "RELRO",
            status = "partial",
            detail = (
                "PT_GNU_RELRO present but BIND_NOW absent — Partial RELRO only. "
                "The GOT is still writable during lazy symbol resolution."
            ),
            cwe = "CWE-693",
        ))

    # ── Mitigation: Stack Canary ──────────────────────────────────────────────
    # Scan the raw binary for the dynamic symbol name "__stack_chk_fail".
    # GCC/Clang -fstack-protector* instruments functions with a call to this.
    canary_on = _find_bytes(data, b"__stack_chk_fail")
    mits.append(Mitigation(
        name   = "Canary",
        status = "enabled" if canary_on else "disabled",
        detail = (
            "__stack_chk_fail found in binary — compiled with -fstack-protector."
            if canary_on else
            "__stack_chk_fail absent — no stack canary instrumentation detected."
        ),
        cwe = "" if canary_on else "CWE-121",
    ))

    # ── PE-only mitigations — mark N/A for ELF ───────────────────────────────
    mits.append(Mitigation(
        name   = "SafeSEH",
        status = "unknown",
        detail = "SafeSEH is a PE/Windows-only mitigation; not applicable to ELF.",
    ))
    mits.append(Mitigation(
        name   = "CFG",
        status = "unknown",
        detail = "Control Flow Guard is a PE/Windows-only mitigation; not applicable to ELF.",
    ))

    return ChecksecResult(
        path        = "",
        fmt         = fmt,
        sha256      = _sha256(data),
        size_bytes  = len(data),
        mitigations = mits,
        errors      = errors,
    )


# ---------------------------------------------------------------------------
# Public API: inspect
# ---------------------------------------------------------------------------

def inspect(path: str | Path) -> ChecksecResult:
    """
    Inspect a binary file for security mitigations.

    Automatically detects PE (Windows) or ELF (Linux) format from the
    magic bytes and dispatches to the appropriate parser.

    Parameters
    ----------
    path : str or Path
        Path to the binary file.  Must be readable.

    Returns
    -------
    ChecksecResult
        Full mitigation report including SHA-256, format, and per-control
        findings with CWE tags for absent controls.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    ValueError
        If the file format is not recognised as PE or ELF.
    OSError
        If the file cannot be read.

    Examples
    --------
    >>> result = inspect("/usr/bin/ls")
    >>> result.fmt
    'ELF64'
    >>> result.get("NX").status
    'enabled'
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Binary not found: {p}")

    data: bytes = p.read_bytes()

    if len(data) < 4:
        raise ValueError("File too small to identify format.")

    magic4 = data[:4]

    if magic4[:2] == b"MZ":
        result = _parse_pe(data)
    elif magic4 == _ELF_MAGIC:
        result = _parse_elf(data)
    else:
        raise ValueError(
            f"Unrecognised file format (magic bytes: {magic4.hex()}). "
            "Only PE (MZ) and ELF (0x7fELF) binaries are supported."
        )

    result.path = str(p.resolve())
    return result


# ---------------------------------------------------------------------------
# Public API: format_report
# ---------------------------------------------------------------------------

_STATUS_ICON = {
    "enabled":  "✔",
    "disabled": "✘",
    "partial":  "◑",
    "unknown":  "?",
}

def format_report(result: ChecksecResult, *, color: bool = True) -> str:
    """
    Render a ChecksecResult as a human-readable text report.

    Parameters
    ----------
    result : ChecksecResult
        The report to format.
    color  : bool
        If True (default), emit ANSI colour codes for terminal output.
        Set to False for plain text / file output.

    Returns
    -------
    str
        Multi-line formatted report.

    Examples
    --------
    >>> print(format_report(inspect("/bin/ls")))
    """
    GREEN  = "\033[32m" if color else ""
    RED    = "\033[31m" if color else ""
    YELLOW = "\033[33m" if color else ""
    GREY   = "\033[90m" if color else ""
    BOLD   = "\033[1m"  if color else ""
    RESET  = "\033[0m"  if color else ""

    lines: list[str] = [
        f"{BOLD}{'─' * 60}{RESET}",
        f"{BOLD}  Aegis checksec — {result.fmt}{RESET}",
        f"  Path   : {result.path}",
        f"  Size   : {result.size_bytes:,} bytes",
        f"  SHA256 : {result.sha256}",
        f"{BOLD}{'─' * 60}{RESET}",
        f"  {'Control':<10}  {'Status':<10}  Detail",
        f"  {'─'*10}  {'─'*10}  {'─'*35}",
    ]

    for m in result.mitigations:
        icon = _STATUS_ICON.get(m.status, "?")
        if m.status == "enabled":
            col = GREEN
        elif m.status == "disabled":
            col = RED
        elif m.status == "partial":
            col = YELLOW
        else:
            col = GREY

        cwe_tag = f"  {YELLOW}[{m.cwe}]{RESET}" if m.cwe else ""
        lines.append(
            f"  {col}{icon} {m.name:<10}{RESET}  "
            f"{col}{m.status:<10}{RESET}  "
            f"{m.detail}{cwe_tag}"
        )

    lines.append(f"{BOLD}{'─' * 60}{RESET}")
    lines.append(
        f"  Score : {result.score}/{len(result.mitigations)} controls enabled"
    )
    if result.errors:
        lines.append(f"  {YELLOW}Warnings:{RESET}")
        for e in result.errors:
            lines.append(f"    ! {e}")
    lines.append(f"{BOLD}{'─' * 60}{RESET}")
    return "\n".join(lines)
