"""
tests/test_checksec.py
======================
Unit tests for aegis.core.checksec.

Strategy: build minimal synthetic PE32, PE32+, ELF32, and ELF64 binaries
from raw bytes in-memory, write them to a temporary directory, and run the
parser against them.  No real OS binaries required — every test is portable
and reproducible.

Run with:  python -m pytest tests/test_checksec.py -v
"""

import struct
import tempfile
import unittest
from pathlib import Path

from aegis.core.checksec import (
    ChecksecResult,
    Mitigation,
    format_report,
    inspect,
)


# ---------------------------------------------------------------------------
# Synthetic binary builders
# ---------------------------------------------------------------------------

class _PEBuilder:
    """
    Construct a minimal but structurally valid PE32 or PE32+ blob.

    The blob contains:
      - 64-byte DOS header (MZ magic + e_lfanew = 0x40)
      - 4-byte PE signature
      - 20-byte File Header
      - Optional Header with configurable DllCharacteristics
    Optionally appends __security_cookie string to simulate /GS.
    """

    def __init__(self, pe_plus: bool = False, dll_chars: int = 0,
                 with_canary: bool = False):
        self.pe_plus    = pe_plus
        self.dll_chars  = dll_chars
        self.with_canary = with_canary

    def build(self) -> bytes:
        NT_OFFSET = 0x40   # e_lfanew value

        # ── DOS header ──────────────────────────────────────────────────────
        dos = bytearray(64)
        struct.pack_into("<H", dos, 0x00, 0x5A4D)   # MZ magic
        struct.pack_into("<I", dos, 0x3C, NT_OFFSET) # e_lfanew

        # ── PE signature ─────────────────────────────────────────────────────
        pe_sig = struct.pack("<I", 0x00004550)        # "PE\0\0"

        # ── File Header (20 bytes) ────────────────────────────────────────────
        # Machine(H) NumSections(H) TimeDateStamp(I) PtrSymTable(I)
        # NumSymbols(I) SizeOptHdr(H) Characteristics(H)
        if self.pe_plus:
            opt_magic = 0x020B
            opt_size  = 112    # PE32+ Optional Header minimum
        else:
            opt_magic = 0x010B
            opt_size  = 96     # PE32 Optional Header minimum

        file_hdr = struct.pack("<HHIIIHH",
            0x8664 if self.pe_plus else 0x014C,  # Machine
            0,                                    # NumberOfSections
            0,                                    # TimeDateStamp
            0,                                    # PointerToSymbolTable
            0,                                    # NumberOfSymbols
            opt_size,                             # SizeOfOptionalHeader
            0x0002,                               # Characteristics
        )

        # ── Optional Header ───────────────────────────────────────────────────
        # We only need to populate up to and including DllCharacteristics.
        if self.pe_plus:
            # PE32+ Optional Header layout (first 80 bytes relevant):
            # Magic(H) MajorLinkerVersion(B) MinorLinkerVersion(B)
            # SizeOfCode(I) SizeOfInitData(I) SizeOfUninitData(I)
            # AddressOfEntryPoint(I) BaseOfCode(I)
            # ImageBase(Q) SectionAlignment(I) FileAlignment(I)
            # MajorOSVersion(H) MinorOSVersion(H) MajorImgVersion(H) MinorImgVersion(H)
            # MajorSubsystemVersion(H) MinorSubsystemVersion(H) Win32VersionValue(I)
            # SizeOfImage(I) SizeOfHeaders(I) CheckSum(I) Subsystem(H)
            # DllCharacteristics(H)   ← at offset 0x4E from Optional Header start
            opt = bytearray(opt_size)
            struct.pack_into("<H", opt, 0x00, opt_magic)
            struct.pack_into("<H", opt, 0x4E, self.dll_chars)
        else:
            # PE32 Optional Header layout (first 68 bytes relevant):
            # ... DllCharacteristics is at offset 0x46
            opt = bytearray(opt_size)
            struct.pack_into("<H", opt, 0x00, opt_magic)
            struct.pack_into("<H", opt, 0x46, self.dll_chars)

        blob = bytes(dos) + pe_sig + file_hdr + bytes(opt)

        if self.with_canary:
            blob += b"\x00__security_cookie\x00"

        return blob


class _ELFBuilder:
    """
    Construct a minimal but structurally valid ELF32 or ELF64 blob
    with configurable program headers.
    """

    def __init__(self, bits: int = 64,
                 e_type: int = 3,          # 3 = ET_DYN (PIE)
                 has_gnu_stack: bool = True,
                 stack_executable: bool = False,
                 has_relro: bool = False,
                 bind_now: bool = False,
                 with_canary: bool = False):
        assert bits in (32, 64)
        self.bits             = bits
        self.e_type           = e_type
        self.has_gnu_stack    = has_gnu_stack
        self.stack_executable = stack_executable
        self.has_relro        = has_relro
        self.bind_now         = bind_now
        self.with_canary      = with_canary

    def build(self) -> bytes:
        endian = "<"   # always little-endian for simplicity

        # ── Build program headers ─────────────────────────────────────────────
        ph_entries: list[bytes] = []

        def _add_ph32(p_type: int, p_flags: int) -> None:
            ph_entries.append(struct.pack(f"{endian}IIIIIIII",
                p_type,  # p_type
                0,       # p_offset
                0,       # p_vaddr
                0,       # p_paddr
                0,       # p_filesz
                0,       # p_memsz
                p_flags, # p_flags
                0,       # p_align
            ))

        def _add_ph64(p_type: int, p_flags: int) -> None:
            ph_entries.append(struct.pack(f"{endian}IIQQQQQQ",
                p_type,  # p_type
                p_flags, # p_flags   (ELF64 Phdr has flags BEFORE p_offset)
                0,       # p_offset
                0,       # p_vaddr
                0,       # p_paddr
                0,       # p_filesz
                0,       # p_memsz
                0,       # p_align
            ))

        add_ph = _add_ph64 if self.bits == 64 else _add_ph32
        PF_R   = 0x4
        PF_W   = 0x2
        PF_X   = 0x1

        if self.has_gnu_stack:
            stack_flags = PF_R | PF_W | (PF_X if self.stack_executable else 0)
            add_ph(0x6474E551, stack_flags)   # PT_GNU_STACK

        if self.has_relro:
            add_ph(0x6474E552, PF_R)          # PT_GNU_RELRO

        # Add a minimal PT_DYNAMIC if bind_now requested
        dyn_offset = 0
        dyn_size   = 0
        if self.bind_now:
            # Build a tiny dynamic section with DT_FLAGS=DF_BIND_NOW + DT_NULL
            if self.bits == 32:
                dyn_blob = struct.pack(f"{endian}Ii", 0x1E, 0x08)   # DT_FLAGS, DF_BIND_NOW
                dyn_blob += struct.pack(f"{endian}Ii", 0, 0)         # DT_NULL
            else:
                dyn_blob = struct.pack(f"{endian}Qq", 0x1E, 0x08)
                dyn_blob += struct.pack(f"{endian}Qq", 0, 0)

            # We'll append dyn_blob after the headers; record offset later.
            # For simplicity, store a placeholder offset — we fix it below.
            dyn_size = len(dyn_blob)
            # PT_DYNAMIC ph will reference this blob
        else:
            dyn_blob = b""

        ph_bytes = b"".join(ph_entries)

        # ── ELF header ────────────────────────────────────────────────────────
        if self.bits == 32:
            e_phentsize = 32
            e_ehsize    = 52
            hdr_size    = 52
        else:
            e_phentsize = 56
            e_ehsize    = 64
            hdr_size    = 64

        e_phoff = hdr_size                   # program headers immediately after ELF header
        e_phnum = len(ph_entries)
        # dyn_file_offset = position where the actual dynamic section blob lands.
        # That is: after the ELF header + ALL program headers including the
        # PT_DYNAMIC ph entry we are about to add.  So n_phs_total = e_phnum + 1.
        dyn_file_offset = e_phoff + (e_phnum + 1) * (56 if self.bits == 64 else 32)

        # Re-build PT_DYNAMIC ph with correct offset if needed
        if self.bind_now:
            ph_entries_rebuilt: list[bytes] = []
            if self.bits == 32:
                ph_entries_rebuilt = list(ph_entries) + [
                    struct.pack(f"{endian}IIIIIIII",
                        0x00000002,        # PT_DYNAMIC
                        dyn_file_offset,   # p_offset — points past all ph entries
                        0, 0,
                        dyn_size, dyn_size,
                        PF_R | PF_W,
                        0,
                    )
                ]
            else:
                ph_entries_rebuilt = list(ph_entries) + [
                    struct.pack(f"{endian}IIQQQQQQ",
                        0x00000002,        # PT_DYNAMIC
                        PF_R | PF_W,
                        dyn_file_offset,   # p_offset — points past all ph entries
                        0, 0,
                        dyn_size, dyn_size,
                        0,
                    )
                ]
            e_phnum = len(ph_entries_rebuilt)
            ph_bytes = b"".join(ph_entries_rebuilt)

        # Build ident (16 bytes)
        ei_class = 1 if self.bits == 32 else 2
        ident = bytes([
            0x7F, 0x45, 0x4C, 0x46,  # magic
            ei_class,                  # EI_CLASS
            0x01,                      # EI_DATA = LE
            0x01,                      # EI_VERSION
            0x00,                      # EI_OSABI = ELFOSABI_NONE
        ]) + b"\x00" * 8

        if self.bits == 32:
            hdr = struct.pack(f"{endian}HHIIIIIHHHHHH",
                self.e_type,    # e_type
                0x003E,         # e_machine (x86-64, doesn't matter for our tests)
                1,              # e_version
                0,              # e_entry
                e_phoff,        # e_phoff
                0,              # e_shoff
                0,              # e_flags
                e_ehsize,       # e_ehsize
                e_phentsize,    # e_phentsize
                e_phnum,        # e_phnum
                0,              # e_shentsize
                0,              # e_shnum
                0,              # e_shstrndx
            )
        else:
            hdr = struct.pack(f"{endian}HHIQQQIHHHHHH",
                self.e_type,    # e_type
                0x003E,         # e_machine
                1,              # e_version
                0,              # e_entry (Q)
                e_phoff,        # e_phoff (Q)
                0,              # e_shoff (Q)
                0,              # e_flags
                e_ehsize,       # e_ehsize
                e_phentsize,    # e_phentsize
                e_phnum,        # e_phnum
                0,              # e_shentsize
                0,              # e_shnum
                0,              # e_shstrndx
            )

        blob = ident + hdr + ph_bytes + dyn_blob

        if self.with_canary:
            blob += b"\x00__stack_chk_fail\x00"

        return blob


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_tmp(data: bytes, suffix: str = ".bin") -> Path:
    """Write *data* to a NamedTemporaryFile and return its path."""
    f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    f.write(data)
    f.close()
    return Path(f.name)


# ---------------------------------------------------------------------------
# PE32 tests
# ---------------------------------------------------------------------------

class TestPE32Mitigations(unittest.TestCase):
    """PE32 (x86) binaries."""

    def _inspect(self, dll_chars: int = 0, with_canary: bool = False) -> ChecksecResult:
        blob = _PEBuilder(pe_plus=False, dll_chars=dll_chars,
                          with_canary=with_canary).build()
        p = _write_tmp(blob)
        try:
            return inspect(p)
        finally:
            p.unlink()

    def test_format_is_pe32(self):
        result = self._inspect()
        self.assertEqual(result.fmt, "PE32")

    def test_nx_enabled(self):
        result = self._inspect(dll_chars=0x0100)
        self.assertEqual(result.get("NX").status, "enabled")

    def test_nx_disabled(self):
        result = self._inspect(dll_chars=0x0000)
        self.assertEqual(result.get("NX").status, "disabled")
        self.assertEqual(result.get("NX").cwe, "CWE-119")

    def test_aslr_full(self):
        # DYNAMIC_BASE + HIGH_ENTROPY_VA
        result = self._inspect(dll_chars=0x0060)
        m = result.get("ASLR")
        self.assertEqual(m.status, "enabled")

    def test_aslr_partial(self):
        # DYNAMIC_BASE only
        result = self._inspect(dll_chars=0x0040)
        m = result.get("ASLR")
        self.assertEqual(m.status, "partial")

    def test_aslr_disabled(self):
        result = self._inspect(dll_chars=0x0000)
        m = result.get("ASLR")
        self.assertEqual(m.status, "disabled")
        self.assertEqual(m.cwe, "CWE-250")

    def test_canary_present(self):
        result = self._inspect(with_canary=True)
        self.assertEqual(result.get("Canary").status, "enabled")

    def test_canary_absent(self):
        result = self._inspect(with_canary=False)
        self.assertEqual(result.get("Canary").status, "disabled")
        self.assertEqual(result.get("Canary").cwe, "CWE-121")

    def test_cfg_enabled(self):
        result = self._inspect(dll_chars=0x4000)
        self.assertEqual(result.get("CFG").status, "enabled")

    def test_cfg_disabled(self):
        result = self._inspect(dll_chars=0x0000)
        self.assertEqual(result.get("CFG").status, "disabled")

    def test_relro_not_applicable(self):
        result = self._inspect()
        self.assertEqual(result.get("RELRO").status, "unknown")

    def test_sha256_present(self):
        result = self._inspect()
        self.assertEqual(len(result.sha256), 64)   # hex digest = 64 chars

    def test_all_controls_minus_nx(self):
        """Full hardened PE32: NX + ASLR + canary + CFG."""
        flags  = 0x0100 | 0x0040 | 0x0020 | 0x4000
        result = self._inspect(dll_chars=flags, with_canary=True)
        self.assertEqual(result.get("NX").status,     "enabled")
        self.assertEqual(result.get("ASLR").status,   "enabled")
        self.assertEqual(result.get("Canary").status, "enabled")
        self.assertEqual(result.get("CFG").status,    "enabled")


class TestPE32PlusMitigations(unittest.TestCase):
    """PE32+ (x64) binaries."""

    def _inspect(self, dll_chars: int = 0, with_canary: bool = False) -> ChecksecResult:
        blob = _PEBuilder(pe_plus=True, dll_chars=dll_chars,
                          with_canary=with_canary).build()
        p = _write_tmp(blob)
        try:
            return inspect(p)
        finally:
            p.unlink()

    def test_format_is_pe32plus(self):
        result = self._inspect()
        self.assertEqual(result.fmt, "PE32+")

    def test_nx_at_plus_offset(self):
        """DllCharacteristics in PE32+ is at a different offset (0x4E not 0x46)."""
        result = self._inspect(dll_chars=0x0100)
        self.assertEqual(result.get("NX").status, "enabled")

    def test_safeseh_na_on_x64(self):
        """SafeSEH is not applicable to PE32+ (x64 uses unwind tables)."""
        result = self._inspect()
        self.assertEqual(result.get("SafeSEH").status, "unknown")


# ---------------------------------------------------------------------------
# ELF64 tests
# ---------------------------------------------------------------------------

class TestELF64Mitigations(unittest.TestCase):
    """ELF64 binaries."""

    def _inspect(self, **kw) -> ChecksecResult:
        blob = _ELFBuilder(bits=64, **kw).build()
        p = _write_tmp(blob)
        try:
            return inspect(p)
        finally:
            p.unlink()

    def test_format_is_elf64(self):
        result = self._inspect()
        self.assertEqual(result.fmt, "ELF64")

    def test_pie_enabled(self):
        result = self._inspect(e_type=3)   # ET_DYN
        self.assertEqual(result.get("ASLR").status, "enabled")

    def test_pie_disabled(self):
        result = self._inspect(e_type=2)   # ET_EXEC
        self.assertEqual(result.get("ASLR").status, "disabled")
        self.assertEqual(result.get("ASLR").cwe, "CWE-250")

    def test_nx_enabled(self):
        result = self._inspect(has_gnu_stack=True, stack_executable=False)
        self.assertEqual(result.get("NX").status, "enabled")

    def test_nx_disabled(self):
        result = self._inspect(has_gnu_stack=True, stack_executable=True)
        self.assertEqual(result.get("NX").status, "disabled")
        self.assertEqual(result.get("NX").cwe, "CWE-119")

    def test_nx_unknown_no_gnustack(self):
        result = self._inspect(has_gnu_stack=False)
        self.assertEqual(result.get("NX").status, "unknown")

    def test_relro_disabled(self):
        result = self._inspect(has_relro=False)
        self.assertEqual(result.get("RELRO").status, "disabled")
        self.assertEqual(result.get("RELRO").cwe, "CWE-693")

    def test_relro_partial(self):
        result = self._inspect(has_relro=True, bind_now=False)
        self.assertEqual(result.get("RELRO").status, "partial")

    def test_relro_full(self):
        result = self._inspect(has_relro=True, bind_now=True)
        self.assertEqual(result.get("RELRO").status, "enabled")

    def test_canary_present(self):
        result = self._inspect(with_canary=True)
        self.assertEqual(result.get("Canary").status, "enabled")

    def test_canary_absent(self):
        result = self._inspect(with_canary=False)
        self.assertEqual(result.get("Canary").status, "disabled")
        self.assertEqual(result.get("Canary").cwe, "CWE-121")

    def test_cfg_not_applicable(self):
        result = self._inspect()
        self.assertEqual(result.get("CFG").status, "unknown")

    def test_fully_hardened_elf64(self):
        """All mitigations active on a hardened ELF64."""
        result = self._inspect(
            e_type=3,
            has_gnu_stack=True, stack_executable=False,
            has_relro=True, bind_now=True,
            with_canary=True,
        )
        self.assertEqual(result.get("ASLR").status,   "enabled")
        self.assertEqual(result.get("NX").status,     "enabled")
        self.assertEqual(result.get("RELRO").status,  "enabled")
        self.assertEqual(result.get("Canary").status, "enabled")


class TestELF32Mitigations(unittest.TestCase):
    """ELF32 binaries."""

    def _inspect(self, **kw) -> ChecksecResult:
        blob = _ELFBuilder(bits=32, **kw).build()
        p = _write_tmp(blob)
        try:
            return inspect(p)
        finally:
            p.unlink()

    def test_format_is_elf32(self):
        result = self._inspect()
        self.assertEqual(result.fmt, "ELF32")

    def test_nx_relro_canary_elf32(self):
        result = self._inspect(
            has_gnu_stack=True, stack_executable=False,
            has_relro=True, bind_now=True,
            with_canary=True,
        )
        self.assertEqual(result.get("NX").status,     "enabled")
        self.assertEqual(result.get("RELRO").status,  "enabled")
        self.assertEqual(result.get("Canary").status, "enabled")


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

class TestErrorHandling(unittest.TestCase):

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            inspect("/absolutely/nonexistent/binary.exe")

    def test_unknown_format(self):
        p = _write_tmp(b"JUNK" * 100)
        try:
            with self.assertRaises(ValueError):
                inspect(p)
        finally:
            p.unlink()

    def test_too_small(self):
        p = _write_tmp(b"MZ")
        try:
            with self.assertRaises(ValueError):
                inspect(p)
        finally:
            p.unlink()

    def test_sha256_is_hex_64(self):
        blob = _PEBuilder(pe_plus=False).build()
        p    = _write_tmp(blob)
        try:
            r = inspect(p)
            self.assertRegex(r.sha256, r"^[0-9a-f]{64}$")
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# format_report smoke test
# ---------------------------------------------------------------------------

class TestFormatReport(unittest.TestCase):

    def test_report_contains_controls(self):
        blob = _PEBuilder(pe_plus=False, dll_chars=0x0140,
                          with_canary=True).build()
        p    = _write_tmp(blob)
        try:
            result = inspect(p)
        finally:
            p.unlink()

        report = format_report(result, color=False)
        for control in ["NX", "ASLR", "Canary", "CFG", "RELRO", "SafeSEH"]:
            self.assertIn(control, report, f"Control '{control}' missing from report.")

    def test_report_contains_sha256(self):
        blob = _ELFBuilder(bits=64).build()
        p    = _write_tmp(blob)
        try:
            result = inspect(p)
        finally:
            p.unlink()

        report = format_report(result, color=False)
        self.assertIn(result.sha256, report)

    def test_score_accounting(self):
        """score == count of 'enabled' mitigations."""
        blob = _PEBuilder(pe_plus=False, dll_chars=0x0140,
                          with_canary=True).build()   # NX + ASLR(partial) + canary
        p    = _write_tmp(blob)
        try:
            result = inspect(p)
        finally:
            p.unlink()

        enabled = sum(1 for m in result.mitigations if m.status == "enabled")
        self.assertEqual(result.score, enabled)


if __name__ == "__main__":
    unittest.main(verbosity=2)
