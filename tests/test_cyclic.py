"""
tests/test_cyclic.py
====================
Comprehensive unit tests for aegis.core.cyclic.

Tests are self-contained: no fixtures, no mocks, no external deps.
Run with:  python -m pytest tests/test_cyclic.py -v
"""

import struct
import unittest

from aegis.core.cyclic import (
    _ALPHABET,
    _MAX_SAFE,
    _ORDER,
    cyclic_metainfo,
    find_offset,
    generate,
)


class TestGenerateLength(unittest.TestCase):
    """Pattern length contract."""

    def test_length_matches_request(self):
        for n in [1, 4, 50, 100, 200, 1000, 8192]:
            with self.subTest(n=n):
                self.assertEqual(len(generate(n)), n)

    def test_minimum_length(self):
        self.assertEqual(len(generate(1)), 1)

    def test_maximum_safe_length(self):
        # Should not raise and must return exactly _MAX_SAFE bytes
        pat = generate(_MAX_SAFE)
        self.assertEqual(len(pat), _MAX_SAFE)

    def test_over_max_raises(self):
        with self.assertRaises(ValueError):
            generate(_MAX_SAFE + 1)

    def test_zero_raises(self):
        with self.assertRaises(ValueError):
            generate(0)

    def test_negative_raises(self):
        with self.assertRaises(ValueError):
            generate(-1)


class TestPatternUniqueness(unittest.TestCase):
    """
    Core mathematical guarantee: every 4-byte window is unique.
    We verify this for a generous sample without scanning all 456 976 bytes.
    """

    _SAMPLE_LEN = 5000   # well within the 26^4 bound

    def setUp(self):
        self.pat = generate(self._SAMPLE_LEN)

    def test_no_duplicate_4byte_windows(self):
        windows = [self.pat[i:i + 4] for i in range(len(self.pat) - 3)]
        self.assertEqual(
            len(windows),
            len(set(windows)),
            "Duplicate 4-byte sub-patterns detected — De Bruijn property violated.",
        )

    def test_all_bytes_are_printable_ascii(self):
        for b in self.pat:
            self.assertIn(b, _ALPHABET, f"Non-alphabet byte 0x{b:02x} found.")

    def test_no_null_bytes(self):
        self.assertNotIn(0, self.pat)


class TestFindOffset32(unittest.TestCase):
    """Offset resolution — 32-bit targets."""

    def _embed_and_resolve(self, seed: int, pattern_len: int = 300) -> int | None:
        pat    = generate(pattern_len)
        needle = struct.pack("<I", struct.unpack("<I", pat[seed:seed + 4])[0])
        crash  = struct.unpack("<I", needle)[0]
        return find_offset(crash, length=pattern_len, arch=32)

    def test_offset_0(self):
        pat   = generate(100)
        crash = struct.unpack("<I", pat[0:4])[0]
        self.assertEqual(find_offset(crash, length=100, arch=32), 0)

    def test_offset_mid(self):
        for offset in [10, 42, 64, 99]:
            with self.subTest(offset=offset):
                pat   = generate(200)
                crash = struct.unpack("<I", pat[offset:offset + 4])[0]
                self.assertEqual(
                    find_offset(crash, length=200, arch=32),
                    offset,
                )

    def test_offset_near_end(self):
        pat    = generate(200)
        offset = 195
        crash  = struct.unpack("<I", pat[offset:offset + 4])[0]
        self.assertEqual(find_offset(crash, length=200, arch=32), offset)

    def test_garbage_value_returns_none(self):
        # 0x00000000 — not in any alphabet-based pattern
        self.assertIsNone(find_offset(0x00000000, length=300, arch=32))

    def test_oversized_value_raises(self):
        with self.assertRaises(ValueError):
            find_offset(0x1_0000_0000, arch=32)   # 5-byte value on 32-bit arch

    def test_invalid_arch_raises(self):
        with self.assertRaises(ValueError):
            find_offset(0x41414141, arch=16)


class TestFindOffset64(unittest.TestCase):
    """Offset resolution — 64-bit targets (canonical address masking)."""

    def test_64bit_clean_4byte_overwrite(self):
        """
        Most 64-bit crashes still show a 4-byte clean overwrite in RIP
        (the CPU zero-extends). Verify the 4-byte fast-path works.
        """
        pat    = generate(200)
        offset = 72
        low4   = struct.unpack("<I", pat[offset:offset + 4])[0]
        # Simulate what the CPU reports: zero-extended to 64-bit
        crash  = low4 & 0xFFFF_FFFF
        result = find_offset(crash, length=200, arch=64)
        self.assertEqual(result, offset)

    def test_64bit_with_canonical_noise(self):
        """
        Upper 2 bytes are 0xFFFF (sign-extension noise from kernel mapping).
        Masking must strip them before lookup.
        """
        pat    = generate(200)
        offset = 50
        low4   = struct.unpack("<I", pat[offset:offset + 4])[0]
        crash  = 0xFFFF_0000_0000_0000 | low4   # upper-bit noise
        result = find_offset(crash, length=200, arch=64)
        self.assertEqual(result, offset)

    def test_garbage_value_64_returns_none(self):
        self.assertIsNone(find_offset(0xDEAD_BEEF_DEAD_BEEF, length=300, arch=64))


class TestMetainfo(unittest.TestCase):
    """cyclic_metainfo correctness."""

    def test_max_safe_length_field(self):
        info = cyclic_metainfo(100)
        self.assertEqual(info["max_safe_length"], 26 ** 4)

    def test_coverage_pct_100(self):
        info = cyclic_metainfo(_MAX_SAFE)
        self.assertAlmostEqual(info["coverage_pct"], 100.0, places=3)

    def test_coverage_pct_partial(self):
        info = cyclic_metainfo(456)
        expected = 456 / (26 ** 4) * 100
        self.assertAlmostEqual(info["coverage_pct"], expected, places=3)

    def test_unique_windows_calculation(self):
        length = 200
        info   = cyclic_metainfo(length)
        # Sliding window count = length - window_width + 1
        self.assertEqual(info["unique_windows"], length - _ORDER + 1)

    def test_alphabet_field(self):
        info = cyclic_metainfo(100)
        self.assertEqual(info["alphabet"], _ALPHABET.decode())

    def test_alphabet_size_is_26(self):
        info = cyclic_metainfo(100)
        self.assertEqual(info["alphabet_size"], 26)


class TestDeterminism(unittest.TestCase):
    """Pattern generation must be pure / deterministic."""

    def test_same_length_same_output(self):
        a = generate(500)
        b = generate(500)
        self.assertEqual(a, b)

    def test_prefix_consistency(self):
        """Shorter pattern must be a prefix of longer one."""
        short = generate(100)
        long_ = generate(200)
        self.assertEqual(short, long_[:100])


if __name__ == "__main__":
    unittest.main(verbosity=2)
