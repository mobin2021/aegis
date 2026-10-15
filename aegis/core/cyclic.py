"""
aegis/core/cyclic.py
====================
De Bruijn Cyclic Pattern Generator & Crash-Offset Resolver
-----------------------------------------------------------

MATHEMATICAL FOUNDATION
-----------------------
A De Bruijn sequence B(k, n) over alphabet Σ (|Σ| = k) is a cyclic sequence
of length k^n in which every possible length-n string over Σ appears as a
contiguous substring exactly once.

For exploit development we instantiate B(26, 4) (26 ASCII lowercase letters,
4-byte windows):
  - Total unique 4-byte sub-patterns: 26^4 = 456,976
  - A 26^4-byte pattern safely covers any x86/x86-64 stack frame in practice.

GENERATION ALGORITHM — FKT (Fredericksen–Kessler–Maurer)
---------------------------------------------------------
The FKT algorithm generates the lexicographically-smallest De Bruijn sequence
by concatenating Lyndon words whose lengths divide n.

We implement the classic recursive version via a generator, which avoids
Python's recursion-depth limit by using an explicit call stack of (t, p)
pairs — where `t` is the current position and `p` is the parent necklace period.

Equivalently, the standard iterative formulation (Martin 1934 / FKT):

    a = [alphabet[0]] * (n+1)         # 1-indexed working array
    i = n
    while i > 0:
        a[i] = next symbol after a[i]  # "increment" step
        if n % i == 0: emit a[1..i]    # Lyndon condition
        i = n                           # reset to end

This yields exactly k^n bytes total.

OFFSET RESOLUTION
-----------------
Given a crash value (e.g. RIP = 0x61616264 on 32-bit), we pack it as
little-endian bytes and call bytes.find() on the generated pattern.
CPython's bytes.find() uses a tuned Boyer-Moore-Horspool variant: O(n).

For 64-bit targets we strip canonical sign-extension bits (upper 2 bytes)
and try a 4-byte window first, then fall back to 8 bytes.

ALPHABET
--------
Lowercase ASCII a–z (k=26): null-free, printable, survives strcpy/gets.

USAGE (CLI)
-----------
  python -m aegis cyclic 200
  python -m aegis cyclic --find 0x61616264
  python -m aegis cyclic --find 0x61616264 --arch 64
"""

from __future__ import annotations

import struct
from typing import Generator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALPHABET: bytes = b"abcdefghijklmnopqrstuvwxyz"   # k = 26, printable, null-free
_ORDER: int      = 4                                # n = 4  → every 4-byte window unique
_MAX_SAFE: int   = len(_ALPHABET) ** _ORDER         # 26^4 = 456,976 bytes maximum

# ---------------------------------------------------------------------------
# Internal: De Bruijn generator — Martin / FKT iterative
# ---------------------------------------------------------------------------

def _debruijn_sequence(alphabet: bytes = _ALPHABET, n: int = _ORDER) -> Generator[int, None, None]:
    """
    Yield individual byte values forming the De Bruijn sequence B(k, n).

    Implements the classic iterative necklace algorithm (Martin 1934 /
    Fredericksen-Kessler-Maurer).  Yields exactly k^n bytes.

    Algorithm
    ---------
    Maintain a 1-indexed array `a[1..n]`, all starting at 0 (= alphabet[0]).
    `i` scans right-to-left from n:

      while i > 0:
          a[i] += 1                         # increment position i
          if n % i == 0: emit a[1..i]       # Lyndon condition: emit this word
          extend a[i+1..n] by tiling a[1..i]  (keep period = i)
          walk right-to-left to find next i to increment

    Time: O(k^n)   Space: O(n)
    Total output: exactly k^n bytes.

    Parameters
    ----------
    alphabet : bytes
        Symbol set; each element is a byte value 0–255.
    n        : int
        Window width (sub-pattern length).

    Yields
    ------
    int
        Individual byte values from the De Bruijn sequence.
    """
    k: int = len(alphabet)

    # 1-indexed working array; a[0] is unused (keeps indexing clean)
    a: list[int] = [0] * (n + 1)
    # j tracks current Lyndon period
    j: int = 1

    # ── seed: a=[0,0,...,0], period j=1 → emit alphabet[0] once (n%1==0) ──
    # This is handled naturally by the loop below — initial a is all zeros,
    # which represents the all-first-symbol Lyndon word of period 1.
    # We prime by setting up correctly and entering the emit-then-advance loop.

    while True:
        # ── EMIT ──────────────────────────────────────────────────────────────
        # Emit the current Lyndon word of length j when j divides n.
        # This is the Lyndon condition: tiling a[1..j] fills exactly n/j
        # positions of the n-window, so this word contributes j bytes.
        if n % j == 0:
            for idx in range(1, j + 1):
                yield alphabet[a[idx]]

        # ── ADVANCE ───────────────────────────────────────────────────────────
        # Copy a[1..j] cyclically into a[j+1..n] to set up the next candidate.
        for pos in range(j + 1, n + 1):
            a[pos] = a[pos - j]

        # Walk right-to-left from n to find rightmost position where we can
        # increment (a[i] < k-1 means symbol can grow).
        i: int = n
        while i > 0 and a[i] >= k - 1:
            i -= 1

        if i == 0:
            # All symbols are at maximum — sequence exhausted
            break

        # Increment the rightmost growable position
        a[i] += 1

        # New Lyndon period = i
        j = i


# ---------------------------------------------------------------------------
# Public API: generate
# ---------------------------------------------------------------------------

def generate(length: int, alphabet: bytes = _ALPHABET, n: int = _ORDER) -> bytes:
    """
    Generate a De Bruijn cyclic pattern of exactly *length* bytes.

    Every contiguous *n*-byte sub-sequence within the returned bytes is
    globally unique — provided length ≤ len(alphabet)^n.

    Parameters
    ----------
    length   : int
        Desired pattern length in bytes.  Must be in [1, 26^4 = 456976].
    alphabet : bytes, optional
        Symbol alphabet.  Defaults to lowercase ASCII a–z.
    n        : int, optional
        Window width.  Default 4 matches 32-bit register width.

    Returns
    -------
    bytes
        The De Bruijn pattern, exactly *length* bytes long.

    Raises
    ------
    ValueError
        If *length* is out of the valid range.

    Examples
    --------
    >>> pat = generate(20)
    >>> len(pat)
    20
    >>> pat[:4]
    b'aaaa'
    """
    max_len: int = len(alphabet) ** n
    if not (1 <= length <= max_len):
        raise ValueError(
            f"length must be between 1 and {max_len} "
            f"(alphabet^n = {len(alphabet)}^{n}); got {length}."
        )

    out = bytearray()
    for byte_val in _debruijn_sequence(alphabet, n):
        out.append(byte_val)
        if len(out) >= length:
            break

    return bytes(out[:length])


# ---------------------------------------------------------------------------
# Public API: find_offset
# ---------------------------------------------------------------------------

def find_offset(
    crash_value: int,
    length: int = _MAX_SAFE,
    alphabet: bytes = _ALPHABET,
    n: int = _ORDER,
    arch: int = 32,
) -> int | None:
    """
    Resolve the exact byte offset of a crash value within the De Bruijn pattern.

    Answers: "My debugger shows RIP/EIP = 0x61616264.  How many padding bytes
    come before the overwritten register?"

    Parameters
    ----------
    crash_value : int
        Integer value observed in the overwritten register (e.g. 0x61616264).
    length      : int, optional
        Pattern length to search.  Default is the full 456,976-byte sequence.
    alphabet    : bytes, optional
        Must match the alphabet used to generate the input pattern.
    n           : int, optional
        Window width.  Default 4.
    arch        : int, optional
        Target architecture: 32 or 64.
        - 32-bit: interprets crash_value as a 4-byte little-endian word.
        - 64-bit: strips upper canonical bits, searches 4-byte window first,
          falls back to 8-byte window.

    Returns
    -------
    int or None
        Byte offset from pattern start, or None if value not found.

    Raises
    ------
    ValueError
        If arch is not 32 or 64, or crash_value exceeds the arch width.

    Examples
    --------
    >>> pat = generate(100)
    >>> val = struct.unpack("<I", pat[42:46])[0]
    >>> find_offset(val)
    42
    """
    if arch not in (32, 64):
        raise ValueError(f"arch must be 32 or 64, got {arch}.")

    # ── Build needle ─────────────────────────────────────────────────────────
    if arch == 32:
        if crash_value > 0xFFFF_FFFF:
            raise ValueError(
                f"crash_value 0x{crash_value:X} exceeds 32-bit width. "
                "Did you mean --arch 64?"
            )
        needle: bytes = struct.pack("<I", crash_value)

    else:  # 64-bit
        if crash_value > 0xFFFF_FFFF_FFFF_FFFF:
            raise ValueError(f"crash_value 0x{crash_value:X} exceeds 64-bit width.")
        # Strip upper 2 canonical bytes (sign-extension from MMU)
        masked: int = crash_value & 0x0000_FFFF_FFFF_FFFF
        needle = struct.pack("<I", masked & 0xFFFF_FFFF)   # 4-byte fast path

    # ── Search ───────────────────────────────────────────────────────────────
    pattern: bytes = generate(length, alphabet, n)
    idx: int = pattern.find(needle)
    if idx != -1:
        return idx

    # ── 64-bit fallback: full 8-byte window ──────────────────────────────────
    if arch == 64:
        needle8: bytes = struct.pack("<Q", crash_value & 0xFFFF_FFFF_FFFF_FFFF)
        idx8: int = pattern.find(needle8)
        if idx8 != -1:
            return idx8

    return None


# ---------------------------------------------------------------------------
# Public API: cyclic_metainfo
# ---------------------------------------------------------------------------

def cyclic_metainfo(length: int) -> dict:
    """
    Return metadata about a cyclic pattern without generating the full bytes.

    Useful for the GUI telemetry panel to display De Bruijn properties.

    Parameters
    ----------
    length : int
        The requested pattern length.

    Returns
    -------
    dict with keys:
        length          – actual pattern length
        alphabet_size   – k (26)
        window_width    – n (4)
        max_safe_length – k^n (456,976)
        coverage_pct    – length / max_safe_length * 100  (float)
        unique_windows  – number of guaranteed-unique n-byte sub-patterns
        alphabet        – the alphabet string

    Examples
    --------
    >>> cyclic_metainfo(200)['unique_windows']
    197
    """
    k: int   = len(_ALPHABET)
    n: int   = _ORDER
    max_len  = k ** n
    coverage = (min(length, max_len) / max_len) * 100.0
    unique_windows = max(0, min(length, max_len) - n + 1)

    return {
        "length":          length,
        "alphabet_size":   k,
        "window_width":    n,
        "max_safe_length": max_len,
        "coverage_pct":    round(coverage, 4),
        "unique_windows":  unique_windows,
        "alphabet":        _ALPHABET.decode(),
    }
