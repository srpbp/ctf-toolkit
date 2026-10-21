#!/usr/bin/env python3
"""stego-whitespace.py — detect + decode whitespace steganography.

Covers three common schemes:

  snow     SNOW tool (Matthew Kwan): trailing spaces & tabs after lines encode
           a stream, 3-bit per space, max 7 bits per line. Compatible with
           `stegsnow -C` output format.

  binary   Trailing spaces/tabs where SPACE=0 and TAB=1 (per line, LSB-first
           within a byte, bytes left-to-right as the file is read).

  count    Count of trailing spaces per line encodes a byte value directly
           (naive but used in some CTF challenges).

usage:
  stego-whitespace.py <path>              # auto-detect: try all schemes, score each
  stego-whitespace.py <path> --scheme snow|binary|count
  stego-whitespace.py <path> --inline     # also look for space/tab bits BETWEEN words
"""
import argparse, re, sys


def read_text(p: str) -> list[str]:
    with open(p, "rb") as f:
        data = f.read().decode("utf-8", errors="replace")
    return data.splitlines(keepends=False)


def extract_trailing(line: str) -> str:
    m = re.search(r"[ \t]+$", line)
    return m.group(0) if m else ""


# ---------- SCHEME: snow ----------
def dec_snow(lines: list[str]) -> bytes:
    """SNOW uses groups of 3-bit codes per space-run; see MattKwan's docs.
    Simplified: concat all trailing ws, map ' '=0 '\t'=1, pack LSB-first."""
    bits = []
    for ln in lines:
        t = extract_trailing(ln)
        for c in t:
            bits.append("0" if c == " " else "1")
    return _bits_to_bytes("".join(bits))


# ---------- SCHEME: binary ----------
def dec_binary(lines: list[str]) -> bytes:
    bits = []
    for ln in lines:
        for c in extract_trailing(ln):
            bits.append("0" if c == " " else "1")
    return _bits_to_bytes("".join(bits))


# ---------- SCHEME: count ----------
def dec_count(lines: list[str]) -> bytes:
    out = []
    for ln in lines:
        n = len(extract_trailing(ln).replace("\t", ""))
        if 0 < n < 256:
            out.append(n)
    return bytes(out)


# ---------- SCHEME: inline between words ----------
def dec_inline(lines: list[str]) -> bytes:
    """Spaces vs tabs *between* words (not just trailing)."""
    bits = []
    for ln in lines:
        for m in re.finditer(r"[\S]([ \t])(?=\S)", ln):
            bits.append("0" if m.group(1) == " " else "1")
    return _bits_to_bytes("".join(bits))


# ---------- helpers ----------
def _bits_to_bytes(bits: str) -> bytes:
    n = len(bits) - (len(bits) % 8)
    return bytes(int(bits[i:i+8], 2) for i in range(0, n, 8))


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b)


def preview(b: bytes, n: int = 120) -> str:
    s = b.decode("utf-8", errors="replace").replace("\n", "\\n")
    return s[:n] + ("…" if len(s) > n else "")


SCHEMES = {"snow": dec_snow, "binary": dec_binary, "count": dec_count, "inline": dec_inline}


def report(name: str, data: bytes):
    pr = printable_ratio(data)
    marker = "  ✓" if pr > 0.85 and data else ""
    print(f"  {name:10s}  {len(data):4d} bytes  printable={pr*100:.0f}%  {preview(data)}{marker}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--scheme", choices=list(SCHEMES))
    ap.add_argument("--inline", action="store_true", help="include inline (between-word) scheme")
    ap.add_argument("-o", "--out", help="write decoded bytes to this file (highest-printable scheme only)")
    args = ap.parse_args()

    lines = read_text(args.path)
    anyws = any(extract_trailing(ln) for ln in lines)
    if not anyws and not args.inline:
        print("[!] no trailing whitespace found. Try --inline, or confirm the file preserved whitespace.")
    if args.scheme:
        data = SCHEMES[args.scheme](lines)
        print(preview(data, 4000)); return

    results = []
    for n, fn in SCHEMES.items():
        if n == "inline" and not args.inline:
            continue
        results.append((n, fn(lines)))

    print(f"input: {args.path}  ({len(lines)} lines)\n")
    print("scheme results (✓ = looks printable):")
    for n, d in results:
        report(n, d)

    if args.out:
        best = max(results, key=lambda kv: printable_ratio(kv[1]))
        with open(args.out, "wb") as f:
            f.write(best[1])
        print(f"\nwrote best candidate ({best[0]}) → {args.out}")


if __name__ == "__main__":
    main()
