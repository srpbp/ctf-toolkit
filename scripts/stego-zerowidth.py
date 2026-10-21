#!/usr/bin/env python3
"""stego-zerowidth.py — detect + decode zero-width character steganography.

Zero-width Unicode codepoints are invisible to humans but survive copy-paste
through most apps. Common schemes:

  binary  Two codepoints = 0 and 1 bits (e.g. U+200B=0, U+200C=1); pack to bytes.
  base4   Four codepoints = base-4 digits (ZWSP/ZWNJ/ZWJ/WJ or BOM).
  mark    One codepoint acts as a marker (presence = 1 bit per gap).

Covers the full zero-width family: ZWSP (U+200B), ZWNJ (U+200C), ZWJ (U+200D),
WJ (U+2060), BOM / ZWNBSP (U+FEFF), and the mongolian / tag characters that
some advanced schemes use (U+180E, U+E0020..U+E007F).

usage:
  stego-zerowidth.py <path>              # auto: show char histogram + try schemes
  stego-zerowidth.py <path> --scheme binary [--zero U+200B --one U+200C]
  stego-zerowidth.py <path> --scheme base4
"""
import argparse, collections, sys


# Full known zero-width set (name -> codepoint)
ZW = {
    "ZWSP":   0x200B,  # zero-width space
    "ZWNJ":   0x200C,  # zero-width non-joiner
    "ZWJ":    0x200D,  # zero-width joiner
    "WJ":     0x2060,  # word joiner
    "BOM":    0xFEFF,  # zero-width no-break space / BOM
    "MVS":    0x180E,  # mongolian vowel separator
}
# Variation selectors / tag characters (used in some schemes)
for i in range(16):
    ZW[f"VS{i+1}"] = 0xFE00 + i          # U+FE00..U+FE0F
for i in range(0x20, 0x80):
    ZW[f"TAG_{chr(i)}"] = 0xE0000 + i    # U+E0020..U+E007F (tag characters)
CP_TO_NAME = {v: k for k, v in ZW.items()}
ZW_SET = set(ZW.values())


def read_text(p: str) -> str:
    with open(p, "rb") as f:
        return f.read().decode("utf-8", errors="replace")


def zw_only(s: str) -> list[int]:
    return [ord(c) for c in s if ord(c) in ZW_SET]


def histogram(cps: list[int]) -> list[tuple[str, int]]:
    cnt = collections.Counter(cps)
    return sorted(((CP_TO_NAME.get(c, f"U+{c:04X}"), n) for c, n in cnt.items()),
                  key=lambda kv: -kv[1])


# ---------- schemes ----------
def dec_binary(cps: list[int], zero: int, one: int) -> bytes:
    bits = "".join("0" if c == zero else "1" if c == one else "" for c in cps)
    n = len(bits) - (len(bits) % 8)
    return bytes(int(bits[i:i+8], 2) for i in range(0, n, 8))


def dec_base4(cps: list[int]) -> bytes:
    """Common base4 mapping: ZWSP=0 ZWNJ=1 ZWJ=2 WJ/BOM=3."""
    m = {0x200B: 0, 0x200C: 1, 0x200D: 2, 0x2060: 3, 0xFEFF: 3}
    digits = [m[c] for c in cps if c in m]
    bits = "".join(f"{d:02b}" for d in digits)
    n = len(bits) - (len(bits) % 8)
    return bytes(int(bits[i:i+8], 2) for i in range(0, n, 8))


def dec_tag(cps: list[int]) -> bytes:
    """Unicode TAG characters U+E0020..U+E007E encode ASCII directly (subtract 0xE0000)."""
    out = bytes(c - 0xE0000 for c in cps if 0xE0020 <= c <= 0xE007E)
    return out


# ---------- helpers ----------
def printable_ratio(b: bytes) -> float:
    if not b: return 0.0
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b)


def preview(b: bytes, n: int = 160) -> str:
    s = b.decode("utf-8", errors="replace").replace("\n", "\\n")
    return s[:n] + ("…" if len(s) > n else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--scheme", choices=("binary", "base4", "tag"))
    ap.add_argument("--zero", default="U+200B", help="codepoint for 0 (e.g. U+200B)")
    ap.add_argument("--one",  default="U+200C", help="codepoint for 1 (e.g. U+200C)")
    ap.add_argument("-o", "--out", help="write decoded bytes to this file")
    args = ap.parse_args()

    text = read_text(args.path)
    cps = zw_only(text)
    print(f"input: {args.path}  ({len(text)} chars total, {len(cps)} zero-width chars)")

    if not cps:
        print("[!] no zero-width characters found. Done.")
        return

    hist = histogram(cps)
    print("\nzero-width character histogram:")
    for name, n in hist[:12]:
        print(f"  {name:14s}  {n}")

    def _parse_cp(s):
        s = s.upper().replace("U+", "").strip()
        return int(s, 16)

    if args.scheme == "binary":
        d = dec_binary(cps, _parse_cp(args.zero), _parse_cp(args.one))
        print(f"\n[binary]  {len(d)} bytes  printable={printable_ratio(d)*100:.0f}%")
        print(f"  {preview(d, 4000)}")
    elif args.scheme == "base4":
        d = dec_base4(cps)
        print(f"\n[base4]   {len(d)} bytes  printable={printable_ratio(d)*100:.0f}%")
        print(f"  {preview(d, 4000)}")
    elif args.scheme == "tag":
        d = dec_tag(cps)
        print(f"\n[tag]     {len(d)} bytes  printable={printable_ratio(d)*100:.0f}%")
        print(f"  {preview(d, 4000)}")
    else:
        # auto: pick two most-common codepoints, try BOTH 0/1 orderings; also base4 + tag
        print("\nauto: trying candidate schemes...")
        if len(hist) >= 2:
            top2 = [c for c, _ in collections.Counter(cps).most_common(2)]
            best = None
            for zero, one in ((top2[0], top2[1]), (top2[1], top2[0])):
                d = dec_binary(cps, zero, one)
                pr = printable_ratio(d)
                z_name = CP_TO_NAME.get(zero, f"U+{zero:04X}")
                o_name = CP_TO_NAME.get(one, f"U+{one:04X}")
                print(f"  binary (0={z_name:6s} 1={o_name:6s})  {len(d)} bytes  "
                      f"printable={pr*100:3.0f}%  {preview(d)}")
                if not best or pr > best[0]: best = (pr, zero, one, d)
        d4 = dec_base4(cps)
        print(f"  base4                                      {len(d4)} bytes  "
              f"printable={printable_ratio(d4)*100:.0f}%  {preview(d4)}")
        dt = dec_tag(cps)
        if dt:
            print(f"  tag (U+E0020..U+E007E as ASCII)             {len(dt)} bytes  "
                  f"printable={printable_ratio(dt)*100:.0f}%  {preview(dt)}")

    if args.out:
        d = {"binary": dec_binary(cps, _parse_cp(args.zero), _parse_cp(args.one)),
             "base4":  dec_base4(cps),
             "tag":    dec_tag(cps)}.get(args.scheme) or dec_base4(cps)
        with open(args.out, "wb") as f: f.write(d)
        print(f"\nwrote → {args.out}")


if __name__ == "__main__":
    main()
