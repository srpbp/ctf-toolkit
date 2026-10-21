#!/usr/bin/env python3
"""stego-whitespace.py — detect + decode whitespace steganography.

Naive bit-level schemes implemented here:

  binary         Trailing space/tab bits (SPACE=0 TAB=1), 8-bit LSB-first bytes.
  binary-swap    Same, but SPACE=1 TAB=0.
  binary-msb-rev Bits reversed within each byte.
  count          Space-count-per-line as a byte value.
  inline         Space/tab bits BETWEEN words (not trailing).

For the **real** SNOW algorithm (Matthew Kwan): 3-bit values via spaces-between-
tabs, 6-bit base64-style packing, optional ICE encryption. Use `--snow` to
delegate to the system `stegsnow` binary (brew install snow / apt install stegsnow).

usage:
  stego-whitespace.py <path>                        # auto: try naive schemes
  stego-whitespace.py <path> --snow                 # delegate to real stegsnow
  stego-whitespace.py <path> --snow --password KEY  # ICE-encrypted stegsnow
  stego-whitespace.py <path> --snow-brute wordlist  # bruteforce stegsnow password
  stego-whitespace.py <path> --scheme binary|binary-swap|binary-msb-rev|count|inline
  stego-whitespace.py <path> --diag                 # dump per-line signature
"""
import argparse, re, shutil, subprocess, sys


def read_text(p: str) -> list[str]:
    with open(p, "rb") as f:
        data = f.read().decode("utf-8", errors="replace")
    return data.splitlines(keepends=False)


def extract_trailing(line: str) -> str:
    m = re.search(r"[ \t]+$", line)
    return m.group(0) if m else ""


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


def dec_binary_swapped(lines):
    """Space=1, tab=0 (opposite of 'binary')."""
    bits = []
    for ln in lines:
        for c in extract_trailing(ln):
            bits.append("1" if c == " " else "0")
    return _bits_to_bytes("".join(bits))


def dec_binary_msb_rev(lines):
    """Bits reversed within each byte (encoder was MSB-first-per-byte, not LSB)."""
    bits = []
    for ln in lines:
        for c in extract_trailing(ln):
            bits.append("0" if c == " " else "1")
    s = "".join(bits); n = len(s) - (len(s) % 8)
    out = bytearray()
    for i in range(0, n, 8):
        out.append(int(s[i:i+8][::-1], 2))
    return bytes(out)


SCHEMES = {
    "binary":         dec_binary,
    "binary-swap":    dec_binary_swapped,
    "binary-msb-rev": dec_binary_msb_rev,
    "count":          dec_count,
    "inline":         dec_inline,
}


# ---------- real SNOW (delegates to stegsnow binary) ----------
def run_stegsnow(path: str, password: str | None = None) -> bytes:
    if not shutil.which("stegsnow"):
        sys.exit("stegsnow not installed. Install:\n  brew install snow   # macOS\n  apt install stegsnow # Debian/Ubuntu/Kali")
    import os
    cwd = os.path.dirname(os.path.abspath(path)) or "."
    name = os.path.basename(path)
    cmd = ["stegsnow", "-C"]
    if password is not None:
        cmd += ["-p", password]
    cmd += [name]
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=10)
    except subprocess.TimeoutExpired:
        return b""
    return r.stdout


def snow_brute(path: str, wordlist: str, success_substrings: list[str] | None = None):
    import os
    cwd = os.path.dirname(os.path.abspath(path)) or "."
    name = os.path.basename(path)
    hits = []
    with open(wordlist, "rb") as f:
        for raw in f:
            pw = raw.rstrip(b"\r\n").decode(errors="ignore")
            try:
                r = subprocess.run(["stegsnow", "-C", "-p", pw, name],
                                   cwd=cwd, capture_output=True, timeout=5)
            except subprocess.TimeoutExpired:
                continue
            out = r.stdout
            if not out: continue
            if success_substrings:
                if any(s.encode() in out for s in success_substrings):
                    print(f"[+] HIT  pw={pw!r}  → {out[:200]!r}")
                    hits.append(pw)
                    return
            else:
                # heuristic: >90% printable AND has common English bigrams
                pr = sum(1 for x in out if 32 <= x < 127 or x in (9, 10, 13)) / len(out)
                english_bigrams = sum(bg in out for bg in (b" th", b"the", b" an", b"ing", b"ion", b"ent"))
                if pr > 0.9 and english_bigrams >= 2:
                    print(f"[~] pw={pw!r}  → {out[:200]!r}")
                    hits.append(pw)
    if not hits:
        print("[-] no hits.")


def report(name: str, data: bytes):
    pr = printable_ratio(data)
    marker = "  ✓" if pr > 0.85 and data else ""
    print(f"  {name:16s}  {len(data):4d} bytes  printable={pr*100:3.0f}%  {preview(data)}{marker}")


def diag(lines: list[str]):
    """Dump per-line whitespace signature so humans can eyeball the pattern."""
    print("per-line trailing-whitespace signature (· = space, → = tab):\n")
    for i, ln in enumerate(lines, 1):
        t = extract_trailing(ln)
        if not t: continue
        pat = t.replace(" ", "·").replace("\t", "→")
        kinds = f"S={t.count(' ')} T={t.count(chr(9))}"
        print(f"  line {i:3d}: len={len(t):2d}  {kinds:8s}  [{pat}]")
    print("\nglobal counts:")
    all_tr = "".join(extract_trailing(ln) for ln in lines)
    print(f"  total trailing chars: {len(all_tr)}  (spaces={all_tr.count(' ')}  tabs={all_tr.count(chr(9))})")
    if len(all_tr) % 8 == 0:
        print(f"  divisible by 8 ✓ — straight 1-bit-per-char binary encoding fits")
    for n in (3, 4, 5, 7):
        if len(all_tr) % n == 0:
            print(f"  divisible by {n} — could be {n}-bit groups per unit")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--scheme", choices=list(SCHEMES))
    ap.add_argument("--inline", action="store_true", help="include inline (between-word) scheme")
    ap.add_argument("--diag", action="store_true", help="dump per-line whitespace signature only")
    ap.add_argument("--snow", action="store_true", help="use real stegsnow binary (requires install)")
    ap.add_argument("--password", help="passphrase for --snow (ICE encryption)")
    ap.add_argument("--snow-brute", metavar="WORDLIST", help="brute --snow password from wordlist")
    ap.add_argument("--expect", action="append", help="success substring for --snow-brute (repeatable, e.g. 'flag{', 'FLAG{')")
    ap.add_argument("-o", "--out", help="write decoded bytes to this file (highest-printable scheme only)")
    args = ap.parse_args()

    if args.snow_brute:
        snow_brute(args.path, args.snow_brute, args.expect)
        return
    if args.snow:
        out = run_stegsnow(args.path, args.password)
        sys.stdout.buffer.write(out)
        if out and not out.endswith(b"\n"): print()
        return
    if args.diag:
        diag(read_text(args.path))
        return

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
