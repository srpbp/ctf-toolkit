#!/usr/bin/env python3
"""stego-nullcipher.py — try all common null-cipher extractions on a text.

A "null cipher" hides a message inside otherwise-normal text. The flag is
usually read by taking the first (or Nth) letter of each word, line, or
sentence. Also handles acrostic (first letter per line) and column reads.

usage:
  stego-nullcipher.py <path>              # try everything, show results side-by-side
  stego-nullcipher.py <path> --n 2        # take the Nth letter per word (1-based)
  stego-nullcipher.py <path> --skip 3     # take every 3rd word's first letter
"""
import argparse, re, sys


def read_text(p: str) -> str:
    with open(p, "rb") as f:
        return f.read().decode("utf-8", errors="replace")


def words(text: str) -> list[str]:
    return re.findall(r"[A-Za-z]+", text)


def lines(text: str) -> list[str]:
    return [ln.rstrip() for ln in text.splitlines() if ln.strip()]


def sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"[.!?]+\s+", text) if s.strip()]


def nth_letter(w: str, n: int) -> str:
    # n is 1-based; negative n reads from end
    try:
        return w[n - 1] if n > 0 else w[n]
    except IndexError:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--n", type=int, help="take Nth letter of each word (default: try 1,2,3,-1)")
    ap.add_argument("--skip", type=int, default=1, help="use every Nth word (default 1)")
    ap.add_argument("--word-sep", default="", help="separator in output between letters")
    args = ap.parse_args()

    text = read_text(args.path)
    ws = words(text)
    ls = lines(text)
    ss = sentences(text)

    print(f"input: {args.path}  ({len(ws)} words, {len(ls)} non-empty lines, {len(ss)} sentences)\n")

    nvals = [args.n] if args.n is not None else [1, 2, 3, -1]
    skip = max(args.skip, 1)

    print("--- per-word (first/second/third/last letter) ---")
    for n in nvals:
        tag = {1: "1st", 2: "2nd", 3: "3rd", -1: "last"}.get(n, f"{n}th")
        selected = ws[::skip]
        decoded = args.word_sep.join(nth_letter(w, n) for w in selected if nth_letter(w, n))
        print(f"  {tag:4s} letter per word (skip={skip}):  {decoded[:200]}")

    print("\n--- acrostic (per line) ---")
    for n in nvals:
        tag = {1: "1st", 2: "2nd", 3: "3rd", -1: "last"}.get(n, f"{n}th")
        decoded = "".join(nth_letter(ln, n) for ln in ls if nth_letter(ln, n))
        print(f"  {tag:4s} char per line:  {decoded[:200]}")

    print("\n--- per sentence (first letter) ---")
    print("  first letter of each sentence: " + "".join(s[0] for s in ss if s)[:200])
    print("  last letter of each sentence:  " + "".join(s[-1] for s in ss if s)[:200])

    print("\n--- word-length chain ---")
    # Each word's length modulo 26 → letter (A=1..Z=26, 0 → space)
    def _wl_to_letter(n):
        return " " if n % 27 == 0 else chr(ord("A") + (n - 1) % 26)
    wl = "".join(_wl_to_letter(len(w)) for w in ws)
    print(f"  word-length -> A..Z (len%26):  {wl[:200]}")

    print("\n--- first letter of EVERY word (full acrostic) ---")
    print(f"  {''.join(w[0] for w in ws)[:300]}")


if __name__ == "__main__":
    main()
