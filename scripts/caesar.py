#!/usr/bin/env python3
"""
caesar.py — print all 26 Caesar shifts (and ROT47 for symbols).

usage:
  caesar.py 'Uryyb Jbeyq'
  echo 'Uryyb Jbeyq' | caesar.py -
  caesar.py --rot47 '!$%&(uryyb'
"""
import sys


def shift(s: str, n: int) -> str:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + n) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + n) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def rot47(s: str) -> str:
    return "".join(chr(33 + (ord(ch) - 33 + 47) % 94) if 33 <= ord(ch) <= 126 else ch for ch in s)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    if sys.argv[1] == "--rot47":
        s = sys.argv[2] if len(sys.argv) > 2 else sys.stdin.read().rstrip()
        print(rot47(s)); return
    s = sys.argv[1]
    if s == "-":
        s = sys.stdin.read().rstrip()
    for n in range(26):
        print(f"{n:>2}  {shift(s, n)}")


if __name__ == "__main__":
    main()
