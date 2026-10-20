#!/usr/bin/env python3
# ruff: noqa
r"""
captcha-math.py — auto-solve numeric/text math captchas.

Handles things like:
  "What is 2 + 3?"               -> 5
  "Compute: 12 x 7"              -> 84
  "7 minus 4 equals"             -> 3
  "two plus five"                -> 7         (--words)
  "<img>" with embedded text     -> use captcha-ocr.py first, pipe into this

usage:
  echo "What is 2 + 3?" | captcha-math.py
  captcha-math.py 'What is 2 + 3?'
  captcha-math.py --words 'two plus five'

Loop it against a real site:
  while :; do
      q=$(curl -s target/captcha | python3 -c 'import sys,re;print(re.search(r"captcha:\s*(.*)",sys.stdin.read()).group(1))')
      a=$(./captcha-math.py "$q")
      curl -s target/submit -d "answer=$a&..."
  done
"""
import operator, re, sys


WORDS = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4,
    "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
    "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
    "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
    "nineteen": 19, "twenty": 20, "thirty": 30, "forty": 40,
    "fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90,
    "hundred": 100,
}
OPS = {
    "+": operator.add, "plus": operator.add, "add": operator.add,
    "-": operator.sub, "minus": operator.sub, "subtract": operator.sub, "less": operator.sub,
    "*": operator.mul, "x": operator.mul, "×": operator.mul, "times": operator.mul,
    "/": operator.floordiv, "÷": operator.floordiv, "divided": operator.floordiv,
}


def words_to_num(s: str) -> int | None:
    s = s.strip().lower()
    if s.isdigit():
        return int(s)
    if s in WORDS:
        return WORDS[s]
    # naive compound: twenty-one, thirty five
    parts = re.split(r"[\s-]+", s)
    total, cur = 0, 0
    for p in parts:
        if p == "hundred" and cur != 0:
            cur *= 100
        elif p in WORDS:
            cur += WORDS[p]
        else:
            return None
    return total + cur


def solve(q: str, words: bool) -> int:
    q = q.lower().replace("?", "").replace("=", "").strip()
    # Try literal integer eval first — grab tokens
    tokens = re.findall(r"[-+*/×÷]|\d+|[a-z]+", q)
    # reduce to a,op,b
    nums, op = [], None
    for t in tokens:
        if t in OPS:
            op = OPS[t]
        else:
            n = int(t) if t.isdigit() else (words_to_num(t) if words else None)
            if n is not None:
                nums.append(n)
    if len(nums) >= 2 and op:
        return op(nums[0], nums[1])
    raise ValueError(f"could not parse: {q!r}  tokens={tokens}")


def main():
    words = "--words" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--words"]
    q = args[0] if args else sys.stdin.read()
    print(solve(q, words))


if __name__ == "__main__":
    main()
