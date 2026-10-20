#!/usr/bin/env python3
"""
urlcode.py — tiny codec swiss army knife.

Subcommands pick what to do; data via arg or stdin.

usage:
  urlcode.py url      enc|dec   [data]       # URL percent-encoding
  urlcode.py urlall   enc       [data]       # encode every byte (handy for WAF bypass)
  urlcode.py html     enc|dec   [data]
  urlcode.py b64      enc|dec   [data]
  urlcode.py b64url   enc|dec   [data]       # URL-safe variant
  urlcode.py hex      enc|dec   [data]
  urlcode.py rot      <n>       [data]       # rot-N (letters only)
  urlcode.py chain    <steps>   [data]       # e.g. "b64,hex,url" applied left→right
"""
import base64, html, sys, urllib.parse


def read(args):
    return args[0] if args else sys.stdin.read().rstrip("\n")


def _run(op: str, data: str) -> str:
    cmd, _, mode = op.partition(":")
    if cmd == "url":
        return urllib.parse.quote(data, safe="") if mode == "enc" else urllib.parse.unquote(data)
    if cmd == "urlall":
        return "".join(f"%{b:02X}" for b in data.encode())
    if cmd == "html":
        return html.escape(data) if mode == "enc" else html.unescape(data)
    if cmd == "b64":
        return base64.b64encode(data.encode()).decode() if mode == "enc" else base64.b64decode(data + "=" * (-len(data) % 4)).decode(errors="replace")
    if cmd == "b64url":
        return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode() if mode == "enc" else base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode(errors="replace")
    if cmd == "hex":
        return data.encode().hex() if mode == "enc" else bytes.fromhex(data).decode(errors="replace")
    sys.exit(f"unknown step: {op}")


def rot(data: str, n: int) -> str:
    out = []
    for ch in data:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + n) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + n) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "rot":
        n = int(sys.argv[2])
        print(rot(read(sys.argv[3:]), n))
        return
    if cmd == "chain":
        steps = sys.argv[2].split(",")
        data = read(sys.argv[3:])
        for step in steps:
            # default to enc if mode omitted
            if ":" not in step:
                step = step + ":enc"
            data = _run(step, data)
        print(data)
        return
    if cmd == "urlall":
        print(_run("urlall:enc", read(sys.argv[2:]))); return
    # 2-arg form: cmd + mode
    mode = sys.argv[2]
    data = read(sys.argv[3:])
    print(_run(f"{cmd}:{mode}", data))


if __name__ == "__main__":
    main()
