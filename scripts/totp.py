#!/usr/bin/env python3
"""
totp.py — generate TOTP codes (RFC 6238) when the secret has leaked.

usage:
  totp.py now       <base32-secret>              # current 6-digit code
  totp.py window    <base32-secret> [n=5]        # current ± n codes
  totp.py uri       <uri>                        # otpauth://... URI -> code
  totp.py validate  <base32-secret> <code>       # True if code is valid in ±1 step
"""
import base64, hashlib, hmac, struct, sys, time, urllib.parse


def totp(secret_b32: str, t: int | None = None, step: int = 30, digits: int = 6, alg: str = "sha1") -> str:
    key = base64.b32decode(secret_b32.replace(" ", "").upper() + "=" * (-len(secret_b32) % 8))
    if t is None:
        t = int(time.time())
    counter = struct.pack(">Q", t // step)
    h = hmac.new(key, counter, getattr(hashlib, alg)).digest()
    off = h[-1] & 0x0F
    code = (struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def parse_uri(uri: str):
    u = urllib.parse.urlparse(uri)
    q = urllib.parse.parse_qs(u.query)
    return {
        "secret": q["secret"][0],
        "digits": int(q.get("digits", ["6"])[0]),
        "period": int(q.get("period", ["30"])[0]),
        "algorithm": q.get("algorithm", ["sha1"])[0].lower(),
    }


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "now":
        print(totp(sys.argv[2]))
    elif cmd == "window":
        n = int(sys.argv[3]) if len(sys.argv) > 3 else 5
        now = int(time.time())
        for i in range(-n, n + 1):
            print(f"{i:+d}  {totp(sys.argv[2], t=now + 30 * i)}")
    elif cmd == "uri":
        p = parse_uri(sys.argv[2])
        print(totp(p["secret"], step=p["period"], digits=p["digits"], alg=p["algorithm"]))
    elif cmd == "validate":
        secret, code = sys.argv[2], sys.argv[3]
        now = int(time.time())
        ok = any(totp(secret, t=now + 30 * i) == code for i in (-1, 0, 1))
        print(ok)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
