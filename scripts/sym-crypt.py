#!/usr/bin/env python3
"""
sym-crypt.py — decrypt (or encrypt) symmetric ciphers that take a key + IV/nonce.

Covers:
  AES-ECB, AES-CBC, AES-CFB, AES-OFB, AES-CTR, AES-GCM
  3DES-ECB, 3DES-CBC
  ChaCha20, ChaCha20-Poly1305
  Blowfish-CBC

Depends on `cryptography` (pure Python crypto lib, no AI/ML). If missing:
    uv pip install cryptography     # or pip install --user cryptography

Inputs accept hex or base64 for key / iv / data / tag. Flags choose encoding.

usage:
  # Decrypt AES-CBC
  sym-crypt.py dec aes-cbc --key-hex 00112233... --iv-hex deadbeef... --data-b64 'AAAA...'

  # Decrypt AES-GCM (needs tag)
  sym-crypt.py dec aes-gcm --key-hex ... --iv-hex ... --tag-hex ... --data-hex ... [--aad-hex ...]

  # Decrypt AES-CTR (iv = initial counter block)
  sym-crypt.py dec aes-ctr --key-hex ... --iv-hex ... --data-hex ...

  # ChaCha20 (nonce is 16 bytes = 4-byte counter + 12-byte nonce for cryptography lib)
  sym-crypt.py dec chacha20 --key-hex ... --nonce-hex ... --data-hex ...

  # Encrypt (same flags, 'enc' instead of 'dec')
  sym-crypt.py enc aes-cbc --key-hex ... --iv-hex ... --data 'plaintext' --pkcs7

List modes:
  sym-crypt.py --list

Output: hex by default; add --out-utf8 to try utf-8, or --out-b64 for base64.
"""
import argparse, base64, sys


def dec(s: str, encoding: str) -> bytes:
    if s is None: return b""
    s = s.strip()
    if encoding == "hex":   return bytes.fromhex(s)
    if encoding == "b64":   return base64.b64decode(s + "=" * (-len(s) % 4))
    if encoding == "utf8":  return s.encode()
    raise ValueError(f"bad encoding {encoding}")


def enc(b: bytes, encoding: str) -> str:
    if encoding == "hex":  return b.hex()
    if encoding == "b64":  return base64.b64encode(b).decode()
    if encoding == "utf8":
        try: return b.decode()
        except UnicodeDecodeError: return b.decode(errors="replace") + "  (not valid utf-8)"
    raise ValueError(encoding)


def read_input(args, name: str) -> bytes:
    for enc_name in ("hex", "b64"):
        v = getattr(args, f"{name}_{enc_name}", None)
        if v: return dec(v, "hex" if enc_name == "hex" else "b64")
    v = getattr(args, name, None)
    if v is not None: return v.encode()
    return b""


def pkcs7_pad(b: bytes, blocksize: int) -> bytes:
    pad = blocksize - (len(b) % blocksize)
    return b + bytes([pad]) * pad


def pkcs7_unpad(b: bytes) -> bytes:
    if not b: return b
    pad = b[-1]
    if pad < 1 or pad > 16 or b[-pad:] != bytes([pad]) * pad:
        return b  # not padded, return as-is
    return b[:-pad]


# ---------- modes ----------
def do_aes(mode: str, action: str, args) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key  = read_input(args, "key")
    data = read_input(args, "data")

    if mode == "aes-ecb":
        c = Cipher(algorithms.AES(key), modes.ECB())
    elif mode == "aes-cbc":
        iv = read_input(args, "iv")
        c = Cipher(algorithms.AES(key), modes.CBC(iv))
    elif mode == "aes-cfb":
        iv = read_input(args, "iv")
        c = Cipher(algorithms.AES(key), modes.CFB(iv))
    elif mode == "aes-ofb":
        iv = read_input(args, "iv")
        c = Cipher(algorithms.AES(key), modes.OFB(iv))
    elif mode == "aes-ctr":
        iv = read_input(args, "iv")
        c = Cipher(algorithms.AES(key), modes.CTR(iv))
    elif mode == "aes-gcm":
        iv  = read_input(args, "iv")
        aad = read_input(args, "aad")
        tag = read_input(args, "tag")
        g = AESGCM(key)
        if action == "dec":
            return g.decrypt(iv, data + tag, aad or None)
        else:
            ct = g.encrypt(iv, data, aad or None)
            # ct is ciphertext || tag(16)
            return ct
    else:
        raise ValueError(mode)

    if action == "dec":
        pt = c.decryptor().update(data) + c.decryptor().finalize()
        if args.pkcs7: pt = pkcs7_unpad(pt)
        return pt
    else:
        if args.pkcs7:
            data = pkcs7_pad(data, 16)
        return c.encryptor().update(data) + c.encryptor().finalize()


def do_3des(mode: str, action: str, args) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key  = read_input(args, "key")
    data = read_input(args, "data")
    if mode == "3des-ecb":
        c = Cipher(algorithms.TripleDES(key), modes.ECB())
    elif mode == "3des-cbc":
        iv = read_input(args, "iv")
        c = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    else:
        raise ValueError(mode)
    if action == "dec":
        pt = c.decryptor().update(data) + c.decryptor().finalize()
        if args.pkcs7: pt = pkcs7_unpad(pt)
        return pt
    if args.pkcs7:
        data = pkcs7_pad(data, 8)
    return c.encryptor().update(data) + c.encryptor().finalize()


def do_chacha20(mode: str, action: str, args) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    key = read_input(args, "key")
    data = read_input(args, "data")
    if mode == "chacha20":
        nonce = read_input(args, "nonce") or read_input(args, "iv")
        if len(nonce) != 16:
            # cryptography's ChaCha20 uses a 16-byte 'nonce' = 4-byte counter || 12-byte real nonce
            nonce = (b"\x00" * (16 - len(nonce))) + nonce
        c = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        if action == "dec":
            return c.decryptor().update(data)
        return c.encryptor().update(data)
    elif mode == "chacha20-poly1305":
        nonce = read_input(args, "nonce") or read_input(args, "iv")
        aad   = read_input(args, "aad")
        tag   = read_input(args, "tag")
        cp = ChaCha20Poly1305(key)
        if action == "dec":
            return cp.decrypt(nonce, data + tag, aad or None)
        return cp.encrypt(nonce, data, aad or None)
    raise ValueError(mode)


def do_blowfish(mode: str, action: str, args) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = read_input(args, "key")
    data = read_input(args, "data")
    if mode == "blowfish-cbc":
        iv = read_input(args, "iv")
        c = Cipher(algorithms.Blowfish(key), modes.CBC(iv))
    elif mode == "blowfish-ecb":
        c = Cipher(algorithms.Blowfish(key), modes.ECB())
    else:
        raise ValueError(mode)
    if action == "dec":
        pt = c.decryptor().update(data) + c.decryptor().finalize()
        if args.pkcs7: pt = pkcs7_unpad(pt)
        return pt
    if args.pkcs7:
        data = pkcs7_pad(data, 8)
    return c.encryptor().update(data) + c.encryptor().finalize()


MODES = {
    "aes-ecb":            do_aes,
    "aes-cbc":            do_aes,
    "aes-cfb":            do_aes,
    "aes-ofb":            do_aes,
    "aes-ctr":            do_aes,
    "aes-gcm":            do_aes,
    "3des-ecb":           do_3des,
    "3des-cbc":           do_3des,
    "chacha20":           do_chacha20,
    "chacha20-poly1305":  do_chacha20,
    "blowfish-cbc":       do_blowfish,
    "blowfish-ecb":       do_blowfish,
}


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("action", nargs="?", choices=("enc", "dec"))
    ap.add_argument("mode",   nargs="?")
    for name in ("key", "iv", "nonce", "data", "aad", "tag"):
        ap.add_argument(f"--{name}")
        ap.add_argument(f"--{name}-hex")
        ap.add_argument(f"--{name}-b64")
    ap.add_argument("--pkcs7", action="store_true", help="apply/strip PKCS#7 padding (CBC/ECB)")
    ap.add_argument("--out-hex",  action="store_true")
    ap.add_argument("--out-b64",  action="store_true")
    ap.add_argument("--out-utf8", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("-h", "--help", action="store_true")
    args = ap.parse_args()

    if args.help or (not args.action and not args.list):
        print(__doc__); return
    if args.list:
        for m in MODES: print(m)
        return

    if args.mode not in MODES: sys.exit(f"unknown mode: {args.mode}  (see --list)")
    try:
        out = MODES[args.mode](args.mode, args.action, args)
    except Exception as e:
        sys.exit(f"error: {type(e).__name__}: {e}")

    if args.out_utf8:   print(enc(out, "utf8"))
    elif args.out_b64:  print(enc(out, "b64"))
    else:               print(enc(out, "hex"))


if __name__ == "__main__":
    main()
