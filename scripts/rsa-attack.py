#!/usr/bin/env python3
"""
rsa-attack.py — try the CTF-classic RSA weaknesses on a given (n, e, c).

usage:
  rsa-attack.py --n <n> --e <e> --c <c>
  rsa-attack.py --pubkey key.pem --c <c>

Attacks run (in order):
  1. e=3 cube root (unpadded short message)
  2. Fermat factorization (p, q close)
  3. factordb.com lookup (needs network)
  4. Wiener (small d)
  5. Common factor between n and a passed --n2

Does NOT do: sagemath-heavy stuff like Coppersmith, broadcast with CRT (use
RsaCtfTool for those).
"""
import argparse, math, sys, urllib.request, json


# ---------- helpers ----------
def iroot(a, b):
    s = int(round(a ** (1 / b)))
    for d in (-2, -1, 0, 1, 2):
        if (s + d) ** b == a:
            return s + d, True
    # exact nth root via newton
    hi = 1 << ((a.bit_length() + b - 1) // b)
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** b < a:
            lo = mid + 1
        else:
            hi = mid
    return lo, lo ** b == a


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m


# ---------- attacks ----------
def cube_root(c):
    m, ok = iroot(c, 3)
    return m if ok else None


def fermat(n, max_iter=1 << 20):
    a = math.isqrt(n)
    if a * a == n:
        return a, a
    for _ in range(max_iter):
        a += 1
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
    return None


def factordb(n):
    try:
        r = urllib.request.urlopen(f"http://factordb.com/api?query={n}", timeout=5).read()
        j = json.loads(r)
        if j.get("status") in ("FF", "P", "CF") and len(j["factors"]) >= 2:
            factors = []
            for f, cnt in j["factors"]:
                factors += [int(f)] * cnt
            if len(factors) == 2:
                return factors[0], factors[1]
    except Exception as e:
        print(f"  (factordb: {e})")
    return None


def wiener(e, n):
    # continued fraction of e/n → convergents (k/d). Test each d.
    cf = []
    a, b = e, n
    while b:
        cf.append(a // b)
        a, b = b, a % b
    h0, h1 = 0, 1
    k0, k1 = 1, 0
    for q in cf:
        hn, kn = q * h1 + h0, q * k1 + k0
        h0, h1 = h1, hn
        k0, k1 = k1, kn
        if kn == 0:
            continue
        k, d = hn, kn
        if k and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1
            disc = s * s - 4 * n
            if disc >= 0:
                sq = math.isqrt(disc)
                if sq * sq == disc and (s + sq) % 2 == 0:
                    return (s + sq) // 2, (s - sq) // 2
    return None


def common_factor(n1, n2):
    g = math.gcd(n1, n2)
    return g if 1 < g < n1 else None


def decrypt(c, n, p, q, e):
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return pow(c, d, n)


def int_to_bytes(m):
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, "big")


# ---------- cli ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int)
    ap.add_argument("--e", type=int, default=65537)
    ap.add_argument("--c", type=int)
    ap.add_argument("--pubkey", help="PEM public key")
    ap.add_argument("--n2", type=int, help="second modulus for common-factor attack")
    args = ap.parse_args()

    if args.pubkey:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        k = load_pem_public_key(open(args.pubkey, "rb").read())
        nums = k.public_numbers()
        args.n, args.e = nums.n, nums.e

    n, e, c = args.n, args.e, args.c
    if not (n and e):
        sys.exit("need --n and --e (or --pubkey)")

    print(f"n ({n.bit_length()} bits), e={e}")

    if e == 3 and c:
        print("[*] e=3 cube root")
        m = cube_root(c)
        if m:
            print(f"  m = {m}")
            try: print(f"  bytes: {int_to_bytes(m)!r}")
            except Exception: pass

    print("[*] Fermat")
    f = fermat(n)
    if f:
        p, q = f
        print(f"  p = {p}\n  q = {q}")
        if c:
            m = decrypt(c, n, p, q, e)
            print(f"  m bytes: {int_to_bytes(m)!r}")
        return

    print("[*] factordb")
    f = factordb(n)
    if f:
        p, q = f
        print(f"  p = {p}\n  q = {q}")
        if c:
            m = decrypt(c, n, p, q, e)
            print(f"  m bytes: {int_to_bytes(m)!r}")
        return

    print("[*] Wiener")
    f = wiener(e, n)
    if f:
        p, q = f
        print(f"  p = {p}\n  q = {q}")
        if c:
            m = decrypt(c, n, p, q, e)
            print(f"  m bytes: {int_to_bytes(m)!r}")
        return

    if args.n2:
        print("[*] common factor with --n2")
        g = common_factor(n, args.n2)
        if g:
            p, q = g, n // g
            print(f"  gcd = {g}")
            if c:
                m = decrypt(c, n, p, q, e)
                print(f"  m bytes: {int_to_bytes(m)!r}")
            return

    print("[-] no easy attack worked — try RsaCtfTool or inspect manually.")


if __name__ == "__main__":
    main()
