#!/usr/bin/env python3
"""rsa-pwn.py — multi-key / oracle / smooth-prime RSA attacks. Stdlib only.

Complements rsa-attack.py (which handles single-key: e=3, Fermat, Wiener,
factordb, common-factor-between-two-N). This script covers:

  common-modulus      Two ciphertexts, same N, different e → recover m via
                      extended Euclidean (no factoring needed).

  hastad              Håstad broadcast: N ciphertexts of same plaintext, same
                      small e, N different moduli → CRT then eth-root.

  pollard-pm1         Pollard p-1 for N with a smooth prime factor.
                      Tries B1=1e4, 1e5, 1e6 by default.

  pollard-rho         Pollard rho for small-factor N. Fast for factors ≲ 2**40.

  known-phi           Given (n, phi), recover (p, q) and then d.

  known-d             Given (n, e, d), recover (p, q).

  partial-d           Given (n, e, d_low) where d_low is the lower k bits of d,
                      recover full d by brute (practical when leaked bits ≤ ~30).

  blind               RSA blinding attack: given signing oracle for arbitrary
                      m and target m*, forge sig(m*) using sig(r*m*) / r.
                      (Illustrates the math — needs real oracle to execute.)

usage examples (see --list for all):
  rsa-pwn common-modulus --n <N> --e1 <e1> --c1 <c1> --e2 <e2> --c2 <c2>
  rsa-pwn hastad --e 3 --n 11111 --c 11010 --n 22222 --c 22020 --n 33333 --c 33030
  rsa-pwn pollard-pm1 --n <N> [--B1 1000000]
  rsa-pwn pollard-rho --n <N>
  rsa-pwn known-phi --n <N> --phi <phi>
  rsa-pwn known-d --n <N> --e <e> --d <d>
"""
import argparse, math, random, sys
from functools import reduce


# ---------- number helpers ----------
def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"no modular inverse (gcd={g})")
    return x % m


def iroot(a, b):
    """Integer b-th root of a. Returns (root, exact?)."""
    if a < 0:
        raise ValueError("negative")
    if a == 0:
        return 0, True
    hi = 1 << ((a.bit_length() + b - 1) // b)
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** b < a:
            lo = mid + 1
        else:
            hi = mid
    return lo, lo ** b == a


def crt(residues, moduli):
    """Chinese remainder theorem. Return x s.t. x ≡ r_i mod m_i for all i."""
    M = reduce(lambda a, b: a * b, moduli)
    x = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        x = (x + r * Mi * modinv(Mi, m)) % M
    return x


def int_to_bytes(n):
    if n == 0:
        return b""
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


# ---------- attacks ----------
def common_modulus(n, e1, c1, e2, c2):
    g, s, t = egcd(e1, e2)
    if g != 1:
        raise ValueError(f"gcd(e1, e2) = {g} ≠ 1, common-modulus doesn't apply directly")
    if s < 0:
        c1 = modinv(c1, n); s = -s
    if t < 0:
        c2 = modinv(c2, n); t = -t
    m = (pow(c1, s, n) * pow(c2, t, n)) % n
    return m


def hastad(e, ciphertexts, moduli):
    """N = e ciphertexts/moduli of same plaintext m, m < min(moduli). Returns m."""
    if len(ciphertexts) < e:
        raise ValueError(f"need ≥ {e} (c, n) pairs for e={e}")
    me = crt(ciphertexts[:e], moduli[:e])
    m, exact = iroot(me, e)
    if not exact:
        raise ValueError("eth root not exact — m is longer than smallest modulus, or wrong e")
    return m


def pollard_pm1(n, B1=1000000):
    """Pollard p-1: works when a prime factor p of n has p-1 B1-smooth."""
    a = 2
    for b in range(2, B1 + 1):
        a = pow(a, b, n)
        if b & (b - 1) == 0 or b % 1000 == 0:  # periodic gcd check
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                return g, n // g
    g = math.gcd(a - 1, n)
    if 1 < g < n:
        return g, n // g
    return None


def pollard_rho(n):
    """Pollard rho; fast for small factors."""
    if n % 2 == 0:
        return 2, n // 2
    while True:
        x = random.randint(2, n - 2)
        y = x
        c = random.randint(1, n - 2)
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d, n // d


def known_phi(n, phi):
    """Given n = pq and phi = (p-1)(q-1), recover p, q."""
    # p + q = n - phi + 1
    s = n - phi + 1
    disc = s * s - 4 * n
    if disc < 0:
        raise ValueError("phi inconsistent with n")
    sq, exact = iroot(disc, 2)
    if not exact:
        raise ValueError("discriminant not a perfect square — bad phi?")
    p = (s + sq) // 2
    q = (s - sq) // 2
    if p * q != n:
        raise ValueError("recovered p*q != n")
    return p, q


def known_d(n, e, d):
    """Boneh's attack: given (n, e, d), probabilistically recover p, q.
    See https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf §4."""
    k = e * d - 1
    # k = 2^t * r with r odd
    t = 0
    r = k
    while r & 1 == 0:
        r //= 2; t += 1
    for _ in range(100):
        g = random.randint(2, n - 1)
        y = pow(g, r, n)
        if y == 1 or y == n - 1:
            continue
        for _ in range(t):
            x = pow(y, 2, n)
            if x == 1:
                p = math.gcd(y - 1, n)
                if 1 < p < n:
                    return p, n // p
                break
            if x == n - 1:
                break
            y = x
    raise ValueError("failed after 100 tries — try again with different seed")


def partial_d(n, e, d_low, bits_known):
    """Given lower `bits_known` bits of d, bruteforce the rest (practical ≤ ~30 bits)."""
    # d = d_high * 2^bits_known + d_low  with d ≈ bit_length of n
    nbits = n.bit_length()
    mask = (1 << bits_known) - 1
    if d_low & ~mask:
        d_low &= mask
    # d*e ≡ 1 mod phi, phi ≈ n, so d_high ≈ (n // 2^bits_known)
    # Rather than smart Coppersmith (needs sage), brute d_high over a window:
    guess_range = 1 << min(nbits - bits_known, 24)   # cap at 2**24 ≈ 16M
    for i in range(guess_range):
        d_guess = (i << bits_known) | d_low
        # cheap sanity: pow(2, e*d_guess - 1, n) == 1 means guess is consistent
        if pow(2, e * d_guess - 1, n) == 1:
            return d_guess
    raise ValueError("not found in brute window — bits_known too few")


def blind_attack_math(n, e, m_target):
    """RSA blinding: sign m* via oracle that will sign anything except m*.
    Returns the pair (r, blinded_msg) you'd send to the oracle, then
    sig(m*) = oracle_sig / r mod n."""
    r = random.randint(2, n - 1)
    while math.gcd(r, n) != 1:
        r = random.randint(2, n - 1)
    blinded = (m_target * pow(r, e, n)) % n
    return r, blinded


# ---------- cli dispatch ----------
def _int(s):
    s = s.strip()
    if s.startswith("0x"): return int(s, 16)
    return int(s)


def cmd_common_modulus(a):
    m = common_modulus(_int(a.n), _int(a.e1), _int(a.c1), _int(a.e2), _int(a.c2))
    print(f"m = {m}")
    print(f"  bytes: {int_to_bytes(m)!r}")


def cmd_hastad(a):
    ns = [_int(x) for x in a.n]
    cs = [_int(x) for x in a.c]
    m = hastad(_int(a.e), cs, ns)
    print(f"m = {m}")
    print(f"  bytes: {int_to_bytes(m)!r}")


def cmd_pollard_pm1(a):
    for B1 in ([_int(a.B1)] if a.B1 else [10_000, 100_000, 1_000_000]):
        print(f"[*] trying B1 = {B1}")
        r = pollard_pm1(_int(a.n), B1)
        if r:
            p, q = r
            print(f"p = {p}\nq = {q}")
            if a.e and a.c:
                m = _decrypt(_int(a.n), _int(a.e), _int(a.c), p, q)
                print(f"m bytes: {int_to_bytes(m)!r}")
            return
    print("no small-factor found")


def cmd_pollard_rho(a):
    p, q = pollard_rho(_int(a.n))
    print(f"factor 1 = {p}\nfactor 2 = {q}")


def cmd_known_phi(a):
    p, q = known_phi(_int(a.n), _int(a.phi))
    print(f"p = {p}\nq = {q}")
    if a.e and a.c:
        m = _decrypt(_int(a.n), _int(a.e), _int(a.c), p, q)
        print(f"m bytes: {int_to_bytes(m)!r}")


def cmd_known_d(a):
    p, q = known_d(_int(a.n), _int(a.e), _int(a.d))
    print(f"p = {p}\nq = {q}")
    if a.c:
        m = _decrypt(_int(a.n), _int(a.e), _int(a.c), p, q)
        print(f"m bytes: {int_to_bytes(m)!r}")


def cmd_partial_d(a):
    d = partial_d(_int(a.n), _int(a.e), _int(a.d_low), int(a.bits))
    print(f"d = {d}")


def cmd_blind(a):
    r, blinded = blind_attack_math(_int(a.n), _int(a.e), _int(a.m))
    print(f"blinding r = {r}")
    print(f"send to signing oracle: {blinded}")
    print(f"then: sig(m_target) = oracle_sig * modinv(r, n) mod n")


def _decrypt(n, e, c, p, q):
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return pow(c, d, n)


def main():
    ap = argparse.ArgumentParser(add_help=False)
    sub = ap.add_subparsers(dest="cmd")

    def add_cmd(name, fn, **flags):
        p = sub.add_parser(name)
        for flag, kw in flags.items():
            if isinstance(kw, dict) and kw.get("multi"):
                p.add_argument(f"--{flag}", action="append", required=kw.get("required", False))
            else:
                p.add_argument(f"--{flag}", required=kw)
        p.set_defaults(func=fn)

    add_cmd("common-modulus", cmd_common_modulus, n=True, e1=True, c1=True, e2=True, c2=True)
    add_cmd("hastad",         cmd_hastad,
            e=True, n={"multi": True, "required": True}, c={"multi": True, "required": True})
    add_cmd("pollard-pm1",    cmd_pollard_pm1, n=True, B1=False, e=False, c=False)
    add_cmd("pollard-rho",    cmd_pollard_rho, n=True)
    add_cmd("known-phi",      cmd_known_phi,   n=True, phi=True, e=False, c=False)
    add_cmd("known-d",        cmd_known_d,     n=True, e=True, d=True, c=False)
    add_cmd("partial-d",      cmd_partial_d,   n=True, e=True, d_low=True, bits=True)
    add_cmd("blind",          cmd_blind,       n=True, e=True, m=True)

    ap.add_argument("--list", action="store_true")
    ap.add_argument("-h", "--help", action="store_true")
    a = ap.parse_args()

    if a.list:
        print("attacks: common-modulus, hastad, pollard-pm1, pollard-rho,")
        print("         known-phi, known-d, partial-d, blind")
        return
    if a.help or not a.cmd:
        print(__doc__); return

    a.func(a)


if __name__ == "__main__":
    main()
