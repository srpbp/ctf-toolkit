#!/usr/bin/env python3
"""
hash-id.py — guess hash type from a string.

usage: hash-id.py '<hash>'
       echo '<hash>' | hash-id.py -
"""
import re, sys


RULES = [
    # (regex, name, hashcat mode, john format)
    (r"^[a-f0-9]{32}$",                      "MD5 / NTLM / MD4 / LM(x2)", "0 / 1000 / 900 / 3000", "raw-md5 / nt / raw-md4 / lm"),
    (r"^[A-F0-9]{32}$",                      "MD5 (upper) / NTLM",         "0 / 1000",             "raw-md5 / nt"),
    (r"^[a-f0-9]{16}$",                      "MySQL<=4 / LM half / DES",   "200 / 3000",           "mysql / lm"),
    (r"^\*[A-F0-9]{40}$",                    "MySQL 4.1+",                 "300",                   "mysql-sha1"),
    (r"^[a-f0-9]{40}$",                      "SHA1 / RIPEMD-160",          "100 / 6000",            "raw-sha1 / ripemd-160"),
    (r"^[a-f0-9]{56}$",                      "SHA224",                     "1300",                  "raw-sha224"),
    (r"^[a-f0-9]{64}$",                      "SHA256 / SHA3-256 / Keccak", "1400 / 17400",          "raw-sha256"),
    (r"^[a-f0-9]{96}$",                      "SHA384",                     "10800",                 "raw-sha384"),
    (r"^[a-f0-9]{128}$",                     "SHA512 / Whirlpool",         "1700 / 6100",           "raw-sha512 / whirlpool"),
    (r"^\$1\$[^$]{1,8}\$[./0-9A-Za-z]{22}$", "md5crypt",                   "500",                   "md5crypt"),
    (r"^\$2[aby]\$\d{2}\$[./0-9A-Za-z]{53}$","bcrypt",                     "3200",                  "bcrypt"),
    (r"^\$5\$",                              "sha256crypt",                "7400",                  "sha256crypt"),
    (r"^\$6\$",                              "sha512crypt",                "1800",                  "sha512crypt"),
    (r"^\$y\$",                              "yescrypt",                   "— (john only)",         "yescrypt"),
    (r"^\$argon2(i|id|d)\$",                 "Argon2",                     "— (john only)",         "argon2"),
    (r"^\$pbkdf2-sha256",                    "PBKDF2-SHA256 (passlib)",    "10900",                 "pbkdf2-sha256"),
    (r"^pbkdf2_sha256\$",                    "Django PBKDF2-SHA256",       "10000",                 "django"),
    (r"^sha1\$",                             "Django SHA1",                "124",                   "django"),
    (r"^[A-Z0-9]{32}:[a-f0-9]{32}$",         "NetNTLMv1-ish",              "5500",                  "netntlm"),
    (r"^.{32,}::\w+:\w+:[a-f0-9]+:[a-f0-9]+$", "NetNTLMv2",                "5600",                  "netntlmv2"),
    (r"^\$DCC2\$10240#",                     "DCC2 (mscash2)",             "2100",                  "mscash2"),
    (r"^0x0100[A-F0-9]{48,}$",               "MSSQL 2000",                 "131",                   "mssql"),
    (r"^0x0200[A-F0-9]{72,}$",               "MSSQL 2012/2014",            "1731",                  "mssql12"),
    (r"^[A-Fa-f0-9]{48}$",                   "SHA384 half / Haval / etc",  "— depends",             "—"),
    (r"^[A-Za-z0-9+/=]{24}$",                "base64(16 bytes) — maybe NTLM-b64 or raw",  "—",     "—"),
    (r"^[A-Za-z0-9+/=]{44}$",                "base64(32 bytes) — maybe SHA256 raw",       "—",     "—"),
    (r"^\$P\$|^\$H\$",                       "phpass",                     "400",                   "phpass"),
    (r"^\$apr1\$",                           "Apache md5",                 "1600",                  "md5crypt-a"),
    (r"^SCRYPT:",                            "scrypt",                     "8900",                  "scrypt"),
]


def guess(h: str):
    print(f"input ({len(h)} chars): {h[:80]}{'…' if len(h) > 80 else ''}")
    hits = []
    for rx, name, mode, jformat in RULES:
        if re.match(rx, h):
            hits.append((name, mode, jformat))
    if not hits:
        print("no match — try hashid, hash-identifier, or search by length/charset.")
        return
    print(f"\n{len(hits)} match(es):")
    for n, m, j in hits:
        print(f"  {n}")
        print(f"    hashcat: {m}")
        print(f"    john   : {j}")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    arg = sys.argv[1]
    h = sys.stdin.read().strip() if arg == "-" else arg.strip()
    guess(h)


if __name__ == "__main__":
    main()
