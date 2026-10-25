# RSA — attack cheatsheet

Everything in `scripts/rsa-attack.py` (single-key) and `scripts/rsa-pwn.py` (multi-key/oracle), plus the math/intuition for picking the right attack.

## Decide which attack to run

Look at what you're given.

| Given | Try |
| --- | --- |
| `n, e, c` only | Fermat (close primes), factordb lookup, Wiener (small d) — `rsa-attack` |
| `e = 3` and short message | Cube root — `rsa-attack` (automatic when e=3) |
| `n` is small (< 2^300) | Factor via factordb / Pollard rho — `rsa-pwn pollard-rho` |
| `n` has smooth p-1 | Pollard p-1 — `rsa-pwn pollard-pm1` |
| Two `n` sharing a factor | GCD — `rsa-attack --n ... --n2 ...` |
| Same `n`, two `e`, two `c` | Common modulus — `rsa-pwn common-modulus` |
| Same `m`, same small `e`, N different `n` | Håstad broadcast — `rsa-pwn hastad` |
| You know `phi(n)` | Direct recovery — `rsa-pwn known-phi` |
| You know `d` | Boneh factorization — `rsa-pwn known-d` |
| Partial `d` leaked (≤ ~30 low bits) | Brute — `rsa-pwn partial-d` |
| Signing oracle refuses target | RSA blinding — `rsa-pwn blind` |
| Related messages, same key | Franklin-Reiter (needs sage, generally) |
| Partial `p` or `q` known | Coppersmith (needs sage) |
| Encrypted session with PKCS1v1.5 oracle | Bleichenbacher (long-running attack) |

If nothing above fits and you have the public key file:
```bash
RsaCtfTool --publickey key.pem --uncipherfile ciphertext.bin
```

## Fundamentals (for sanity-checking what you have)

- `n = p * q` (two large primes)
- `phi(n) = (p-1) * (q-1)`
- `e * d ≡ 1 (mod phi(n))` — public exponent + private exponent
- `c = m^e mod n` — encrypt
- `m = c^d mod n` — decrypt (requires d, which needs p and q)

RSA breaks the moment you can factor n OR learn phi OR learn d.

## Common CTF setups

### "e=3 but padded message is longer than n^(1/3)"
Standard cube-root fails. Try:
- Håstad broadcast if multiple ciphertexts available.
- Chosen-ciphertext attack if there's an oracle.

### "small e, same message to multiple recipients"
Håstad broadcast is the move:
```bash
rsa-pwn hastad --e 3 \
    --n 11111 --c 11010 \
    --n 22222 --c 22020 \
    --n 33333 --c 33030
```

### "two ciphertexts, same n, different e"
Common modulus if `gcd(e1, e2) == 1`:
```bash
rsa-pwn common-modulus --n <N> --e1 <e1> --c1 <c1> --e2 <e2> --c2 <c2>
```

### "nothing works, try factordb"
Many CTFs use primes already factored in factordb.com. `rsa-attack` queries it automatically. Online — check CTF rules.

### "p and q look close in magnitude"
Fermat factorization — iterates `a = isqrt(n) + k` until `a^2 - n` is a perfect square. `rsa-attack` runs it automatically.

### "d is tiny (<1/3 n^(1/4))"
Wiener's attack via continued fractions of `e/n`. Automated in `rsa-attack`.

### "half of d is leaked"
If low bits leaked: `rsa-pwn partial-d --bits <k>` brute-forces the high bits (practical ≤ ~30 unknown bits without Coppersmith).

If high bits leaked: Boneh-Durfee / Coppersmith — needs sage.

### "LSB oracle" (decryption oracle returns parity of plaintext)
Repeatedly multiply `c` by `2^e` and query — each response gives one bit of `m` via binary search. Not in the toolkit (needs active oracle); write a quick loop against the given endpoint.

## Reading values out of a PEM

```bash
openssl rsa -pubin -in key.pem -text -noout                 # public
openssl rsa -in private.pem -text -noout                    # private
# or extract just n and e:
openssl rsa -pubin -in key.pem -modulus -noout              # Modulus=<hex N>
```

Hex to int in Python: `int(h, 16)`. Int back to bytes: `n.to_bytes((n.bit_length()+7)//8, 'big')`.

## Message decoding pitfalls

After you recover `m` as a big integer:
```python
# Int → bytes
m_bytes = m.to_bytes((m.bit_length()+7)//8, 'big')
# Strip PKCS#1 padding if applicable (0x00 0x02 ... 0x00 payload)
if m_bytes[0:2] == b'\x00\x02':
    m_bytes = m_bytes[m_bytes.index(b'\x00', 2)+1:]
print(m_bytes)
```

## Textbook vs. real-world

Textbook RSA (no padding) is what CTF uses. Real-world RSA uses OAEP or PKCS#1v1.5 padding, which blocks most of these attacks EXCEPT:
- Bleichenbacher (PKCS#1v1.5 padding oracle)
- Timing attacks
- Key reuse flaws

## Offline reference

```bash
ls /opt/tools/crypto-attacks/                                 # scripts for RSA/ECC/etc.
rg -n 'rsa' /opt/tools/HackTricks/
RsaCtfTool --help
```

## Tips
- Always try `factordb` first — fastest win when n is already published.
- Low `e` + anything looking "deterministic" (no padding, no noise) = Håstad or chosen-ciphertext.
- `rsa-pwn pollard-pm1` ramps B1 from 1e4 → 1e5 → 1e6; stop at the first success.
- When Boneh's `known-d` fails after 100 tries, re-run — it's probabilistic, usually works within 2-3 attempts.
- CTFs with huge `n` (>2048 bits) that still want you to factor usually have a *structural* weakness: look for weird `e`, p-q distance, leaked bits.
