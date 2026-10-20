# Crypto & Hash Cracking

Common tools: hashcat, John the Ripper (jumbo), hashid,
RsaCtfTool, SageMath, PARI/GP, OpenSSL, bkcrack, factordb-python (library),
crypto-attacks (/opt/tools/crypto-attacks), padding-oracle-attacker,
Didier Stevens suite. **CrackStation and other online crackers are banned.**

## Identify hash

| Length | Charset | Likely |
|---|---|---|
| 32 | hex | MD5 |
| 40 | hex | SHA1 |
| 56 | hex | SHA224 |
| 64 | hex | SHA256 |
| 96 | hex | SHA384 |
| 128 | hex | SHA512 |
| starts `$2a$`, `$2b$` | base64 | bcrypt |
| starts `$1$` | base64 | md5crypt |
| starts `$5$` | base64 | sha256crypt |
| starts `$6$` | base64 | sha512crypt |
| starts `$argon2` | base64 | argon2 |
| starts `$y$`, `$7$` | base64 | yescrypt |
| 16 hex | hex | MySQL<4 or LM |
| 41 chars, `*ABC...` | hex | MySQL5 |
| ends `=`, len ~24 | b64 | NTLM-b64, or raw bytes |

Try `hash-id.py` (in `scripts/`) or `hashid some_hash`.

## Hashcat modes (common)

```
0     MD5
100   SHA1
1400  SHA256
1700  SHA512
1000  NTLM
3000  LM
3200  bcrypt
1800  sha512crypt ($6$)
500   md5crypt    ($1$)
16500 JWT (HS256/384/512)
22000 WPA-PBKDF2-PMKID+EAPOL
10000 Django PBKDF2 SHA256
900   MD4
```

```bash
hashcat -a 0 -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -a 3 -m 0 hash '?d?d?d?d?d?d'                 # 6-digit numeric brute
hashcat -a 0 -m 0 hashes.txt rockyou.txt -r rules/best64.rule
```

## John

```bash
john --wordlist=rockyou.txt --format=raw-md5 hashes.txt
john --show --format=raw-md5 hashes.txt

# Common converters:
zip2john archive.zip > zip.hash
rar2john archive.rar > rar.hash
pdf2john.pl file.pdf > pdf.hash
ssh2john id_rsa > ssh.hash
keepass2john kdbx > kp.hash
```

## Classical ciphers

| Signal | Try |
|---|---|
| Only A-Z, same length as plaintext | Caesar (`scripts/caesar.py`), Vigenère |
| Pairs, no J | Playfair |
| 5x5 grid feel | ADFGVX, Polybius |
| `-.-` style | Morse |
| Only 2 chars (A/B) | Baconian |
| Mix of letters+digits ending `=` | Base64 |
| All hex | hex → ASCII |
| ASCII art of brackets | Brainfuck |
| `><` symbols | Ook/Brainfuck |
| Looks like `U2FsdGVkX1...` | OpenSSL AES CBC |

Quick base checks:
```bash
echo "$x" | base64 -d
echo "$x" | base32 -d
echo "$x" | xxd -r -p
```

## RSA attacks (CTF favorites)

| Signal | Attack |
|---|---|
| `e = 3` and `m^3 < n` | Cube root of `c` |
| Small `n` (<~500 bits) | Factor with the `factordb-python` library (approved) or SageMath |
| Shared `n` between keys | Common modulus |
| Close primes `p` and `q` | Fermat factorization |
| Small `d` | Wiener's attack |
| Many messages, same `e` | Håstad's broadcast |
| `n = p*q` with p|q bits leaked | Coppersmith |

Tools (-approved): `RsaCtfTool`, `SageMath`, `PARI/GP`, `/opt/tools/crypto-attacks` for scripted attacks.

## XOR

Single-byte XOR (frequency analysis):
```python
cands = []
for k in range(256):
    pt = bytes(b^k for b in ct)
    score = sum(32 <= b < 127 for b in pt)
    cands.append((score,k,pt))
cands.sort(reverse=True)
```

Repeating-key XOR: find key length by hamming-distance / IC, then split into single-byte XORs. See `scripts/xor-crack.py` (stdlib only).

## Zip password cracking

```bash
# ZipCrypto with known plaintext -> bkcrack (approved)
bkcrack -C encrypted.zip -c some_file -p known_plaintext_bytes

# AES zip or no plaintext -> brute with hashcat / john
zip2john target.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
hashcat -m 13600 zip.hash /usr/share/wordlists/rockyou.txt
```

## Padding oracle

```bash
padding-oracle-attacker encrypt <url> <ciphertext>
# or (/opt/tools/padding-oracle-attacker)
```
