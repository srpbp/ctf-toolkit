# AES — attack cheatsheet

## When each attack applies

| Mode | Classic flaw | Attack |
| --- | --- | --- |
| **ECB** | Identical plaintext blocks → identical ciphertext blocks | ECB penguin, chosen-plaintext oracle byte-at-a-time |
| **CBC** | Deterministic IV; bit-flip in `C_{i-1}` flips bit in `P_i`; padding error reveal | Bit-flipping, padding oracle (CVE class) |
| **CBC + MAC-less** | Attacker can mangle ciphertext without detection | Any CBC attack above |
| **CTR / stream** | Keystream reuse (same key + nonce for different messages) | Two-time pad: XOR two ciphertexts, crib-drag |
| **CFB / OFB** | Same as CTR when nonces reused | Keystream recovery |
| **GCM** | Nonce reuse disaster; truncated tag | Forbidden-attack / Joux (nonce reuse) |

For the mechanical decrypt once you have key + IV, use `sym-crypt`:
```bash
sym-crypt dec aes-cbc --key-hex ... --iv-hex ... --data-hex ... --pkcs7 --out-utf8
sym-crypt dec aes-gcm --key-hex ... --iv-hex ... --data-hex ... --tag-hex ... --out-utf8
sym-crypt --list
```

## ECB penguin / block pattern

Classic giveaway: identical 16-byte blocks of plaintext repeat as identical 16-byte blocks of ciphertext.

Detect:
```python
def ecb_detect(ct):
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    return len(blocks) != len(set(blocks))
```

Exploit (byte-at-a-time ECB decryption when a secret is appended to attacker input):
```python
# target: AES_ECB(attacker_input || SECRET, key)
# strategy: feed 15 bytes of 'A', the 16th position holds the first byte of SECRET.
# Enumerate all 256 bytes for the 16th position, find the match → first byte known.
# Repeat with 14 bytes of A + known_byte + 1 unknown_byte, etc.
```

## CBC bit-flipping

Flipping bit `x` of `C_{i-1}` flips the same bit `x` of `P_i` (while garbling `P_{i-1}` to random).

Example: flip `isAdmin=0` to `isAdmin=1` without knowing the key:
```python
#  P_i = AES_dec(C_i) XOR C_{i-1}
# want: new_P_i[k] = old_P_i[k] XOR 1
# set: new_C_{i-1}[k] = old_C_{i-1}[k] XOR 1
# Trade-off: P_{i-1} becomes random — hope the app doesn't care.
```

## Padding oracle (CBC)

Any oracle that distinguishes "bad padding" from "valid padding but bad plaintext" lets you decrypt arbitrary ciphertexts and encrypt forgeries.

Toolkit: `padding-oracle-attacker` (approved per TOOLS).
```bash
# install via pipx on Kali VM
pipx install padding-oracle-attacker
poattack decrypt 'http://target/decode?ct=' --iv-included
```

## CTR / stream cipher two-time pad

Two ciphertexts under the same key+nonce:
```
C1 XOR C2 = P1 XOR P2
```

If you know (or guess) part of P1, you learn the same part of P2 via XOR crib-dragging. Automated:
```bash
cipher-id --cipher xor-single '<C1 XOR C2 in hex>'
```

Or hand-crib: look for repeating "the ", space, common bigrams.

## GCM nonce reuse

If two messages encrypt under same (key, nonce):
```
C1 XOR C2 = P1 XOR P2     # same as CTR two-time pad for the body
```

The authentication tag is also compromised (recover the hash subkey H via polynomial math) — can forge valid messages. See Joux's forbidden-attack paper.

## Key recovery from CTR nonce reuse (specific CTF trick)

CTR mode uses `AES(K, nonce || counter) XOR plaintext`. If the counter is fixed (not incremented) across many blocks of the SAME message, every block uses the same keystream = ECB-style weakness within a single message.

## Bleichenbacher (PKCS#1v1.5 — technically RSA but same oracle logic)

If a TLS-style server returns different responses for "valid PKCS#1" vs "invalid", you can decrypt arbitrary RSA ciphertexts via millions of queries. Rarely practical in CTF without rate limits lifted.

## Key stretching / KDF

CTF password-based keys often use:
- `PBKDF2(password, salt, iters)` with weak iterations → crack password with hashcat `-m 10900` (PBKDF2-SHA256).
- `scrypt` → `-m 8900`.
- Argon2 → john only (`argon2` format).

Once you have the password, re-derive the key with the KDF parameters, then `sym-crypt dec`.

## OpenSSL `aes-256-cbc` with password (classic CTF prompt)

If the ciphertext starts with `Salted__` (bytes `53 61 6c 74 65 64 5f 5f`), it's OpenSSL password-derived:
```bash
openssl enc -d -aes-256-cbc -in ct.bin -out pt.bin -pass pass:'<password>' -pbkdf2
# fallback for ancient MD5 derivation (OpenSSL <1.1.0):
openssl enc -d -aes-256-cbc -in ct.bin -out pt.bin -pass pass:'<password>' -md md5
```

Brute passwords:
```bash
while read -r p; do
  openssl enc -d -aes-256-cbc -in ct.bin -pass pass:"$p" -pbkdf2 2>/dev/null | file - | grep -q 'ASCII text' && echo "HIT: $p" && break
done < /usr/share/wordlists/rockyou.txt
```

## Reading key material

PEM/DER-encoded symmetric keys are rare; usually keys are given as hex / base64 in CTF prompts. Convert with the tool:
```bash
sym-crypt dec aes-cbc --key-hex ... --iv-hex ...
sym-crypt dec aes-cbc --key-b64 ... --iv-b64 ... --data-b64 ...
```

## Offline reference

```bash
ls /opt/tools/crypto-attacks/
rg -n 'aes|cbc|ctr|gcm' /opt/tools/HackTricks/
rg -n 'padding oracle' /opt/tools/PayloadsAllTheThings/
```

## Tips
- ECB penguin: visually obvious on images; programmatically obvious as duplicate 16-byte block sets.
- `Salted__` prefix → OpenSSL password-based → brute with rockyou.
- GCM is "safe" ONLY if the nonce never repeats. CTF challenges deliberately reuse nonces.
- CTR + fixed nonce + two messages = two-time pad every time. Classic cryptopals challenge.
- When you see `aes-128-cbc` with no HMAC, immediately think padding oracle AND bit-flipping — both apply.
- The classic `sym-crypt dec aes-gcm` footgun: tag goes at the END of `--data` or in `--tag` separately depending on your source format. `sym-crypt` wants them separate.
