# CTF Toolkit

Personal reference + helper scripts for CTF categories: Web, Crypto, Forensic,
Network, Stego, OSINT, Reversing, MISC. See [TOOLS.md](TOOLS.md) for the full
tool list this toolkit assumes is available.

Scripts shell out only to the tools in TOOLS.md (or use Python stdlib). No
online analysis services, no AI/ML libraries, no commercial-license tools.

## Layout

```
USAGE.md       How to run each script, with worked examples per task.
CHECKLIST.md   Per-category playbook — what to try when you open a web/stego/osint/etc challenge.
TIPS.md        Meta tips (before/during/after an event; common mistakes; team coordination).
TOOLS.md       Tool list + ground rules.
install.sh     Symlink scripts into ~/.local/bin so they're callable by short name.
cheatsheets/   Markdown notes, one per category.
scripts/       Runnable helpers (python / bash).
```

## Quickstart

```bash
./install.sh                       # one-time: puts scripts on your PATH
cipher-id --help                   # try any script by its short name
```

See [USAGE.md](USAGE.md) for end-to-end examples per task and a per-script reference.

## My notes (Notion)

- [Write-ups](https://animated-handbell-061.notion.site/Write-ups-3c4b0a543f628079b2bcde51363cf3e5) — challenge solutions I've worked through, with the toolkit commands used.
- [Modules](https://animated-handbell-061.notion.site/Modules-310b0a543f62804493ecf589bcdbda48) — study notes per topic / module.

## Cheatsheets

| File | Category | Covers |
| --- | --- | --- |
| [web-sqli.md](cheatsheets/web-sqli.md) | Web | SQL injection — error/UNION/blind, SQLite quirks, Juice-Shop specifics |
| [web-xss.md](cheatsheets/web-xss.md) | Web | Reflected / stored / DOM XSS, context + filter bypasses + CSP |
| [web-ssrf.md](cheatsheets/web-ssrf.md) | Web | SSRF probes, cloud metadata, protocol smuggling |
| [web-auth-jwt.md](cheatsheets/web-auth-jwt.md) | Web | JWT attacks + session + OAuth + password reset |
| [web-lfi-rfi.md](cheatsheets/web-lfi-rfi.md) | Web | LFI/RFI/path traversal, PHP wrappers, log poisoning, filter bypasses |
| [web-ssti.md](cheatsheets/web-ssti.md) | Web | SSTI detection + per-engine RCE (Jinja2 / Twig / FreeMarker / Velocity / etc.) |
| [web-deserialization.md](cheatsheets/web-deserialization.md) | Web | pickle / unserialize / Java readObject / Node / .NET / YAML.load gadgets |
| [web-xxe.md](cheatsheets/web-xxe.md) | Web | XXE file read / OOB blind / SSRF / Office doc tricks / XInclude |
| [web-upload.md](cheatsheets/web-upload.md) | Web | File upload bypasses — extension / MIME / content / polyglots / zip-slip |
| [crypto-hashes.md](cheatsheets/crypto-hashes.md) | Crypto | Hash ID, hashcat/john modes, classical, XOR, padding oracle |
| [crypto-rsa.md](cheatsheets/crypto-rsa.md) | Crypto | RSA attack picker — pairs with `rsa-attack` + `rsa-pwn` scripts |
| [crypto-aes.md](cheatsheets/crypto-aes.md) | Crypto | AES mode-by-mode attacks — ECB penguin, CBC bit-flip, padding oracle, GCM nonce reuse |
| [cyberchef.md](cheatsheets/cyberchef.md) | Crypto / MISC | When to reach for CyberChef vs. CLI; common recipes by task |
| [forensics.md](cheatsheets/forensics.md) | Forensic | File carving, PDF, memory, disk, Windows DFIR (Chainsaw / EZ Tools) |
| [forensics-memory.md](cheatsheets/forensics-memory.md) | Forensic | Volatility 3 playbook — Windows/Linux triage, hashdump, bash history, flag hunting |
| [network.md](cheatsheets/network.md) | Network | pcap triage, tshark filters, DNS/ICMP/USB/TLS/wireless |
| [stego.md](cheatsheets/stego.md) | Stego | Image / audio / video / text stego |
| [imagemagick.md](cheatsheets/imagemagick.md) | Stego | ImageMagick recipes: bit-plane work, LSB extraction, diffs, QR preprocessing |
| [osint.md](cheatsheets/osint.md) | OSINT | Pre-event prep reference; mostly offline during the comp |
| [reversing.md](cheatsheets/reversing.md) | Reversing | Ghidra / radare2 / gdb-gef / dnSpy / jadx / angr / Frida |
| [pwn.md](cheatsheets/pwn.md) | Pwn | Buffer overflow / ROP / format string / shellcode / heap basics |
| [misc.md](cheatsheets/misc.md) | MISC | QR / SSTV / Morse / sqlite trivia / container escape / LPE |
| [recon.md](cheatsheets/recon.md) | — | Recon helpers that cross categories |

## Scripts

### Setup

| Script | Purpose |
| --- | --- |
| [check-approved.sh](scripts/check-approved.sh) | Verify which common CTF tools are installed. Optional category filter: `./check-approved.sh web`. |

### Web

| Script | Purpose |
| --- | --- |
| [sqli-smoketest.sh](scripts/sqli-smoketest.sh) | Fire 15+ SQLi probes at a URL, flag diffs and SQL error leaks (curl only) |
| [jwt.py](scripts/jwt.py) | Decode / forge-none / resign / crack / edit JWTs (stdlib) |
| [urlcode.py](scripts/urlcode.py) | URL / HTML / base64 / hex / rot codec, chainable (stdlib) |
| [replay.sh](scripts/replay.sh) | Replay a raw HTTP request (Burp-style file) with curl |
| [enum-web.sh](scripts/enum-web.sh) | Opinionated recon: headers, robots, sensitive paths, ffuf, katana, subfinder |
| [cve-scan.sh](scripts/cve-scan.sh) | Service + web stack fingerprint → nmap vuln NSE + searchsploit (offline Exploit-DB) lookup; auto-switches between network and web modes |
| [race-fire.sh](scripts/race-fire.sh) | Fire N parallel curls (race conditions) |
| [flask-cookie.py](scripts/flask-cookie.py) | Decode / crack / forge Flask session cookies (stdlib) |

### 2FA / captcha

| Script | Purpose |
| --- | --- |
| [totp.py](scripts/totp.py) | Generate TOTP codes when the secret has leaked (stdlib) |
| [otp-bruteforce.py](scripts/otp-bruteforce.py) | Probe 2FA endpoint for weak rate limiting (stdlib) |
| [captcha-math.py](scripts/captcha-math.py) | Auto-solve numeric/text math captchas (stdlib) |

### Crypto

| Script | Purpose |
| --- | --- |
| [hash-id.py](scripts/hash-id.py) | Identify likely hash type (stdlib) |
| [cipher-id.py](scripts/cipher-id.py) | Identify + decode ~35 ciphers. Keyless: hex, b64/32/58/85, URL, HTML, Morse, Baconian, A1Z26, T9, NATO, Leet, Brainfuck, Ook, Atbash, ROT13/47, Caesar brute, Affine brute, Trithemius, Rail-fence brute, Tap code, JWT, PEM. Keyed: Vigenere, Gronsfeld, Beaufort, Autokey, Playfair, Columnar, XOR. Bruteforce: xor-single, xor-repeating. `--chain` peels wrappers. (stdlib) |
| [sym-crypt.py](scripts/sym-crypt.py) | Symmetric encrypt/decrypt with key+IV/nonce: AES-ECB/CBC/CFB/OFB/CTR/GCM, 3DES-ECB/CBC, ChaCha20, ChaCha20-Poly1305, Blowfish. (needs `cryptography`) |
| [caesar.py](scripts/caesar.py) | All 26 Caesar shifts + ROT47 (stdlib) |
| [xor-crack.py](scripts/xor-crack.py) | Single-byte & repeating-key XOR via frequency (stdlib) |
| [rsa-attack.py](scripts/rsa-attack.py) | Single-key: e=3 / Fermat / factordb / Wiener / common factor (stdlib) |
| [rsa-pwn.py](scripts/rsa-pwn.py) | Multi-key / oracle / smooth-prime RSA: common-modulus, Håstad broadcast, Pollard p-1, Pollard rho, known-phi, known-d (Boneh), partial-d brute, blinding math (stdlib) |

### Forensics / stego / network

| Script | Purpose |
| --- | --- |
| [magic-bytes.py](scripts/magic-bytes.py) | Identify files by signature + scan for embedded blobs (stdlib) |
| [stego-triage.sh](scripts/stego-triage.sh) | Throw stego tools at a file; grep for flag |
| [image-stego.sh](scripts/image-stego.sh) | ImageMagick-driven image workflow: metadata, channel split, LSB visualisation, bit planes, negate, auto-level, alpha extract, QR scan, binwalk, zsteg → all in one output dir |
| [stego-whitespace.py](scripts/stego-whitespace.py) | Decode whitespace stego (SNOW / binary / count / inline schemes) (stdlib) |
| [stego-zerowidth.py](scripts/stego-zerowidth.py) | Decode zero-width Unicode stego (binary / base4 / tag) (stdlib) |
| [stego-nullcipher.py](scripts/stego-nullcipher.py) | Try acrostic / Nth-letter / word-length null-cipher extractions (stdlib) |
| [stego-wav.py](scripts/stego-wav.py) | Extract 1-4 bit LSB data from WAV audio (stdlib) |
| [pcap-triage.sh](scripts/pcap-triage.sh) | Fast pcap overview via tshark; HTTP object export; cleartext-proto cred extract |
| [usb-keystrokes.py](scripts/usb-keystrokes.py) | Decode USB HID keyboard capdata (stdlib) |

### OSINT

| Script | Purpose |
| --- | --- |
| [osint-handle.sh](scripts/osint-handle.sh) | Probe common sites directly for a username (curl only) |

## First run on a Kali-style VM

```bash
./scripts/check-approved.sh         # verify everything is present
./scripts/check-approved.sh web     # filter to one category

# Confirm offline references exist (if your VM has them)
ls /opt/tools/{PayloadsAllTheThings,HackTricks,GTFOBins.github.io,crypto-attacks}
ls /usr/share/wordlists/rockyou.txt
ls /usr/share/seclists
```

## Ethics

Only use these against systems you own or have explicit written authorization to test.
