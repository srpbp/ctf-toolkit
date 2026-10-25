# CyberChef — when to reach for which operation

CyberChef (browser-based, approved per TOOLS.md) is the Swiss army knife for codec / crypto / analysis. Fast for one-off decodes, superior to CLI when you need a visual stack of operations.

Local offline copy: GitHub → gchq/CyberChef releases → download the single HTML file, open in Chrome. Runs 100% client-side.

## When to use CyberChef vs. a toolkit script

| Situation | CyberChef | CLI (toolkit) |
| --- | --- | --- |
| One-shot decode, visual | ✓ | — |
| Chain 3+ encodings and tweak | ✓ (drag ops in Recipe pane) | `urlcode chain b64,hex,url 'in'` |
| Processing a big file or batch | — | `cipher-id`, `sym-crypt`, scripts |
| Need to compute / brute | — | `cipher-id --cipher *-brute`, pwntools |
| Need to pipe into other tools | — | CLI |
| Visualising a magic / hex dump | ✓ (Magic op is great) | `magic-bytes --scan` |
| Rendering QR / barcode | — | `zbarimg`, `image-stego` |

**Rule of thumb**: use CyberChef when you're exploring and don't know what you're looking at. Switch to CLI when you've figured out the recipe and want to automate / fuzz / brute.

## The one op you'll use most: **Magic**

Operation: **Magic** (under *Extractors*). Automatically tries all common decodes and reports confidence. Set:
- *Depth*: 3 (recursive decoding)
- *Intensive mode*: on
- *Extensive language support*: on

Think of it as CyberChef's `cipher-id --chain`.

## Common tasks → recipes

### Decode base64 → hex → ascii
```
From Base64 → From Hex
```

### JWT inspect / tamper
```
JWT Decode                                   # just view header + payload
# To forge alg=none:
JSON to JWT  (header = {"alg":"none","typ":"JWT"}, payload = {...}, signature = "")
# To crack HMAC secret (dictionary):
JWT Verify / Brute Force   (use jwt_tool CLI for serious cracking)
```

### Classical cipher triage
```
ROT13 → ROT47 → From Base58 → From Base85 → Vigenère Decode
# or stack: Magic op first; it picks the right one
```

### Decrypt AES-CBC
```
From Hex (if ct is hex)
AES Decrypt
  Key:   { Hex, UTF8, ... }
  IV:    { Hex, ... }
  Mode:  CBC
  Input: Raw / Hex
  Output: Raw / UTF8
```

### Spectrogram / audio stego preview
```
Spectrogram (in Multimedia)
# Preview audio for hidden images in frequencies — Audacity/Sonic Visualiser better for serious analysis
```

### View / render QR code
```
Parse QR Code                                # if you have the image bytes
Generate QR Code                             # if you have the data and want an image
```

### XOR with a key
```
XOR  (Key = whatever, scheme = Hex/UTF8/Base64)
# Brute single-byte: use CLI `xor-crack single` instead — faster
```

### Hex dump / binary analysis
```
To Hexdump                                   # pretty 16-byte-per-line view
From Hexdump                                 # reverse
```

### Decompress gzip / zlib / bz2 / etc.
```
Gunzip                                       # gzip
Raw Inflate                                  # zlib (no header)
Zlib Inflate                                 # zlib (with header)
Bzip2 Decompress
```

### Parse / tidy structured data
```
JSON Beautify
XML Beautify
JavaScript Beautify
CSS Beautify
```

### Regex extract (grep-style)
```
Regular Expression   (built-in presets for IPs, emails, URLs, credit cards)
```

### Hash a string
```
MD5 / SHA1 / SHA256 / SHA3 / HMAC
```

### Parse a cert / public key
```
Parse X.509 Certificate
Parse PEM
Parse ASN.1 Hex String
```

### URL / phone / UA parsing
```
Parse URI
Parse User Agent
```

### Image metadata inside the browser
```
Extract EXIF
Render Image            (shows the image inline — useful when triaging dumps)
```

### Steganography (basic)
```
Extract LSB             (crude — zsteg via CLI finds more variants)
```

## Operation groups you'll scan

- **Data format**: From/To Hex/Base64/Base32/Base58/Base85, URL encoding, HTML entities, Unicode escape
- **Encryption / Encoding**: AES / DES / RC4 / Blowfish / Vigenère / Caesar / ROT13/47 / Rail Fence
- **Public Key**: RSA sign/verify, parse PEM, parse X.509
- **Hashing**: MD5, SHA family, HMAC, CRC
- **Compression**: Gunzip, Inflate, Bzip2, LZString
- **Extractors**: Magic (!), extract strings, URLs, emails, IPs, hashes
- **Multimedia**: Spectrogram, QR code, EXIF
- **Networking**: Parse UA/URI/IPv4/IPv6
- **Code tidy**: Beautify / Minify for most languages
- **Flow control**: Fork, Merge, Subsection, Register (loop and condition)
- **Date / time**: From Unix / parse / time delta

## Workflow tips

1. **Drag the input into the Input pane** (file upload supported) — CyberChef handles up to ~10MB comfortably.
2. **Click an operation to add it to the recipe** — order matters; recipe runs top-to-bottom.
3. **Favorites star** — star ops you use often; they pin at top of the op list.
4. **Right-click an op** → "Jump to definition" to see the code.
5. **Save a recipe** → Load/Save button → gives you a URL you can bookmark.
6. **Flow control blocks** let you fork input, apply different ops to each fork, merge back. Great for "try both base64 variants side by side".

## Bookmark these shortcut recipes

| Task | Recipe fragment |
| --- | --- |
| Try everything | `Magic` (depth 3, intensive on) |
| Base64 → hex → ascii | `From Base64, From Hex` |
| URL-decode and view | `URL Decode` |
| Hex to int, int to decimal | `From Hex, To Base, radix 10` |
| Decrypt ROT-N (unknown N) | `ROT13 Brute Force` |
| Guess charset of binary | `Detect File Type` + `Extract Strings` |
| Visualise image bytes | `Render Image, Extract EXIF` |

## Tips
- CyberChef's **Magic** is roughly the same approach as `cipher-id --chain` — both peel wrappers automatically. CyberChef is more thorough; CLI is pipeable and scriptable.
- For brute-force or large wordlists → CLI. CyberChef is single-threaded in-browser.
- The browser offline copy survives any no-internet rule; drop the HTML on your Mac desktop.
- Flow Control → **Register** op lets you capture a regex match and reuse it later — powerful for recursive challenges.
- CyberChef remembers the last recipe in URL fragments — share a solved challenge recipe with a teammate just by sharing the URL.
