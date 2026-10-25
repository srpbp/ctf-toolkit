# Per-category checklists

What to do when you open a challenge in each category. Follow top-to-bottom
and stop when something hits. Script names here match the `install.sh` short
names — see [USAGE.md](USAGE.md) for flags.

---

## Web

### Triage (first 60 seconds)
```bash
curl -skIL <URL>                              # headers → Server, X-Powered-By, cookies
curl -skL  <URL> | head -200                  # body → <meta generator>, framework hints
cve-scan   <URL>                              # fingerprint + searchsploit cross-ref
enum-web   <URL>                              # headers, robots, sensitive paths, ffuf, katana
```
Then open in a browser, hit **View Source**, DevTools → Network, DevTools → Application (cookies/localStorage).

### What to try per signal

| Signal | Likely vuln | First move |
| --- | --- | --- |
| Login form / auth cookie | SQLi, weak hash, JWT, session fixation | `sqli-smoketest 'URL?u=FUZZ'`; `jwt decode <token>`; `flask-cookie decode` |
| Search / query param reflects | SQLi, XSS, SSTI | `sqli-smoketest`; try `{{7*7}}`, `${7*7}`, `#{7*7}` |
| User-controlled HTML renders | XSS | `<svg onload=alert(1)>` → see `cheatsheets/web-xss.md` |
| URL/image fetch feature | SSRF | probe `127.0.0.1`, `169.254.169.254` cloud metadata — `cheatsheets/web-ssrf.md` |
| File upload / parse | RCE via deserialization, LFI | upload polyglots, path traversal `../../etc/passwd` |
| `?file=`, `?include=`, `?path=` | LFI / RFI | `php://filter/convert.base64-encode/resource=index.php` |
| JSON API | NoSQL injection, mass assignment | `{"email":{"$ne":null},"password":{"$ne":null}}`; add admin fields |
| 2FA / OTP endpoint | rate-limit bypass | `otp-bruteforce --url ... --digits 6` |
| Captcha | OCR / math solver | `captcha-math 'What is 2+3?'` |
| Buy/transfer flow | race condition | `race-fire 20 -- -X POST <URL> -d id=1` |

### Flag not surfacing?
- `cat /opt/tools/PayloadsAllTheThings/<vuln>/README.md` on the Kali VM
- Burp Suite → Repeater (approved) for manual poking
- `cipher-id --try <blob>` on anything that looks encoded

---

## Crypto

### Triage
```bash
cipher-id --try '<ct>'                        # ~35 classical/modern ciphers
cipher-id --chain '<ct>'                      # peel wrappers (b64 → hex → ...)
hash-id '<hash>'                              # identify hash type
```

### What to try per shape

| Shape of ciphertext | Try |
| --- | --- |
| 32/40/56/64/128 hex chars | hash — `hash-id`, then hashcat with the right `-m` |
| Starts `$2a$`, `$2b$` | bcrypt → `hashcat -m 3200` |
| JWT (3 parts, dots) | `jwt decode`, `jwt none`, `jwt crack` |
| Looks like base64 | `cipher-id --chain` — probably wrapped |
| Only A-Z, same length as plaintext | Caesar / Vigenère / substitution → `cipher-id --try --only caesar,affine,vigenere-brute` |
| Short, know plaintext prefix | `cipher-id --cipher vigenere-prefix --key 'KNOWN'` |
| High-entropy hex, long | AES-* / ChaCha — need key + IV → `sym-crypt dec aes-cbc ...` |
| Low IC (<0.04) | base-encoded or OTP; try `--chain` first |
| IC ~0.067 | Monoalphabetic sub — frequency crack (manual or `cipher-id` IC hint) |
| IC 0.038-0.055 | Vigenère family → `cipher-id --cipher vigenere-brute` |
| `n, e, c` given | RSA → `rsa-attack --n ... --e ... --c ...`, fallback `RsaCtfTool` |
| Zip password-protected | `bkcrack` (known plaintext) or `zip2john → john` |
| Repeating-byte XOR | `xor-crack keylen` then `xor-crack repeat` |

### Common gotchas
- IC says keylen 14 on short text? Treat as noise — try 6, 7 first.
- Vigenère brute failing? Use `vigenere-prefix` with the likely flag format (`FLAG{`, `CSG_FLAG{`).

---

## Forensics

### Triage
```bash
file           <target>
magic-bytes    <target> --scan             # also catches embedded files
exiftool -a -G1 -s <target>
strings -n 8   <target> | less
```

### What to try per file type

| File | Workflow |
| --- | --- |
| PNG / JPG / BMP | `image-stego <img>` — one-shot: metadata, channels, LSB, QR, binwalk, zsteg |
| WAV / MP3 | `stego-wav`; also open in Audacity → Analyze → Spectrogram; `multimon-ng -a MORSE_CW/DTMF` |
| PDF | `pdfinfo`, `pdfimages -all`, `pdftotext`, `pdfid.py`, `peepdf-3`, `qpdf --qdf` to inflate for grepping |
| Office (docx/xlsx) | unzip; grep xml for flag; check `word/comments.xml`, `word/media/` |
| ZIP | try no password first; if `bkcrack` applies (known plaintext header), use it; else `zip2john | john` |
| Disk image (.dd / .img) | `mmls`, `fls -r`, `icat`, Autopsy for GUI |
| Memory dump | `vol -f dump.raw windows.info/pstree/cmdline/hashdump`, `linux.bash` for history |
| PCAP | `pcap-triage <cap.pcap>` — DNS/HTTP/FTP creds + file export + USB capdata |
| Windows evtx | Chainsaw with Sigma rules, Hayabusa, RegRipper for registry hives |
| Mobile backup | ALEAPP (Android), iLEAPP (iOS) |
| SQLite DB | `sqlite3 file ".dump" | grep flag`; FQLite for deleted rows; DB Browser for GUI |

### Common gotchas
- "Hidden" data is often after the file's declared EOF — carve the trailing bytes.
- `exiftool` finds flags in Author/Comment/Description more often than you'd think.
- Volatility 3 auto-detects profiles; Volatility 2 only if a plugin exists only there.

---

## Network

### Triage (pcap)
```bash
pcap-triage <cap.pcap>                        # overview + extractions in one dir
capinfos    <cap.pcap>
tshark -r <cap.pcap> -q -z io,phs             # protocol hierarchy — what's in it?
tshark -r <cap.pcap> -q -z conv,tcp           # TCP conversations
```

### What to try per protocol

| In the pcap | Workflow |
| --- | --- |
| HTTP | `tshark --export-objects http,out/` + `grep flag out/*` |
| HTTP with auth | `tshark -Y http.authorization -T fields -e http.authorization` |
| FTP / telnet / SMTP cleartext | grep for USER/PASS/MAIL commands |
| DNS exfil | long unique subdomains → concat labels → base64/32/hex decode |
| ICMP exfil | `-Y icmp.type==8 -T fields -e data.data` |
| USB (keyboard) | `-Y usb.capdata -T fields -e usb.capdata` → `usb-keystrokes` |
| 802.11 (WPA) | `hcxpcapngtool -o hash.22000` → `hashcat -m 22000 hash.22000 rockyou.txt` |
| TLS | server names from ClientHello; need `SSLKEYLOGFILE` to decrypt |
| SMB | `--export-objects smb,out/` |
| CAN bus / vehicle | `canplayer -I dump.log`; `candump` |
| Zeek logs | query `conn.log`, `http.log`, `dns.log` with awk/jq |

### Live-network tasks
```bash
cve-scan <ip>                                 # nmap -sV + vuln NSE + searchsploit
cve-scan --fast <ip>                          # top-100 only
rustscan -a <ip>                              # faster port discovery, hand off to nmap
```

---

## Stego

### Triage
```bash
image-stego <image>                           # one-shot image workflow
stego-triage <any-file> [wordlist]            # throws every stego tool at it
stego-whitespace <text-file>                  # trailing/inline whitespace schemes
stego-zerowidth <text-file>                   # zero-width Unicode
stego-nullcipher <text-file>                  # acrostic / Nth-letter extractions
stego-wav <audio.wav>                         # LSB extraction from audio
```

### Decision tree

| Suspect | Try |
| --- | --- |
| Image, PNG/BMP | `zsteg -a img` + `image-stego img`; eyeball each channel/bitplane |
| Image, JPEG | `steghide extract` (empty pw first), `stegseek img rockyou.txt`, `jsteg reveal` |
| Image, bytes after IEND/FFD9 | `binwalk -e`, or hand-carve from `rfind(b'\xff\xd9')+2` |
| Audio spectrogram | Sonic Visualiser / Audacity — flag usually drawn in frequencies |
| Audio Morse / DTMF | `multimon-ng -a MORSE_CW -a DTMF <wav>` |
| Audio LSB | `stego-wav` |
| SSTV (slow-scan TV tones) | `PySSTV` decoder, or run through sonic-visualiser first |
| Text file, odd whitespace | `stego-whitespace --diag` for signature; try `--snow` if stegsnow format |
| Text with Unicode | `stego-zerowidth` |
| Text looks mundane | `stego-nullcipher` — acrostic / first-letter extraction |
| QR / barcode | `zbarimg` directly; pre-threshold if noisy (see `cheatsheets/imagemagick.md`) |
| Video | `ffmpeg -i vid.mp4 -vf fps=1 frame_%04d.png` → stego often in one specific frame |
| ZIP / tar | `binwalk --dd '.*'`; check for passphrase hints in Comment field |

### Common gotchas
- `stegsnow` on a WS-stego file producing garbage = it was encrypted with a password.
- `zsteg` output is noisy; false positives are common — look for the one with the longest clean ASCII run.
- A "congratulatory" image in the challenge directory is usually the writeup graphic, NOT the challenge binary.

---

## OSINT

### Triage
```bash
exiftool -a -G1 -s <image|doc>                # GPS, device, author, software fingerprint
pdftotext file.pdf -                          # extract text from PDF
osint-handle <username>                       # probe common sites for a handle
```

### Pivots

| Starting data | Next step |
| --- | --- |
| Image | EXIF (GPS, author); reverse image search (Yandex > Google > TinEye); check background landmarks |
| Username | `osint-handle`; check platform-specific `/user/<name>` URLs; GitHub for leaked keys |
| Email | HIBP for breach presence (web browser, if sanctioned); `holehe` where allowed |
| Domain | `whois`, `dig +short any`, cert transparency via `crt.sh` (if sanctioned) |
| Phone | truecaller / Phoneinfoga (if sanctioned); country code → geo clues |
| Document | metadata (`exiftool`), revision history (unzip docx + xml diff) |
| Social post | screenshot, archive via wayback/archive.today, cross-reference with other platforms |
| Face / background | Yandex reverse image, Street View if landmarks visible |

### Shadow pivots (post-publication)
- `web.archive.org` wayback for deleted content
- GitHub commit history for leaked secrets (`gitleaks detect --source .`)
- `builtwith.com` for site tech stack

### Common gotchas
- CSG forbids most online OSINT services during event — use what's on the Kali VM.
- Flags often hide in document metadata, not body text.
- "Deleted" tweets/posts live on in nitter/archive mirrors.

---

## Reversing

### Triage
```bash
file                 <bin>
checksec --file=<bin>                          # NX, PIE, canary, RELRO
strings -n 8         <bin> | less
die <bin>                                      # Detect It Easy: packer/compiler guess
upx -d <bin>                                   # if DIE says UPX-packed
cve-scan --binary <bin>                        # strings + searchsploit for version banners
```

### What tool for what binary

| Binary type | Go-to |
| --- | --- |
| ELF / PE native | Ghidra (primary), radare2 / Cutter, gdb+GEF/peda/pwndbg |
| .NET exe/dll | dnSpyEx |
| JVM (jar, class) | jadx-gui, Bytecode Viewer, Fernflower |
| Android APK | `apktool d`, `jadx-gui`, `dex2jar` |
| Python .pyc | `uncompyle6` (py≤3.8), `pycdc` (3.9+), `unpyc3` |
| PyInstaller EXE | `pyinstxtractor-ng target.exe` → extract .pyc files → decompile |
| Go binary (stripped) | `GoReSym -t -d -s bin > syms.txt`, load in Ghidra |
| Packed / obfuscated | FLOSS, `capa`, `die`, UPX, manual Ghidra unpacking |

### Dynamic analysis
- `ltrace` — library calls (fastest way to find `strcmp` password checks)
- `strace` — syscalls (file paths, network)
- `gdb -x /opt/tools/gef.py` — breakpoint + pattern create/search for buffer overflows
- `frida` — hook functions at runtime, e.g. intercept `strcmp` args

### Common challenge patterns
- Password strcmp → `ltrace ./bin` shows plaintext comparison
- Serial key check → Ghidra decompile the check function, invert logic
- XOR'd flag → find the XOR key in `.rodata`, decode with `cipher-id --cipher xor`
- CRC/checksum gate → patch the comparison in Ghidra, export as modified binary
- Format string → leak with `%p %p %p`, write with `%n`
- Buffer overflow → `pattern_create 200` → crash offset → `ROPgadget` → chain

---

## Pwn / Binary exploitation

### Triage
```bash
checksec --file=<bin>
file <bin>
strings <bin> | grep -i flag                   # might just be there
```

### Protection → attack mapping

| Protections | Typical attack |
| --- | --- |
| No NX, No ASLR | Shellcode on stack |
| NX, No ASLR | ret2libc / static ROP |
| NX + ASLR | leak libc → ret2libc; `ROPgadget --binary libc.so.6` |
| Canary | leak canary via format string / fork patterns, then overflow |
| Full RELRO + PIE | heap-based: UAF, double-free, overlap chunks |
| Standard libc | one-gadget worth checking (not in approved tools; compute manually) |

### Workflow
1. Find the input, size the overflow (`pattern_create 200` → crash → `pattern_search`).
2. Identify what you control (RIP? RSP? GOT entry?).
3. Pick a technique that fits the protections.
4. Build the chain: shellcode / ROP / heap primitive.
5. Automate with `pwntools` (import pattern via pip).

---

## MISC

A grab-bag of "doesn't fit elsewhere". When nothing else works, try:

| Looks like | Try |
| --- | --- |
| QR / barcode | `zbarimg` directly; preprocess with `convert -threshold` first |
| SSTV / RTTY tones | PySSTV / `multimon-ng -a POCSAG512/1200` |
| Morse / DTMF audio | `multimon-ng -a MORSE_CW -a DTMF` |
| Esolang (Brainfuck, Ook, Whitespace) | `cipher-id --cipher brainfuck` / `--cipher ook`; or run through an actual interpreter |
| CAN bus log | `canplayer`, `candump` |
| Container escape | `/opt/tools/GTFOBins.github.io/_gtfobins/`, `/opt/tools/HackTricks` |
| LPE Linux | `sudo -l`, `find / -perm -4000`, `getcap -r /`, GTFOBins |
| Odd file / unknown format | `magic-bytes --scan`, `binwalk`, `bulk_extractor` |

See [`cheatsheets/misc.md`](cheatsheets/misc.md) for more.

---

## OT / ICS / Hardware

Rare but shows up in some CTFs (CSG has an OT track).

| Signal | Try |
| --- | --- |
| Modbus pcap | `tshark -Y modbus` → function codes, register reads/writes |
| S7 (Siemens) pcap | `tshark -Y s7comm` |
| EtherNet/IP | `tshark -Y enip` |
| CAN bus | `can-utils`, `cannelloni`; replay via `canplayer` |
| Firmware image | `binwalk -e`, then analyze extracted root filesystem |
| UART dump / serial log | `strings`, look for boot banners + credential prompts |

---

## When truly stuck (any category)

1. **Re-read the challenge brief.** Often names a tool, format, or technique.
2. **Try `cipher-id --chain`** on anything that looks encoded.
3. **Check offline references** on the Kali VM:
   ```bash
   rg -i '<topic>' /opt/tools/{PayloadsAllTheThings,HackTricks,GTFOBins.github.io}
   ```
4. **Search exploit-db offline** with `searchsploit <keyword>`.
5. **Diff against a known-clean reference** if the challenge gives you one (`plain.c` vs `challenge.c`).
6. **Look at the challenge *filename*** — it often hints at the technique (`_lsb`, `_vigenere`, `_offset=65537`).
7. **Submit the obvious thing** — some challenges really are just reading text on an image.
