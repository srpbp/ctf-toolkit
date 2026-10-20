# Tools reference

Opinionated tool list this toolkit assumes is available. Covers the major CTF
categories: Web, Crypto, Forensic, Network, Stego, OSINT, Reversing, MISC.

The scripts in `scripts/` only shell out to tools from this list (or use the
Python stdlib). If a tool here isn't installed on your machine, scripts will
either skip that step or print a hint. Run `scripts/check-approved.sh` to see
what's present on the current host.

## Ground rules

A few opinionated defaults that keep the toolkit portable and competition-safe:

1. **No AI/ML libraries** — stdlib or well-known crypto/forensics libs only.
2. **No online analysis services** — nothing calls VirusTotal, CrackStation,
   Shodan, dehashed, online decompilers, etc. Many CTFs forbid them anyway;
   staying offline keeps the workflow consistent.
3. **No commercial-license tools** — Fiddler Classic, PST Walker, SysTools
   SQLite Viewer and similar are out.
4. **Prefer offline references** — HackTricks / PayloadsAllTheThings /
   GTFOBins / SecLists mounted at `/opt/tools/*` on most Kali-like VMs.

## Categories

- **Web** — SQLi, XSS, SSRF, auth, JWT, deserialization, SSTI.
- **Crypto** — hashes, RSA, XOR, classical, symmetric, PRNG, padding oracle.
- **Forensic** — file carving, memory, disk, PDF, Windows/mobile artifacts, SQLite.
- **Network** — pcap, protocols, 802.11, CAN bus.
- **Stego** — image / audio / video, QR / barcode, SSTV.
- **OSINT** — ExifTool, Katana, Subfinder, nmap recon, offline wordlists.
- **Reversing** — Ghidra, radare2, gdb+GEF/peda/pwndbg, dnSpyEx, jadx, FLOSS,
  YARA, capa, angr, Frida, Impacket, mimikatz.
- **MISC** — scripting, protocol-of-the-day, trivia, container escape, LPE.

## Assumed tool list

### Windows (host)
```
CyberChef (browser)              — codec / basic crypto / everything
Wireshark + tshark               — network / forensic
Ghidra                           — reversing primary
RsaCtfTool                       — crypto RSA
volatility3 (+ OpenSSH plugin)   — memory forensics
Burp Suite Community             — web
HxD, x64dbg, dnSpyEx, Notepad++  — reversing
Autopsy, Sleuth Kit              — forensics
Eric Zimmerman's Tools           — Windows DFIR
Python 3 (WSL) + uv              — scripting
```

### Linux / Kali
```
Web        sqlmap, ffuf, Gobuster, Feroxbuster, Katana, Subfinder,
           jwt_tool, Burp, Impacket, Metasploit, Hydra, legion,
           offline PayloadsAllTheThings / HackTricks / SecLists, rockyou.txt

Crypto     hashcat, John the Ripper (jumbo), hashid, RsaCtfTool,
           SageMath, PARI/GP, OpenSSL, bkcrack, factordb-python,
           crypto-attacks, padding-oracle-attacker

Forensic   Autopsy, Sleuth Kit, volatility2+3, bulk_extractor, foremost,
           TestDisk/PhotoRec, Plaso, Chainsaw, Hayabusa, RegRipper,
           Hindsight, mac_apt, ALEAPP, iLEAPP, FQLite, DB Browser,
           DBeaver, SQLCipher, Didier Stevens Suite, peepdf-3, qpdf,
           mupdf-tools, oletools, ewf-tools, pff-tools, libesedb

Network    Wireshark/tshark, tcpdump, Zeek, Nmap, aircrack-ng, hcxtools,
           can-utils, cannelloni, socat

Stego      zsteg, binwalk, ExifTool, steghide, stegseek, stegsnow,
           StegSolve, OpenStego, Sonic Visualiser, Audacity, SoX,
           multimon-ng, PySSTV, ZBar, pngcheck, Jpeginfo, AperiSolve,
           ImageMagick, G'MIC, FFmpeg

Reversing  Ghidra, Cutter (AppImage), radare2, GEF, peda, pwndbg, gdb,
           BinDiff, dnSpyEx, Fernflower, jadx, apktool, dex2jar,
           pycdc / uncompyle6 / unpyc3, pyinstxtractor-ng, FLOSS, YARA,
           capa, angr, Frida, ROPgadget, checksec, UPX, Detect It Easy,
           rat-king-parser, GoReSym, Impacket, mimikatz (wine),
           pypykatz, OllyDbg (wine), ltrace, strace, NASM, objdump,
           Bytecode Viewer

MISC       Python 3, uv, Node.js, Go, Rust, Java (Temurin), Docker,
           jq, ripgrep, Git, Gitleaks, curl, wget, searchsploit (offline)
```

## Offline reference anchors

Common locations if you're on a Kali-style setup:
```
/opt/tools/PayloadsAllTheThings     — payload reference by vuln class
/opt/tools/HackTricks               — pwning techniques by platform
/opt/tools/GTFOBins.github.io       — LPE primitives per binary
/opt/tools/crypto-attacks           — paired with sagemath
/usr/share/seclists/                — wordlists (web / DNS / usernames)
/usr/share/wordlists/rockyou.txt
```

## How this toolkit maps to the list

- **Cheatsheets** reference these tools in concrete commands.
- **Scripts** either call these tools or use pure Python stdlib (plus the
  `cryptography` library for `sym-crypt.py`).
- `scripts/check-approved.sh` enumerates each CLI above and reports which are
  present on the current host.
