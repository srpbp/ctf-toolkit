# MISC

Challenges that don't fit cleanly into Web / Crypto / Forensic / Stego / Network / Reversing / OSINT.
In MISC often means: scripting puzzles, protocol-of-the-day, SQLite trivia, QR / barcodes, SSTV,
container escapes, LPE primitives, odd file formats.

## QR / barcodes

```bash
zbarimg code.png
```

Multiple codes in one image: pre-process (`convert`), split, re-run.

## SSTV (slow-scan TV audio → image)

```bash
# PySSTV: encode (rare in CTF). To DECODE SSTV in Kali Kali VM:
# Open the WAV in Sonic Visualiser → look for the expected frequency pattern
# Or: pipe to a software SDR decoder (not on list; use the GUI route)
```

Approved audio-tool chain for RF-style audio: Audacity → export the signal span → re-sample if needed with SoX → inspect in Sonic Visualiser.

## Morse / DTMF

```bash
multimon-ng -t wav -a MORSE_CW -a DTMF -a POCSAG512 -a POCSAG1200 input.wav
```

## Base-N / codec guesswork

CyberChef is king here. On Windows host open the browser bookmark. On Kali:
- `base64 / base32 / xxd -r -p`
- `python3 -c "import codecs; print(codecs.decode('...','rot_13'))"`
- `openssl base64 -d`

For base58/85/91: use `uv run --with pybase62 python -c '...'` or write it stdlib.

## Hex analysis / patching

```bash
xxd target | head
xxd -r patched.hex > patched.bin
# or use HxD (Windows) / bvi (Kali)
```

## SQLite tricks

```bash
sqlite3 db.sqlite
.tables
.schema users
SELECT sql FROM sqlite_master WHERE type='table';

# WAL / rollback journal
ls -l   # look for .sqlite-wal / .sqlite-journal — often has uncommitted data
# FQLite: recovery tool for deleted rows
fqlite db.sqlite
# DB Browser: GUI
sqlitebrowser db.sqlite
```

## PCAP + file carving in one shot

```bash
tshark -r cap.pcap --export-objects http,out/
foremost -i cap.pcap -o out/
bulk_extractor cap.pcap -o out/
```

## Container / sandbox escape primitives

```
GTFOBins (offline): /opt/tools/GTFOBins.github.io/_gtfobins/*.md
HackTricks:         /opt/tools/HackTricks/   (search docker, k8s, lxc, SUID)
```

Quick checks on a shell:
```bash
id; groups
getcap -r / 2>/dev/null                      # capabilities
find / -perm -4000 -ls 2>/dev/null           # SUID binaries
ls -la /                                     # mounted volumes
mount | grep -v /proc                        # cgroup / docker overlay signs
cat /proc/1/cgroup                           # container indicator
hostname; cat /etc/hostname
```

Container-specific:
```bash
ls -la /.dockerenv
capsh --print            # inside container
```

## LPE primitives (Linux)

```bash
# Sudo rules
sudo -l

# Writable PATH
echo $PATH; ls -la $PATH

# SUID with GTFOBins entry
cat /opt/tools/GTFOBins.github.io/_gtfobins/<name>.md

# World-writable systemd units / cron
find /etc/cron* /etc/systemd/system -type f -writable 2>/dev/null
```

## Searching for flags

```bash
# fast recursive grep
rg -n --no-ignore --hidden -i 'flag\{|ctf\{|\{' /

# base64-wrapped flag
rg -n 'ZmxhZ3s'   # "flag{" base64

# in sqlite
sqlite3 db ".dump" | rg -i 'flag'

# in memory image
strings dump.raw | rg -i 'flag\{'
volatility3 -f dump.raw windows.strings | rg -i flag
```

## Protocol scripting

Templates:
```bash
# raw TCP
exec 3<>/dev/tcp/host/port
echo -e "GET / HTTP/1.0\r\n\r\n" >&3
cat <&3
```

```python
# python stdlib socket client
import socket
s = socket.create_connection(("host", 1234))
s.sendall(b"HELO\n")
print(s.recv(4096))
```

```bash
# socat chaining
socat TCP:remote:1234 - <<< "payload"
socat -v TCP-LISTEN:9999,fork TCP:remote:1234    # MITM
```

## CAN bus (if a vehicle challenge drops)

```bash
# Replay a dump
canplayer -I dump.log vcan0=can0

# Decode / sniff
candump -t a vcan0
cansend vcan0 123#DEADBEEF

# Convert pcap <-> canlog
cannelloni -I vcan0 -R host -r port -l port
```

## Fast look-up anchors

```
PayloadsAllTheThings  /opt/tools/PayloadsAllTheThings
HackTricks            /opt/tools/HackTricks
GTFOBins              /opt/tools/GTFOBins.github.io
SecLists              /usr/share/seclists
rockyou.txt           /usr/share/wordlists/rockyou.txt
```
