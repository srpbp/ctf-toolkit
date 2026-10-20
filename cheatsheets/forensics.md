# Forensics

Common tools: Autopsy, Sleuth Kit, volatility2+3,
bulk_extractor, foremost, TestDisk / PhotoRec, exiftool, strings, xxd, HxD,
Eric Zimmerman's Tools, Chainsaw, Hayabusa, Plaso (log2timeline),
RegRipper, Hindsight (pyhindsight), mac_apt, ALEAPP, iLEAPP, FQLite, DB Browser,
DBeaver, SQLCipher, Didier Stevens Suite (pdfid / pdf-parser / oledump /
onedump), peepdf-3, qpdf, mupdf-tools, oletools, ewf-tools, pff-tools,
libesedb, Impacket, pypykatz.

## Universal triage

Run on every file blind:
```bash
file target
exiftool target
strings -n 8 target | less
xxd target | head -40
binwalk target
```

## File carving

```bash
binwalk -e target                 # auto-extract embedded files
foremost -i target -o out/
scalpel -c scalpel.conf -o out/ target
dd if=target of=out.bin bs=1 skip=<offset> count=<len>
```

If `binwalk` finds a trailing archive, often there's a file concatenated:
```bash
# split at known PK (zip) signature
python3 -c "import sys; d=open('in','rb').read(); i=d.find(b'PK\\x03\\x04'); open('out.zip','wb').write(d[i:])"
```

## Image stego

```bash
# JPG — mostly steghide (passphrase)
steghide extract -sf img.jpg
steganabara / stegsolve.jar       # LSB bit-plane viewer

# PNG — zsteg finds LSB / least-sig channel stuff
zsteg -a img.png

# Palette/alpha anomalies — check with GIMP channels, or
convert img.png -separate -scale 100%% channel.png

# EXIF
exiftool -a -G1 -s img.jpg
```

Common tricks:
- LSB in 1 or more RGB channels (zsteg catches most).
- Appended data after IEND / EOF (binwalk/foremost).
- Mismatched declared size vs. actual (sometimes decoy frames).

## Audio stego

```bash
# Spectrogram — often where the flag is drawn
sonic-visualiser audio.wav   # or audacity → Analyze → Spectrogram

# DTMF / Morse
multimon-ng -t wav -a MORSE_CW audio.wav

# LSB in WAV
# https://github.com/ragibson/Steganography (stego-lsb)
```

## PDF

```bash
pdfinfo file.pdf
pdfimages -all file.pdf out/
pdftotext file.pdf -
qpdf --qdf --object-streams=disable file.pdf out.pdf     # inflate for grepping
exiftool file.pdf

# Didier Stevens suite (approved):
pdfid.py     file.pdf
pdf-parser.py --stats file.pdf
pdf-parser.py --object 7 file.pdf

# peepdf-3 (approved) for interactive exploration + embedded JS
peepdf-3 -i file.pdf
```

## Memory dumps

Volatility 3 (preferred, auto-detects profile):
```bash
vol -f dump.raw windows.info
vol -f dump.raw windows.pstree
vol -f dump.raw windows.cmdline
vol -f dump.raw windows.filescan | grep -i flag
vol -f dump.raw windows.hashdump                   # NT hashes
vol -f dump.raw windows.lsadump                    # LSA secrets
vol -f dump.raw linux.bash                         # bash history
```

Volatility 2 (if a plugin only exists for v2):
```bash
vol.py -f dump.raw --profile=Win7SP1x64 pstree
```

Also useful on Kali VM: `dwarf2json` + volatility3 for Linux profiles, Hayabusa for Windows event log analysis, Chainsaw for Sigma rules, RegRipper for registry hives, Plaso (log2timeline) for super-timeline.

## Network captures

```bash
# Overview
capinfos capture.pcap
tshark -r capture.pcap -q -z io,phs

# Extract files
tshark -r capture.pcap --export-objects http,out/
tshark -r capture.pcap --export-objects smb,out/
foremost capture.pcap

# Follow a conversation
tshark -r capture.pcap -z follow,tcp,ascii,0

# Credentials: extract auth headers / FTP creds with tshark; parse NTLM/Kerb with Impacket.
tshark -r capture.pcap -Y 'http.authorization' -T fields -e http.authorization

# USB keystrokes
tshark -r capture.pcap -Y 'usb.capdata' -T fields -e usb.capdata
```

## Disk images

```bash
mmls image.dd           # partition layout
fls -r -o <sector> image.dd
icat -o <sector> image.dd <inode> > recovered_file
sleuthkit tools in general: autopsy for GUI
```

## Binary

Static:
```bash
file bin
checksec --file=bin
objdump -d -M intel bin | less
rabin2 -z bin           # strings in data section
r2 -A bin               # radare
```

Dynamic:
```bash
ltrace bin
strace -f bin
gdb-peda / gef / pwndbg
```
