# Steganography

Common tools: zsteg, binwalk, ExifTool, steghide,
stegseek, stegsnow (SNOW), StegSolve, OpenStego, Sonic Visualiser, Audacity,
SoX, PySSTV, multimon-ng, ZBar (`zbarimg`), pngcheck, Jpeginfo, qpdf, mupdf-tools,
mediainfo, G'MIC, AperiSolve (`/opt/tools/AperiSolve`), ImageMagick, FFmpeg.

## Blind triage order

```bash
file     target
exiftool target
strings  -n 8 target | less
xxd      target | head -40
binwalk  target
```

If none of those hit, go per-format below.

## Image

### PNG

```bash
zsteg -a target.png                        # LSB in RGB(A), least/most sig, extra bits
pngcheck -v target.png                      # chunk layout; look for text chunks or oddly sized IDAT
pngtools                                    # for IDAT extraction/combination
```

Hidden chunks: `tEXt`, `zTXt`, `iTXt`. View with `exiftool -a` or:
```bash
python3 -c "
import struct, sys
d=open(sys.argv[1],'rb').read()[8:]
while d:
    (ln,) = struct.unpack('>I', d[:4]); t = d[4:8].decode(errors='replace')
    print(f'{t} len={ln}')
    d = d[8+ln+4:]
" target.png
```

### JPEG

```bash
steghide extract -sf img.jpg               # passphrase; try blank/common first
stegseek img.jpg rockyou.txt               # bruteforce steghide
jsteg reveal img.jpg out                   # jsteg LSB
outguess -r img.jpg out
exiftool -a -G1 -s img.jpg
jpeginfo -c img.jpg
```

Try also appended data after FFD9 (JPEG EOI):
```bash
python3 -c "d=open('img.jpg','rb').read(); i=d.rfind(b'\\xff\\xd9'); open('tail','wb').write(d[i+2:])"
```

### GIF / BMP

```bash
# multiple frames may each hide 1 bit/pixel
convert img.gif frame_%03d.png
```

### LSB in general

Tools: `zsteg` (ruby, PNG/BMP), `stegolsb` (python), `StegOnline` (web), stegsolve.jar.

Patterns to try: 1-bit from LSB of R, G, B separately; MSB; bit planes 0-7; interpret as text, base64, zlib.

### Visual

Open in GIMP → separate RGB → bit-plane viewer. Also:
```bash
convert -separate img.png ch_%d.png        # one PNG per channel
```

## Audio

```bash
# Spectrogram — the flag is often written in frequencies
sonic-visualiser audio.wav                 # or Audacity → Analyze → Spectrogram

# DTMF (phone tones)
multimon-ng -t wav -a DTMF audio.wav

# Morse (CW)
multimon-ng -t wav -a MORSE_CW audio.wav

# WAV LSB — write a small Python script using stdlib `wave`; no third-party tool required.
python3 - <<'PY'
import wave, sys
w = wave.open("audio.wav", "rb")
frames = w.readframes(w.getnframes())
bits = ''.join(str(b & 1) for b in frames)
out = int(bits[:len(bits)//8*8], 2).to_bytes(len(bits)//8, "big")
open("out.bin", "wb").write(out)
PY
```

Also try reversing the file, playing at different speeds (Audacity → Effect → Change Speed/Reverse).

## Video

```bash
ffmpeg -i vid.mp4 -vf fps=1 frame_%04d.png # one frame per second — stego often in a specific frame
ffmpeg -i vid.mp4 audio.wav                # dump audio for stego checks
mediainfo vid.mp4                          # metadata
exiftool vid.mp4
```

## Office / PDF

PDF covered in `forensics.md`. For Office files (which are zips):
```bash
unzip -o doc.docx -d docx-contents/
grep -r --include='*.xml' -i 'flag' docx-contents/
# Hidden comments, revision history, embedded media:
ls docx-contents/word/media/
cat docx-contents/word/comments.xml
```

## Text / "whitespace" stego

Signals: text file that renders normally but has weird file size.
```bash
cat -A text.txt | head                     # shows ^I (tab), ^M, $ (EOL)
hexdump -C text.txt | head

# Zero-width characters (U+200B/C/D, U+FEFF)
python3 -c "
import sys
d=open(sys.argv[1],encoding='utf-8').read()
zw=[c for c in d if ord(c) in (0x200B,0x200C,0x200D,0xFEFF)]
print('zero-width count:', len(zw))
print(''.join(zw).encode('unicode_escape').decode())
" text.txt

# Snow stego (space+tab after lines)
stegsnow -C text.txt
```

## Filesystems

```bash
# NTFS alternate data streams (when working with disk images)
# ext inode-level hidden data
istat image.dd <inode>

# TrueCrypt/VeraCrypt hidden volume detection: entropy spike + unused space
ent target
```

## When nothing works

- `binwalk --dd='.*' target` extracts *everything* binwalk recognizes.
- `foremost -i target -o out`.
- Try `bulk_extractor target -o out` — grabs URLs, emails, keys, phone numbers from any blob.
- Rename extension and open elsewhere — a `.png` might really be a zip.
- The flag may be in the filename, EXIF author, or git history of the challenge repo.
