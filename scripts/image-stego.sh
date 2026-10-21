#!/usr/bin/env bash
# image-stego.sh — opinionated ImageMagick workflow for image stego challenges.
#
# Chains the usual "I just got an image, now what?" recipes into one command
# that produces an output directory you can eyeball or feed into other tools.
#
# usage: image-stego <image> [outdir]
#
# What it does, in order:
#   1. identify -verbose              → metadata, dimensions, quality, colorspace
#   2. exiftool -a -G1 -s             → full tag dump (if exiftool present)
#   3. strings -n 8                   → ASCII strings embedded in the file
#   4. convert -separate              → split R, G, B (and A) into separate PNGs
#   5. LSB visualisation              → amplify low bits of each channel
#   6. bit-plane extraction           → one PNG per bit (0-7) of the red channel
#   7. -negate                        → inverted colours (reveals faint ink/watermarks)
#   8. -auto-level                    → stretched contrast
#   9. -alpha extract                 → alpha channel only (if present)
#   10. zbarimg                       → scan for QR / barcodes (if zbar present)
#   11. binwalk -e                    → carve any appended files (if binwalk present)
#   12. zsteg -a                      → LSB stego for PNG/BMP (if zsteg present)
#
# After it finishes:
#   open <outdir>                     # eyeball every file (macOS)
#   xdg-open <outdir>                 # (linux)
#   grep -R flag <outdir>             # fast scan for literal flags in metadata

set -u

IMG="${1:-}"
if [[ -z "$IMG" || ! -f "$IMG" ]]; then
    echo "usage: $0 <image> [outdir]"
    exit 1
fi

NAME="$(basename "$IMG")"
OUT="${2:-image-${NAME%.*}-out}"
mkdir -p "$OUT"

say() { echo; echo "=== $* ==="; }

say "1. identify (ImageMagick metadata)"
identify -verbose "$IMG" 2>&1 | tee "$OUT/identify.txt" | sed -n '1,20p'

if command -v exiftool >/dev/null 2>&1; then
    say "2. exiftool"
    exiftool -a -G1 -s "$IMG" 2>&1 | tee "$OUT/exiftool.txt" | head -40
fi

say "3. strings"
strings -n 8 "$IMG" | tee "$OUT/strings.txt" | head -20

say "4. channel split (RGB and alpha if present)"
convert "$IMG" -separate "$OUT/channel_%d.png" 2>&1 && ls "$OUT"/channel_*.png | sed 's|^|    |'

say "5. LSB visualisation (low 1 bit, stretched to full range)"
convert "$IMG" -evaluate And 1 -evaluate Multiply 255 "$OUT/lsb_1bit.png" 2>&1
convert "$IMG" -evaluate And 3 -evaluate Multiply 85  "$OUT/lsb_2bit.png" 2>&1
convert "$IMG" -evaluate And 7 -evaluate Multiply 36  "$OUT/lsb_3bit.png" 2>&1
convert "$IMG" -evaluate And 15 -evaluate Multiply 17 "$OUT/lsb_4bit.png" 2>&1
echo "    wrote lsb_[1234]bit.png"

say "6. bit-plane extraction (red channel, bits 0..7)"
for b in 0 1 2 3 4 5 6 7; do
    mask=$((1 << b))
    convert "$IMG" -channel R -separate +channel \
        -evaluate And "$mask" -evaluate Multiply $((255 / (mask > 0 ? mask : 1))) \
        "$OUT/bitplane_R$b.png" 2>/dev/null
done
echo "    wrote bitplane_R0..R7.png"

say "7. -negate (inverted colours)"
convert "$IMG" -negate "$OUT/negate.png" 2>&1 && echo "    wrote negate.png"

say "8. -auto-level (stretch contrast)"
convert "$IMG" -auto-level "$OUT/stretched.png" 2>&1 && echo "    wrote stretched.png"

say "9. alpha channel (if any)"
has_alpha=$(identify -format "%A" "$IMG" 2>/dev/null)
if [[ "$has_alpha" == "True" || "$has_alpha" == "Blend" ]]; then
    convert "$IMG" -alpha extract "$OUT/alpha.png" 2>&1 && echo "    wrote alpha.png"
    convert "$IMG" -alpha off     "$OUT/no-alpha.png" 2>&1
else
    echo "    (no alpha channel)"
fi

if command -v zbarimg >/dev/null 2>&1; then
    say "10. zbarimg (QR / barcode scan on original + cleaned variant)"
    zbarimg --raw "$IMG" 2>&1 | tee "$OUT/zbar.txt" | head
    # also try after thresholding (helps noisy captchas / blurry QRs)
    convert "$IMG" -colorspace Gray -threshold 60% -morphology Open Diamond:1 "$OUT/cleaned.png" 2>/dev/null
    zbarimg --raw "$OUT/cleaned.png" 2>&1 | tee -a "$OUT/zbar.txt" | head
fi

if command -v binwalk >/dev/null 2>&1; then
    say "11. binwalk + extract"
    # Try new Rust binwalk (--extract --directory), fall back to old Python flags
    if binwalk --help 2>&1 | grep -q '^Usage: binwalk <--list'; then
        binwalk --extract --directory "$OUT/binwalk-out" "$IMG" 2>&1 | tee "$OUT/binwalk.txt" | head -15
    else
        binwalk -e --directory "$OUT" --dd='.*' "$IMG" 2>&1 | tee "$OUT/binwalk.txt" | head -15
    fi
fi

if command -v zsteg >/dev/null 2>&1; then
    say "12. zsteg -a (PNG/BMP LSB stego)"
    case "${IMG##*.}" in
        png|PNG|bmp|BMP) zsteg -a "$IMG" 2>&1 | tee "$OUT/zsteg.txt" | head -30 ;;
        *) echo "    skipped — zsteg only handles PNG/BMP" ;;
    esac
fi

say "search for flag-like strings across every output"
rg -R -iE 'flag\{|ctf\{|csg\{|csg2026\{' "$OUT" 2>/dev/null || grep -R -iE 'flag\{|ctf\{|csg\{' "$OUT" 2>/dev/null | head

echo
echo "[*] done → $OUT/"
echo "    open $OUT               # eyeball every file"
