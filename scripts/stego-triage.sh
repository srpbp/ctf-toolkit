#!/usr/bin/env bash
# stego-triage.sh — try every common stego/forensics tool against a file.
# Produces a folder of outputs you can grep for a flag.
#
# usage: stego-triage.sh <file> [wordlist-for-steghide]
#
# Install helpers:
#   brew install binwalk steghide zsteg exiftool foremost outguess
#   gem install zsteg
#   pip3 install stegano

set -u

F="${1:-}"
WL="${2:-/usr/share/wordlists/rockyou.txt}"
if [[ -z "$F" || ! -f "$F" ]]; then
    echo "usage: $0 <file> [wordlist]"
    exit 1
fi

OUT="stego-$(basename "$F")-out"
mkdir -p "$OUT"

run() {
    local label="$1"; shift
    local log="$OUT/$label.txt"
    echo "[*] $label"
    { echo "# $*"; "$@"; } > "$log" 2>&1 || true
}

run file-cmd       file "$F"
run exiftool       exiftool -a -G1 -s "$F"
run strings        strings -n 8 "$F"
run xxd-head       xxd "$F" | head -200
run binwalk        binwalk "$F"
run binwalk-extract binwalk --dd='.*' -q -C "$OUT" "$F"
run foremost       foremost -q -i "$F" -o "$OUT/foremost"

case "${F##*.}" in
    png|PNG|bmp|BMP)
        command -v zsteg >/dev/null && run zsteg zsteg -a "$F"
        run pngcheck    pngcheck -vt "$F"
        ;;
    jpg|JPG|jpeg|JPEG)
        if command -v steghide >/dev/null; then
            run steghide-empty steghide extract -sf "$F" -p ""
            if command -v stegseek >/dev/null; then
                run stegseek   stegseek --crack "$F" "$WL"
            fi
        fi
        command -v outguess >/dev/null && run outguess outguess -r "$F" "$OUT/outguess.out"
        ;;
    wav|WAV|mp3|MP3|ogg|OGG|flac|FLAC)
        echo "[*] audio: open in Audacity → Analyze → Spectrogram"
        command -v multimon-ng >/dev/null && run multimon multimon-ng -t wav -a MORSE_CW -a DTMF "$F"
        ;;
    pdf|PDF)
        run pdfinfo    pdfinfo "$F"
        command -v pdfimages >/dev/null && pdfimages -all "$F" "$OUT/pdfimg" >/dev/null 2>&1
        command -v pdftotext >/dev/null && pdftotext "$F" "$OUT/text.txt"
        ;;
esac

echo
echo "[*] grep for flag-like strings"
grep -R -iE "flag\{|ctf\{|[a-z0-9_-]{8,}\{" "$OUT" 2>/dev/null | head -40

echo
echo "[*] done -> $OUT/"
