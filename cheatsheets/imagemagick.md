# ImageMagick

Approved in  (`convert`, `identify`, `montage`, `compare`, `mogrify`,
`magick` — the IM7 unified binary). Primary uses in CTF: pre-process images
for stego tools, extract/combine bit planes, probe metadata, compare near-
duplicate images, generate test material.

Modern IM7 syntax: `magick <in> [ops] <out>`.
IM6 syntax (still common): `convert <in> [ops] <out>`.

## Inspect

```bash
identify     image.png                 # one-line summary
identify -verbose image.png | less     # full metadata
identify -format "%w %h %Q %z %r\n" *  # width height quality depth colorspace
```

Catch anomalies:
```bash
# large png with tiny visible content? maybe LSB stego
identify -format "%f  size=%b  pixels=%[fx:w*h]\n" *.png
```

## Channel / bit-plane work

```bash
# split R/G/B/A into separate PNGs — zsteg-free alternative
convert image.png -channel R -separate R.png
convert image.png -separate ch_%d.png     # 0=R 1=G 2=B 3=A if present

# dump only the N-th bit plane of the red channel
convert image.png -channel R -separate +channel -evaluate And 1 -evaluate Multiply 255 bitR0.png
#                                                            ^ 1<<N for Nth bit

# amplify low-order bits so your eye can see them
convert image.png -evaluate And 7 -evaluate Multiply 36 lsb.png

# subtract two near-identical images to see what changed
compare -metric AE a.png b.png diff.png

# combine channels back
convert ch_0.png ch_1.png ch_2.png -combine recombined.png
```

## LSB extraction primitive

Pull one bit per channel per pixel into a bytestream (useful starting point):

```bash
# dump raw pixel bytes
convert image.png -depth 8 RGB:- > pixels.bin

# then in python
python3 - <<'PY'
d = open("pixels.bin","rb").read()
bits = ''.join(str(b & 1) for b in d)
# chunk into bytes, drop trailing partial
out = bytes(int(bits[i:i+8],2) for i in range(0, len(bits)//8*8, 8))
open("lsb.bin","wb").write(out)
PY
```

Try the same with `-channel R` only, or MSB (`& 128`) if `& 1` is noise.

## Format conversions

```bash
convert in.jpg out.png                    # also strips most JPEG lossy artifacts
convert in.pdf -density 300 page_%03d.png # rasterize PDF pages
convert *.png out.gif -delay 20 -loop 0   # frame set → animated gif
convert in.svg -background none out.png
convert in.png -strip clean.png           # drop every metadata tag
```

For animated GIFs:
```bash
convert anim.gif -coalesce frame_%03d.png # one PNG per frame — flag may hide in frame N
```

## Steg-adjacent tricks

### Fix a corrupt PNG header

If `file image.png` says it's not a PNG but the header is `?PNG`, patch the first 8 bytes:
```bash
printf '\x89PNG\r\n\x1a\n' > hdr; cat hdr <(tail -c +9 broken.png) > fixed.png
```

Then `identify fixed.png` and `pngcheck -v fixed.png`.

### Palette shift

Some stego uses the palette index, not the color. Dump palette:
```bash
identify -verbose image.png | awk '/Colormap/,/Histogram/'
```

Re-render with every pair of indices swapped — look for text.

### Lossless comparisons

```bash
# per-pixel diff, both as mask and metric
compare -highlight-color red a.png b.png diff.png
compare -metric PSNR a.png b.png null:
compare -metric MAE  a.png b.png null:
```

### Over/underlay (text in alpha channel)

```bash
# extract alpha only
convert image.png -alpha extract alpha.png

# force alpha to opaque, strip to see hidden content underneath
convert image.png -alpha off visible.png
```

### Contrast / level stretching (reveal faint ink)

```bash
convert faint.png -auto-level stretched.png
convert faint.png -evaluate Multiply 1.5 -evaluate Subtract 20% boosted.png
convert faint.png -negate inverted.png
convert faint.png -separate -auto-level -combine fixed.png
```

### Thresholding — turn watermark into readable text

```bash
convert in.png -colorspace Gray -threshold 50% bw.png
convert in.png -colorspace Gray -adaptive-threshold 25x25+5 adaptive.png
```

### Rotate / crop / tile montage

```bash
convert in.png -rotate 90 r90.png
convert in.png -crop 100x100+0+0 +repage tile.png
montage frames_*.png -tile 8x -geometry +0+0 grid.png
```

## QR / barcode preprocessing

Captchas and QRs often have noise. Clean before `zbarimg`:
```bash
convert in.png -colorspace Gray -threshold 60% -morphology Open Diamond:1 clean.png
zbarimg clean.png
```

## G'MIC pairing

`gmic` is approved and bolts advanced filters onto IM:
```bash
gmic in.png fx_lsb_steganography 1,0,0 output[0] out.png
```

## Scripts in this toolkit that call ImageMagick

- `stego-triage.sh` — chains binwalk / exiftool / zsteg / IM separate-channels when applicable.

## Minimal reference card

| Op | Command |
|---|---|
| Info | `identify -verbose img` |
| Split RGB | `convert img -separate ch_%d.png` |
| LSB visible | `convert img -evaluate And 1 -evaluate Multiply 255 lsb.png` |
| Strip metadata | `convert img -strip out.png` |
| PDF→PNG | `convert -density 300 in.pdf out_%03d.png` |
| GIF frames | `convert anim.gif -coalesce f_%03d.png` |
| Diff | `compare -metric AE a b diff.png` |
| Invert | `convert img -negate out.png` |
| Grayscale + threshold | `convert img -colorspace Gray -threshold 50% bw.png` |
| Pixel bytes to stdout | `convert img -depth 8 RGB:-` |
