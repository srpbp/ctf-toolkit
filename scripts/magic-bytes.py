#!/usr/bin/env python3
"""
magic-bytes.py — identify files by signature. For when `file` is wrong or stripped.

usage:
  magic-bytes.py path/to/thing
  magic-bytes.py path/to/thing --scan     # find ALL embedded signatures
"""
import sys


SIGS = [
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff\xe0", "JPEG (JFIF)"),
    (b"\xff\xd8\xff\xe1", "JPEG (Exif)"),
    (b"\xff\xd8\xff\xdb", "JPEG"),
    (b"GIF87a", "GIF87a"),
    (b"GIF89a", "GIF89a"),
    (b"BM", "BMP"),
    (b"II*\x00", "TIFF (LE)"),
    (b"MM\x00*", "TIFF (BE)"),
    (b"RIFF", "RIFF (WAV/AVI/WEBP)"),
    (b"OggS", "OGG"),
    (b"ID3", "MP3 (ID3)"),
    (b"ftyp", "MP4 / MOV (offset 4)"),
    (b"PK\x03\x04", "ZIP / APK / docx / jar"),
    (b"PK\x05\x06", "ZIP (empty)"),
    (b"PK\x07\x08", "ZIP (spanned)"),
    (b"Rar!\x1a\x07\x00", "RAR v1.5+"),
    (b"Rar!\x1a\x07\x01\x00", "RAR v5"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"\x1f\x8b\x08", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"\x75\x73\x74\x61\x72", "TAR (offset 257)"),
    (b"%PDF", "PDF"),
    (b"%!PS", "PostScript"),
    (b"{\\rtf", "RTF"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "MS OLE (doc/xls/ppt/msi)"),
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "DOS/PE binary"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat / Java class"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit (BE)"),
    (b"-----BEGIN", "PEM-encoded block"),
    (b"SQLite format 3\x00", "SQLite3 DB"),
    (b"\x53\x51\x4c\x69\x74\x65", "SQLite"),
    (b"TZif", "tzdata"),
    (b"CWS", "SWF compressed"),
    (b"FWS", "SWF uncompressed"),
    (b"BPG\xfb", "BPG"),
    (b"\x00asm", "WebAssembly"),
    (b"OTTO", "OpenType font"),
    (b"ttcf", "TrueType collection"),
    (b"\x00\x01\x00\x00\x00", "TrueType font"),
    (b"wOFF", "WOFF"),
    (b"wOF2", "WOFF2"),
]


def identify(data: bytes):
    hits = []
    for sig, name in SIGS:
        if data.startswith(sig):
            hits.append((0, name, sig))
    return hits


def scan(data: bytes):
    hits = []
    for sig, name in SIGS:
        off = 0
        while True:
            i = data.find(sig, off)
            if i < 0:
                break
            hits.append((i, name, sig))
            off = i + 1
    hits.sort()
    return hits


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    data = open(sys.argv[1], "rb").read()
    if "--scan" in sys.argv:
        hits = scan(data)
        if not hits:
            print("no known signatures found")
            return
        for off, name, sig in hits:
            print(f"  0x{off:08x}  {name:28s}  sig={sig[:10].hex()}")
    else:
        hits = identify(data)
        if not hits:
            print("unknown — try --scan for embedded signatures")
            return
        for _, name, _ in hits:
            print(name)


if __name__ == "__main__":
    main()
