#!/usr/bin/env python3
"""stego-wav.py — extract LSB-encoded data from a WAV file. Stdlib only.

usage:
  stego-wav.py <path.wav>                    # try 1,2,3,4 LSBs; show best
  stego-wav.py <path.wav> --bits 2           # force N LSBs per sample
  stego-wav.py <path.wav> --channel 0        # pick a specific channel (stereo wavs)
  stego-wav.py <path.wav> -o out.bin         # write raw decoded bytes
"""
import argparse, wave, sys


def extract(path: str, bits: int, channel: int | None) -> bytes:
    with wave.open(path, "rb") as w:
        n_ch   = w.getnchannels()
        sw     = w.getsampwidth()
        frames = w.readframes(w.getnframes())

    # one sample = sw bytes * n_ch
    sample_size = sw * n_ch
    out_bits = []
    mask = (1 << bits) - 1

    for i in range(0, len(frames), sample_size):
        for ch in range(n_ch):
            if channel is not None and ch != channel: continue
            start = i + ch * sw
            sample = int.from_bytes(frames[start:start+sw], "little", signed=(sw > 1))
            v = sample & mask
            out_bits.append(f"{v:0{bits}b}")
    bit_str = "".join(out_bits)
    n = len(bit_str) - (len(bit_str) % 8)
    return bytes(int(bit_str[i:i+8], 2) for i in range(0, n, 8))


def printable_ratio(b: bytes) -> float:
    if not b: return 0.0
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b)


def preview(b: bytes, n: int = 120) -> str:
    s = b.decode("utf-8", errors="replace").replace("\n", "\\n")
    return s[:n] + ("…" if len(s) > n else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--bits", type=int, help="N LSBs per sample (1..4). Default: try all.")
    ap.add_argument("--channel", type=int, help="specific channel index (0, 1, ...)")
    ap.add_argument("-o", "--out", help="write decoded bytes to this file")
    args = ap.parse_args()

    with wave.open(args.path, "rb") as w:
        print(f"input: {args.path}")
        print(f"  channels={w.getnchannels()}  sampwidth={w.getsampwidth()}B  "
              f"framerate={w.getframerate()}  frames={w.getnframes()}")
    print()

    if args.bits:
        d = extract(args.path, args.bits, args.channel)
        print(f"[{args.bits}-bit LSB]  {len(d)} bytes  printable={printable_ratio(d)*100:.0f}%")
        print(f"  {preview(d, 2000)}")
        if args.out:
            open(args.out, "wb").write(d); print(f"\nwrote → {args.out}")
        return

    results = []
    for b in (1, 2, 3, 4):
        try: d = extract(args.path, b, args.channel)
        except Exception as e: print(f"  {b}-bit: error {e}"); continue
        results.append((b, d))
        print(f"  {b}-bit LSB  {len(d):>8} bytes  printable={printable_ratio(d)*100:3.0f}%  {preview(d, 100)}")

    if args.out and results:
        best = max(results, key=lambda kv: printable_ratio(kv[1]))
        open(args.out, "wb").write(best[1])
        print(f"\nwrote best ({best[0]}-bit) → {args.out}")


if __name__ == "__main__":
    main()
