#!/usr/bin/env python3
"""
xor-crack.py — crack single-byte XOR and repeating-key XOR via frequency.

usage:
  xor-crack.py single <hex>              # try all 256 keys, show best
  xor-crack.py single-file <path>        # same, binary file
  xor-crack.py keylen  <hex> [max=40]    # guess repeating-key length (hamming/IC)
  xor-crack.py repeat  <hex> <keylen>    # extract repeating key of given length
"""
import sys


# frequency score: common English letters, space heavy
_WEIGHT = {b" ": 15.0}
for c, w in zip(b"etaoinshrdlu", [12, 9, 8, 7, 7, 7, 6, 6, 6, 4, 4, 3]):
    _WEIGHT[c] = w


def score(buf: bytes) -> float:
    s = 0.0
    for b in buf:
        if 32 <= b < 127:
            s += _WEIGHT.get(b | 0x20, 1.0)
        elif b in (9, 10, 13):
            s += 1
        else:
            s -= 5
    return s


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ b[i % len(b)] for i, x in enumerate(a))


def single_byte(ct: bytes, top: int = 3):
    cands = []
    for k in range(256):
        pt = bytes(b ^ k for b in ct)
        cands.append((score(pt), k, pt))
    cands.sort(reverse=True)
    for sc, k, pt in cands[:top]:
        preview = pt[:120].decode(errors="replace").replace("\n", " ")
        print(f"  score={sc:>8.1f}  key=0x{k:02x}  {preview}")


def hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_keylen(ct: bytes, max_k: int = 40, top: int = 5):
    scores = []
    for k in range(2, min(max_k, len(ct) // 4) + 1):
        blocks = [ct[i * k:(i + 1) * k] for i in range(min(8, len(ct) // k))]
        pairs = [(blocks[i], blocks[j]) for i in range(len(blocks)) for j in range(i + 1, len(blocks))]
        if not pairs:
            continue
        norm = sum(hamming(a, b) for a, b in pairs) / (len(pairs) * k)
        scores.append((norm, k))
    scores.sort()
    print("  normalized hamming distance (lower=better):")
    for norm, k in scores[:top]:
        print(f"    keylen={k:>3}  score={norm:.3f}")


def repeat_key(ct: bytes, keylen: int):
    key = bytearray()
    for i in range(keylen):
        col = bytes(ct[j] for j in range(i, len(ct), keylen))
        best = max(range(256), key=lambda k: score(bytes(b ^ k for b in col)))
        key.append(best)
    pt = xor_bytes(ct, key)
    print(f"  key: {key.hex()}   ({key.decode(errors='replace')!r})")
    print(f"  pt:  {pt[:200].decode(errors='replace')}")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "single":
        single_byte(bytes.fromhex(sys.argv[2]))
    elif cmd == "single-file":
        single_byte(open(sys.argv[2], "rb").read())
    elif cmd == "keylen":
        mx = int(sys.argv[3]) if len(sys.argv) > 3 else 40
        guess_keylen(bytes.fromhex(sys.argv[2]), mx)
    elif cmd == "repeat":
        repeat_key(bytes.fromhex(sys.argv[2]), int(sys.argv[3]))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
