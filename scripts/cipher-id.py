#!/usr/bin/env python3
"""cipher-id.py — identify + decode ~35 classical/modern ciphers. Pure stdlib.

usage:
  cipher-id.py '<ct>'                              # list candidates with confidence
  cipher-id.py --try '<ct>'                        # also decode each candidate
  cipher-id.py --chain '<ct>'                      # recursively peel wrappers
  cipher-id.py --only base64,hex '<ct>'            # restrict
  cipher-id.py --cipher vigenere --key LEMON '<ct>'
  cipher-id.py --cipher xor-single '<hex|raw>'     # bruteforce single-byte XOR
  cipher-id.py --list
Keyed: vigenere, gronsfeld, beaufort, autokey, playfair, columnar, xor.
Brute: xor-single, xor-repeating.
"""
import argparse, base64, codecs, html, re, sys, urllib.parse
from collections import Counter

# ---------- scoring ----------
PRINT = set(range(32, 127)) | {9, 10, 13}
ENG = {"A":8.17,"B":1.49,"C":2.78,"D":4.25,"E":12.70,"F":2.23,"G":2.02,"H":6.09,
       "I":6.97,"J":0.15,"K":0.77,"L":4.03,"M":2.41,"N":6.75,"O":7.51,"P":1.93,
       "Q":0.10,"R":5.99,"S":6.33,"T":9.06,"U":2.76,"V":0.98,"W":2.36,"X":0.15,
       "Y":1.97,"Z":0.07}

def printable(b): return sum(1 for x in b if x in PRINT) / max(len(b), 1)

def eng_score(b):
    try: s = b.decode("utf-8", errors="replace").upper()
    except Exception: return 0.0
    letters = [c for c in s if c.isalpha()]
    if not letters: return 0.0
    n = len(letters); counts = Counter(letters)
    chi = sum((counts.get(L, 0) - ENG[L]*n/100) ** 2 / (ENG[L]*n/100 + 0.1) for L in ENG)
    return min(s.count(" ")/len(s), 0.2) * 50 - chi/10

def ioc(s):
    s = "".join(c for c in s.upper() if c.isalpha())
    if len(s) < 2: return 0.0
    f = Counter(s)
    return sum(c*(c-1) for c in f.values()) / (len(s)*(len(s)-1))

def preview(b, n=100):
    if isinstance(b, str): b = b.encode()
    s = b.decode("utf-8", errors="replace").replace("\n", "\\n").replace("\r", "")
    return s[:n] + ("…" if len(s) > n else "")

def strip_ws(s): return re.sub(r"\s+", "", s)

# ---------- shift-cipher engine (handles 8+ ciphers) ----------
def shift(text, keyfn, reverse=False):
    """keyfn(i, c) -> int shift. reverse=True gives Beaufort/Atbash style."""
    out, i = [], 0
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            k = keyfn(i, c)
            v = (k - (ord(c) - base)) if reverse else (ord(c) - base - k)
            out.append(chr(v % 26 + base)); i += 1
        else: out.append(c)
    return "".join(out).encode()

def key_letters(k):
    k = re.sub(r"[^A-Za-z]", "", k).upper()
    if not k: raise ValueError("letter key required")
    return [ord(c) - ord("A") for c in k]

def key_digits(k):
    k = re.sub(r"[^0-9]", "", k)
    if not k: raise ValueError("digit key required")
    return [int(c) for c in k]

def dec_vigenere(s, k):  K = key_letters(k); return shift(s, lambda i, c: K[i % len(K)])
def dec_gronsfeld(s, k): K = key_digits(k);  return shift(s, lambda i, c: K[i % len(K)])
def dec_beaufort(s, k):  K = key_letters(k); return shift(s, lambda i, c: K[i % len(K)], reverse=True)
def dec_atbash(s):       return shift(s, lambda i, c: 25, reverse=True)
def dec_trithemius(s):   return shift(s, lambda i, c: i)
def dec_rot(s, n):       return shift(s, lambda i, c: n)

def dec_caesar_brute(s):
    best = sorted(((eng_score(dec_rot(s, n)), n) for n in range(26)), reverse=True)
    lines = ["top 3 by English score:"]
    for sc, n in best[:3]:
        lines.append(f"  shift={n:2d}  score={sc:6.1f}  {dec_rot(s, n).decode(errors='replace')}")
    return "\n".join(lines).encode()

def dec_autokey(s, k):
    stream = list(re.sub(r"[^A-Za-z]", "", k).upper())
    out = []
    for c in s:
        if c.isalpha():
            sh = ord(stream.pop(0)) - ord("A")
            base = ord("A") if c.isupper() else ord("a")
            p = chr((ord(c) - base - sh) % 26 + base)
            out.append(p); stream.append(p.upper())
        else: out.append(c)
    return "".join(out).encode()

def dec_affine_brute(s):
    cands = []
    for a in [1,3,5,7,9,11,15,17,19,21,23,25]:
        ai = pow(a, -1, 26)
        pt = "".join(
            chr(ai * (ord(c) - (ord("A") if c.isupper() else ord("a")) - b) % 26
                + (ord("A") if c.isupper() else ord("a"))) if c.isalpha() else c
            for b in [0] for c in s
        )
        for b in range(26):
            pt = "".join(
                chr(ai * (ord(c) - (ord("A") if c.isupper() else ord("a")) - b) % 26
                    + (ord("A") if c.isupper() else ord("a"))) if c.isalpha() else c
                for c in s
            )
            cands.append((eng_score(pt.encode()), a, b, pt))
    cands.sort(reverse=True)
    lines = ["top 3 by English score:"]
    for sc, a, b, pt in cands[:3]:
        lines.append(f"  a={a:2d} b={b:2d}  score={sc:6.1f}  {pt}")
    return "\n".join(lines).encode()

# ---------- base encodings (table-driven) ----------
BASES = {
    "hex":     (lambda s: bytes.fromhex(strip_ws(s)),                                     r"[A-Fa-f0-9\s]+",      lambda s: len(strip_ws(s)) % 2 == 0),
    "b64":     (lambda s: base64.b64decode(strip_ws(s) + "=" * (-len(strip_ws(s)) % 4)),  r"[A-Za-z0-9+/=\s]+",   lambda s: len(strip_ws(s)) % 4 == 0 and len(strip_ws(s)) >= 4),
    "b64url":  (lambda s: base64.urlsafe_b64decode(strip_ws(s) + "=" * (-len(strip_ws(s)) % 4)), r"[A-Za-z0-9_\-=\s]+", lambda s: "_" in s or "-" in s),
    "b32":     (lambda s: base64.b32decode(strip_ws(s).upper() + "=" * (-len(strip_ws(s)) % 8)), r"[A-Z2-7=\s]+", lambda s: len(strip_ws(s)) % 8 == 0),
    "b85":     (lambda s: base64.a85decode(strip_ws(s), adobe=strip_ws(s).startswith("<~")), r"[!-u\s]+", lambda s: "~" in s or strip_ws(s).startswith("<~")),
}

def dec_binary(s): s = strip_ws(s); return int(s, 2).to_bytes(len(s)//8, "big")
def dec_octal(s):  s = strip_ws(s); return bytes(int(s[i:i+3], 8) for i in range(0, len(s), 3))

def dec_b58(s):
    A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for c in strip_ws(s): n = n * 58 + A.index(c)
    nz = len(s) - len(s.lstrip("1"))
    return b"\x00"*nz + (n.to_bytes((n.bit_length()+7)//8, "big") if n else b"")

# ---------- Morse / tables ----------
MORSE = {".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H",
         "..":"I",".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P",
         "--.-":"Q",".-.":"R","...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X",
         "-.--":"Y","--..":"Z","-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",
         ".....":"5","-....":"6","--...":"7","---..":"8","----.":"9",
         ".-.-.-":".","--..--":",","..--..":"?","-.-.--":"!","---...":":","-....-":"-"}

NATO = {"ALPHA":"A","BRAVO":"B","CHARLIE":"C","DELTA":"D","ECHO":"E","FOXTROT":"F","GOLF":"G",
        "HOTEL":"H","INDIA":"I","JULIET":"J","JULIETT":"J","KILO":"K","LIMA":"L","MIKE":"M",
        "NOVEMBER":"N","OSCAR":"O","PAPA":"P","QUEBEC":"Q","ROMEO":"R","SIERRA":"S","TANGO":"T",
        "UNIFORM":"U","VICTOR":"V","WHISKEY":"W","XRAY":"X","YANKEE":"Y","ZULU":"Z",
        "ZERO":"0","ONE":"1","TWO":"2","THREE":"3","FOUR":"4","FIVE":"5","SIX":"6",
        "SEVEN":"7","EIGHT":"8","NINE":"9"}

OOK = {"Ook. Ook?":">","Ook? Ook.":"<","Ook. Ook.":"+","Ook! Ook!":"-",
       "Ook! Ook.":".","Ook. Ook!":",","Ook! Ook?":"[","Ook? Ook!":"]"}

LEET = str.maketrans({"4":"a","3":"e","1":"i","0":"o","7":"t","5":"s","$":"s",
                      "8":"b","9":"g","6":"g","2":"z","+":"t","|":"i","@":"a","!":"i"})

TAP_GRID = ["ABCDE","FGHIK","LMNOP","QRSTU","VWXYZ"]

def dec_morse(s):
    s = s.replace("|", "/").replace("_", "-")
    return " ".join("".join(MORSE.get(c, "?") for c in w.split() if c)
                    for w in re.split(r"\s*/\s*|\s{2,}", s.strip())).encode()

def dec_a1z26(s):
    nums = re.findall(r"\d+", s)
    return "".join(chr(ord("A") + int(n) - 1) if 1 <= int(n) <= 26 else "?" for n in nums).encode()

def dec_nato(s):
    return "".join(NATO.get(w, "") for w in re.findall(r"[A-Z]+", s.upper())).encode()

def dec_leet(s): return s.lower().translate(LEET).encode()

def dec_baconian(s):
    s = s.upper().replace(" ", ""); out = []
    for i in range(0, len(s) - len(s) % 5, 5):
        chunk = s[i:i+5]
        if all(c in "AB" for c in chunk):
            n = int(chunk.replace("A","0").replace("B","1"), 2)
            if n < 26: out.append(chr(ord("A") + n))
    return "".join(out).encode()

def dec_tap(s):
    out = []
    for r, c in re.findall(r"([1-5])\s*([1-5])", s):
        try: out.append(TAP_GRID[int(r)-1][int(c)-1])
        except IndexError: out.append("?")
    return "".join(out).encode()

def dec_t9(s):
    out = []; i = 0; runs = re.findall(r"(\d)\1*|\s+", s)
    for run, _ in [(m.group(), None) for m in re.finditer(r"(\d)\1*|\s+", s)]:
        if not run.strip(): out.append(" "); continue
        tbl = {"2":"ABC","3":"DEF","4":"GHI","5":"JKL","6":"MNO","7":"PQRS","8":"TUV","9":"WXYZ","0":" "}
        d = run[0]
        if d in tbl: out.append(tbl[d][(len(run)-1) % len(tbl[d])])
    return "".join(out).encode()

def dec_brainfuck(s, max_ops=10**6):
    code = re.sub(r"[^+\-<>.,\[\]]", "", s); tape = bytearray(30000); p = ip = 0; out = []
    bm = {}; st = []
    for i, c in enumerate(code):
        if c == "[": st.append(i)
        elif c == "]":
            if not st: return b"<unbalanced>"
            j = st.pop(); bm[i] = j; bm[j] = i
    if st: return b"<unbalanced>"
    ops = 0
    while ip < len(code) and ops < max_ops:
        c = code[ip]
        if c == "+": tape[p] = (tape[p]+1) & 0xFF
        elif c == "-": tape[p] = (tape[p]-1) & 0xFF
        elif c == ">": p = (p+1) % len(tape)
        elif c == "<": p = (p-1) % len(tape)
        elif c == ".": out.append(chr(tape[p]))
        elif c == "[" and tape[p] == 0: ip = bm[ip]
        elif c == "]" and tape[p] != 0: ip = bm[ip]
        ip += 1; ops += 1
    return "".join(out).encode()

def dec_ook(s):
    toks = re.findall(r"Ook[.!?]\s*Ook[.!?]", s)
    return dec_brainfuck("".join(OOK.get(t, "") for t in toks))

def dec_rail_fence_brute(s):
    s = strip_ws(s)
    def dec(ct, r):
        if r < 2: return ct
        n = len(ct); pos = []; rail = step = 1; rail = 0
        for _ in range(n):
            pos.append(rail)
            if rail == 0: step = 1
            elif rail == r-1: step = -1
            rail += step
        counts = [pos.count(x) for x in range(r)]
        chunks = []; off = 0
        for c in counts: chunks.append(list(ct[off:off+c])); off += c
        return "".join(chunks[p].pop(0) for p in pos)
    cands = sorted(((eng_score(dec(s, r).encode()), r, dec(s, r)) for r in range(2, min(11, len(s)))), reverse=True)
    return ("top 3 rail counts:\n" + "\n".join(f"  rails={r:2d}  score={sc:6.1f}  {pt}" for sc, r, pt in cands[:3])).encode()

# ---------- Playfair / Columnar ----------
def dec_playfair(s, k):
    k = re.sub(r"[^A-Z]", "", k.upper()).replace("J", "I")
    seen = []
    for c in k + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in seen: seen.append(c)
    g = [seen[i*5:(i+1)*5] for i in range(5)]
    pos = {c: (r, col) for r, row in enumerate(g) for col, c in enumerate(row)}
    s = re.sub(r"[^A-Z]", "", s.upper()).replace("J", "I")
    out = []; i = 0
    while i < len(s):
        a, b = s[i], s[i+1] if i+1 < len(s) else "X"
        if a == b: b = "X"; i += 1
        else: i += 2
        ra, ca = pos[a]; rb, cb = pos[b]
        if ra == rb: out.append(g[ra][(ca-1)%5] + g[rb][(cb-1)%5])
        elif ca == cb: out.append(g[(ra-1)%5][ca] + g[(rb-1)%5][cb])
        else: out.append(g[ra][cb] + g[rb][ca])
    return "".join(out).encode()

def dec_columnar(s, k):
    s = strip_ws(s); n = len(k.strip())
    order = sorted(range(n), key=lambda i: (k[i], i))
    rows = (len(s) + n - 1) // n
    short = rows * n - len(s)
    heights = [rows - 1 if (n - 1 - i) < short else rows for i in range(n)]
    cols = {}; off = 0
    for idx in order:
        cols[idx] = list(s[off:off+heights[idx]]); off += heights[idx]
    out = []
    for r in range(rows):
        for c in range(n):
            if r < heights[c]: out.append(cols[c].pop(0))
    return "".join(out).encode()

# ---------- XOR ----------
def _xor_input(s):
    s = s.strip()
    return bytes.fromhex(strip_ws(s)) if re.fullmatch(r"[A-Fa-f0-9\s]+", s) else s.encode()

def dec_xor_known(s, k):
    data = _xor_input(s); kb = k.encode()
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))

def dec_xor_single(s):
    data = _xor_input(s)
    cands = sorted(((eng_score(bytes(b^k for b in data)), k) for k in range(256)), reverse=True)
    out = ["top 5 single-byte XOR keys:"]
    for sc, k in cands[:5]:
        pt = bytes(b^k for b in data)
        if printable(pt) < 0.6: continue
        out.append(f"  key=0x{k:02x} ({chr(k) if 32<=k<127 else '?'})  score={sc:5.1f}  {preview(pt, 80)}")
    return "\n".join(out).encode()

def dec_xor_repeating(s, max_keylen=20):
    data = _xor_input(s)
    def ham(a, b): return sum(bin(x^y).count("1") for x, y in zip(a, b))
    def best_byte(col):
        return max(range(256), key=lambda k: eng_score(bytes(b^k for b in col)))
    scores = []
    for L in range(2, min(max_keylen, len(data)//4) + 1):
        blocks = [data[i*L:(i+1)*L] for i in range(min(8, len(data)//L))]
        pairs = [(blocks[i], blocks[j]) for i in range(len(blocks)) for j in range(i+1, len(blocks))]
        if pairs: scores.append((sum(ham(a,b) for a,b in pairs) / (len(pairs)*L), L))
    scores.sort()
    out = ["candidate repeating-key XOR solutions:"]
    for norm, L in scores[:3]:
        key = bytes(best_byte(data[i::L]) for i in range(L))
        pt  = bytes(b ^ key[i % L] for i, b in enumerate(data))
        out.append(f"  keylen={L:2d}  hamm={norm:.3f}  key={key.hex()}  pt={preview(pt, 100)}")
    return "\n".join(out).encode()

# ---------- structural ----------
def dec_jwt(s):
    parts = s.split(".")
    out = []
    for p in parts[:2]:
        try: out.append(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        except Exception: pass
    return b"\n".join(out)

def dec_pem(s):
    body = re.sub(r"\s+", "", re.sub(r"-----(BEGIN|END)[^-]+-----", "", s))
    return base64.b64decode(body)

def dec_url(s):   return urllib.parse.unquote_to_bytes(s)
def dec_html(s):  return html.unescape(s).encode()
def dec_reverse(s): return s[::-1].encode()

# ---------- registries ----------
NOKEY = {
    "hex": lambda s: BASES["hex"][0](s), "binary": dec_binary, "octal": dec_octal,
    "base64": lambda s: BASES["b64"][0](s), "base64url": lambda s: BASES["b64url"][0](s),
    "base32": lambda s: BASES["b32"][0](s), "base58": dec_b58, "base85": lambda s: BASES["b85"][0](s),
    "url": dec_url, "html": dec_html, "jwt": dec_jwt, "pem": dec_pem,
    "morse": dec_morse, "brainfuck": dec_brainfuck, "ook": dec_ook, "baconian": dec_baconian,
    "atbash": dec_atbash, "rot13": lambda s: codecs.decode(s, "rot_13").encode(),
    "rot47": lambda s: "".join(chr(33+(ord(c)-33+47)%94) if 33<=ord(c)<=126 else c for c in s).encode(),
    "caesar": dec_caesar_brute, "affine": dec_affine_brute, "railfence": dec_rail_fence_brute,
    "a1z26": dec_a1z26, "t9": dec_t9, "nato": dec_nato, "leet": dec_leet,
    "trithemius": dec_trithemius, "tap": dec_tap, "reverse": dec_reverse,
}

KEYED = {"vigenere": dec_vigenere, "gronsfeld": dec_gronsfeld, "beaufort": dec_beaufort,
         "autokey": dec_autokey, "playfair": dec_playfair, "columnar": dec_columnar,
         "xor": dec_xor_known}

BRUTE = {"xor-single": dec_xor_single, "xor-repeating": dec_xor_repeating}

# ---------- identify ----------
def identify(text):
    s = text.rstrip("\n"); sc = strip_ws(s); lo = re.sub(r"[^A-Za-z]", "", s)
    out = []
    def add(name, conf, dec, note=""): out.append({"name": name, "conf": conf, "decode": dec, "note": note})

    # structural
    if re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", s):
        add("JWT", 0.95, lambda: dec_jwt(s), "see scripts/jwt.py")
    if "-----BEGIN" in s and "-----END" in s:
        add("PEM block", 0.95, lambda: dec_pem(s))

    # base N — walk the table
    for name, (fn, rx, extra) in BASES.items():
        try:
            if re.fullmatch(rx, s) and extra(s):
                readable = {"hex": "Hex", "b64": "Base64", "b64url": "Base64 URL-safe",
                            "b32": "Base32", "b85": "Base85 / Ascii85"}[name]
                hits = {32:"MD5/NTLM",40:"SHA1",56:"SHA224",64:"SHA256",96:"SHA384",128:"SHA512"}
                if name == "hex" and len(sc) in hits:
                    readable += f" — {hits[len(sc)]}"
                add(readable, 0.75 if name != "hex" or len(sc) not in hits else 0.9, lambda s=s, fn=fn: fn(s))
        except Exception: pass

    if re.fullmatch(r"[01\s]+", s) and len(sc) % 8 == 0 and len(sc) >= 8:
        add("Binary", 0.85, lambda: dec_binary(s))
    if re.fullmatch(r"[0-7\s]+", s) and len(sc) % 3 == 0 and " " in s:
        add("Octal", 0.5, lambda: dec_octal(s))
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", sc) and 20 <= len(sc) <= 100:
        add("Base58", 0.4, lambda: dec_b58(s))
    if "%" in s and re.search(r"%[0-9A-Fa-f]{2}", s):
        add("URL percent-encoding", 0.9, lambda: dec_url(s))
    if re.search(r"&(#x?[0-9A-Fa-f]+|[a-z]+);", s):
        add("HTML entities", 0.9, lambda: dec_html(s))

    # pattern-match ciphers
    if re.fullmatch(r"[.\-/\s|_]+", s) and "." in s and "-" in s:
        add("Morse", 0.95, lambda: dec_morse(s))
    if re.fullmatch(r"[+\-<>.,\[\]\s]+", s) and any(c in s for c in "+<>["):
        add("Brainfuck", 0.9, lambda: dec_brainfuck(s))
    if re.search(r"[Oo]ok", s):
        add("Ook!", 0.9, lambda: dec_ook(s))

    nums = re.findall(r"\d+", s)
    if nums and all(1 <= int(n) <= 26 for n in nums) and re.fullmatch(r"[\d\s/.,;-]+", s):
        add("A1Z26", 0.75, lambda: dec_a1z26(s), "A=1..Z=26")
    if re.fullmatch(r"[0-9\s]+", s) and re.search(r"(\d)\1{1,3}", s):
        add("T9 multi-tap", 0.5, lambda: dec_t9(s))
    if len(re.findall(r"\b(ALPHA|BRAVO|CHARLIE|DELTA|ECHO|FOXTROT|GOLF|HOTEL|INDIA|JULIET|KILO|LIMA|MIKE|NOVEMBER|OSCAR|PAPA|QUEBEC|ROMEO|SIERRA|TANGO|UNIFORM|VICTOR|WHISKEY|YANKEE|ZULU)\b", s.upper())) >= 3:
        add("NATO phonetic", 0.9, lambda: dec_nato(s))
    if re.search(r"[0-9@$!]", s) and lo and len(lo) >= 3:
        add("Leet", 0.3, lambda: dec_leet(s))
    if lo and set(lo.upper()) <= {"A","B"} and len(lo) % 5 == 0 and len(lo) >= 10:
        add("Baconian", 0.9, lambda: dec_baconian(s))
    if len(re.findall(r"\b[1-5]\s*[1-5]\b", s)) >= 3:
        add("Tap code", 0.7, lambda: dec_tap(s))

    # letter-only classical
    if lo and len(lo) >= 6:
        add("ROT13",            0.5, lambda: codecs.decode(s, "rot_13").encode())
        add("Caesar brute",     0.7, lambda: dec_caesar_brute(s))
        add("Atbash",           0.3, lambda: dec_atbash(s))
        add("Affine brute",     0.5, lambda: dec_affine_brute(s))
        add("Trithemius",       0.3, lambda: dec_trithemius(s))
        add("Rail fence brute", 0.5, lambda: dec_rail_fence_brute(s))

        v = ioc(lo)
        if 0.038 < v < 0.055:
            add(f"Polyalphabetic (IC={v:.3f})", 0.5, None,
                "Vigenere/Beaufort/Autokey/Gronsfeld — pass --cipher <name> --key KEY")
        elif v > 0.058:
            add(f"Monoalphabetic sub (IC={v:.3f})", 0.5, None, "Hand-crack by frequency")

    if re.fullmatch(r"[!-~\s]+", s) and any(not c.isalnum() for c in s):
        add("ROT47", 0.3, lambda: NOKEY["rot47"](s))

    add("Reversed string", 0.15, lambda: dec_reverse(s))
    return out

# ---------- driver ----------
def chain(text, depth=0, max_d=5):
    if depth > max_d: return
    cands = sorted((c for c in identify(text) if c["decode"]), key=lambda c: -c["conf"])
    for c in cands[:3]:
        if c["conf"] < 0.65: continue
        try: dec = c["decode"]()
        except Exception: continue
        if not dec or printable(dec) < 0.85: continue
        print("  " * depth + f"└── {c['name']}  →  {preview(dec)}")
        try: chain(dec.decode("utf-8", errors="replace"), depth+1, max_d)
        except Exception: pass
        break

def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("text", nargs="?")
    ap.add_argument("--try", dest="try_", action="store_true")
    ap.add_argument("--chain", action="store_true")
    ap.add_argument("--only")
    ap.add_argument("--cipher"); ap.add_argument("--key")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("-h", "--help", action="store_true")
    a = ap.parse_args()

    if a.help or (not a.text and not a.list and sys.stdin.isatty()):
        print(__doc__); return
    if a.list:
        print("keyless:"); [print(f"  {n}") for n in sorted(NOKEY)]
        print("\nkeyed (--key):"); [print(f"  {n}") for n in sorted(KEYED)]
        print("\nbrute:"); [print(f"  {n}") for n in sorted(BRUTE)]
        return

    text = a.text if a.text and a.text != "-" else sys.stdin.read()
    text = text.rstrip("\n")

    if a.cipher:
        c = a.cipher.lower()
        try:
            if c in NOKEY: out = NOKEY[c](text)
            elif c in KEYED:
                if not a.key: sys.exit(f"{c} needs --key")
                out = KEYED[c](text, a.key)
            elif c in BRUTE: out = BRUTE[c](text)
            else: sys.exit(f"unknown cipher: {c}  (--list)")
        except Exception as e: sys.exit(f"error: {e}")
        print(preview(out, 4000)); return

    if a.chain:
        print(f"input: {preview(text)}"); chain(text); return

    cands = sorted(identify(text), key=lambda c: -c["conf"])
    if a.only:
        want = [w.strip().lower() for w in a.only.split(",")]
        cands = [c for c in cands if any(w in c["name"].lower() for w in want)]

    print(f"input: {preview(text)}\n\n{len(cands)} candidate(s):")
    for c in cands:
        print(f"  [{c['conf']:.2f}]  {c['name']}")
        if c["note"]: print(f"           note: {c['note']}")
        if a.try_ and c["decode"]:
            try:
                d = c["decode"]()
                if isinstance(d, str): d = d.encode()
                print(f"           dec:  {preview(d)}")
                if printable(d) >= 0.85: print(f"           english: {eng_score(d):.1f}")
            except Exception as e: print(f"           dec:  <error: {e}>")


if __name__ == "__main__":
    main()
