#!/usr/bin/env bash
# enum-web.sh — opinionated web enum: dirs + vhosts + headers + robots.
#
# usage: enum-web.sh https://target [wordlist]

set -eu

TARGET="${1:-}"
WL="${2:-/usr/share/wordlists/dirb/common.txt}"
OUT="enum-$(echo "$TARGET" | sed 's|https\?://||; s|[/:]|_|g')"
mkdir -p "$OUT"

if [[ -z "$TARGET" ]]; then
    echo "usage: $0 https://target [wordlist]"
    exit 1
fi

need() { command -v "$1" >/dev/null 2>&1 || echo "warn: $1 missing"; }
for b in curl ffuf; do need "$b"; done

echo "[*] headers -> $OUT/headers.txt"
curl -sIkL "$TARGET" | tee "$OUT/headers.txt" >/dev/null

echo "[*] robots/sitemap -> $OUT/"
curl -sk "$TARGET/robots.txt"  > "$OUT/robots.txt"  || true
curl -sk "$TARGET/sitemap.xml" > "$OUT/sitemap.xml" || true

echo "[*] common sensitive paths"
for p in .git/HEAD .env .DS_Store backup.zip phpinfo.php server-status .htaccess api/ admin/ login .vscode/sftp.json; do
    code=$(curl -sko /dev/null -w "%{http_code}" "$TARGET/$p")
    [[ "$code" != "404" ]] && echo "    $code  $TARGET/$p" | tee -a "$OUT/sensitive.txt"
done

if command -v ffuf >/dev/null 2>&1; then
    echo "[*] ffuf dir brute (wordlist=$WL) -> $OUT/ffuf.json"
    ffuf -u "$TARGET/FUZZ" -w "$WL" -mc 200,204,301,302,307,401,403 -ac \
         -of json -o "$OUT/ffuf.json" -s | tee "$OUT/ffuf.txt" >/dev/null
fi

if command -v katana >/dev/null 2>&1; then
    echo "[*] katana crawl -> $OUT/katana.txt"
    katana -u "$TARGET" -silent > "$OUT/katana.txt" 2>/dev/null || true
fi

if command -v subfinder >/dev/null 2>&1; then
    host=$(echo "$TARGET" | sed 's|https\?://||; s|/.*||; s|:.*||')
    if [[ "$host" == *.* ]]; then
        echo "[*] subfinder for $host -> $OUT/subfinder.txt"
        subfinder -d "$host" -silent > "$OUT/subfinder.txt" 2>/dev/null || true
    fi
fi

echo "[*] done — results in $OUT/"
