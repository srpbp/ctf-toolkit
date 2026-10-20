#!/usr/bin/env bash
# replay.sh — replay a raw HTTP request from a file.
#
# usage: replay.sh request.txt [https://optional-override-host]
#
# Request file format (Burp-style raw):
#   GET /path HTTP/1.1
#   Host: target.com
#   User-Agent: ...
#   <blank line>
#   <optional body>

set -eu

REQ="${1:-}"
OVERRIDE="${2:-}"
if [[ -z "$REQ" || ! -f "$REQ" ]]; then
    echo "usage: $0 request.txt [https://host]"
    exit 1
fi

# split header / body on first blank line
HEADER=$(awk 'NR==1 || /./' "$REQ")
BODY=$(awk 'f;/^$/{f=1}' "$REQ")

read -r METHOD PATH_ HTTP <<<"$(head -1 "$REQ" | tr -d '\r')"
HOST=$(grep -i '^Host:' "$REQ" | head -1 | awk '{print $2}' | tr -d '\r')

if [[ -n "$OVERRIDE" ]]; then
    URL="$OVERRIDE$PATH_"
else
    URL="http://$HOST$PATH_"
fi

# Collect headers (skip request line & empty)
HDR_ARGS=()
while IFS= read -r line; do
    line="${line%$'\r'}"
    [[ -z "$line" ]] && break
    [[ "$line" =~ ^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\  ]] && continue
    HDR_ARGS+=("-H" "$line")
done < "$REQ"

echo "[*] $METHOD $URL"
if [[ -n "$BODY" ]]; then
    curl -sk -i -X "$METHOD" "${HDR_ARGS[@]}" --data-binary "$BODY" "$URL"
else
    curl -sk -i -X "$METHOD" "${HDR_ARGS[@]}" "$URL"
fi
