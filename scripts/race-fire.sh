#!/usr/bin/env bash
# race-fire.sh — fire N parallel copies of a curl command to probe race conditions.
#
# usage: race-fire.sh <count> -- curl [curl args ...]
#
# Example (buy an item 20 times in parallel):
#   ./race-fire.sh 20 -- -s -X POST 'http://target/buy' -b 'session=...' -d 'id=1'
#
# Prints each response's status + size + time, sorted by time of completion.

set -u

if [[ $# -lt 3 ]] || [[ "$2" != "--" ]]; then
    echo "usage: $0 <count> -- <curl args>"
    exit 1
fi

COUNT="$1"
shift 2

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for i in $(seq 1 "$COUNT"); do
    (
        curl -sk -o "$tmp/$i.body" \
             -w "%{time_starttransfer} %{http_code} %{size_download}\n" \
             "$@" > "$tmp/$i.meta"
    ) &
done

wait

echo "idx  start       code  size"
for i in $(seq 1 "$COUNT"); do
    read -r t code size <"$tmp/$i.meta"
    printf "%3d  %-10s  %-4s  %s\n" "$i" "$t" "$code" "$size"
done | sort -k2 -n
