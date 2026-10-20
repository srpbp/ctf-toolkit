#!/usr/bin/env bash
# pcap-triage.sh — fast overview of a pcap plus common extractions.
#
# usage: pcap-triage.sh capture.pcap

set -u

P="${1:-}"
if [[ -z "$P" || ! -f "$P" ]]; then
    echo "usage: $0 capture.pcap"
    exit 1
fi

OUT="pcap-$(basename "$P" .pcap)-out"
mkdir -p "$OUT"

say() { echo; echo "=== $* ==="; }

say "capinfos"
capinfos "$P" || true

say "protocol hierarchy"
tshark -r "$P" -q -z io,phs 2>/dev/null | sed -n '1,30p'

say "TCP conversations (top 15)"
tshark -r "$P" -q -z conv,tcp 2>/dev/null | sed -n '1,20p'

say "endpoints"
tshark -r "$P" -q -z endpoints,ip 2>/dev/null | sed -n '1,15p'

say "DNS queries"
tshark -r "$P" -Y 'dns.qry.name' -T fields -e dns.qry.name 2>/dev/null | sort -u | tee "$OUT/dns.txt" | head -20

say "HTTP hosts + URIs"
tshark -r "$P" -Y 'http.request' -T fields -e http.host -e http.request.uri 2>/dev/null | sort -u | tee "$OUT/http-uris.txt" | head -20

say "User-Agents"
tshark -r "$P" -Y 'http.user_agent' -T fields -e http.user_agent 2>/dev/null | sort -u | head

say "likely credentials in cleartext protocols"
{
  echo "## http.authorization"
  tshark -r "$P" -Y 'http.authorization' -T fields -e http.authorization 2>/dev/null
  echo
  echo "## ftp USER / PASS"
  tshark -r "$P" -Y 'ftp.request.command == "USER" or ftp.request.command == "PASS"' \
      -T fields -e ftp.request.command -e ftp.request.arg 2>/dev/null
  echo
  echo "## telnet (raw)"
  tshark -r "$P" -Y 'telnet' --raw 2>/dev/null | head -40
} | tee "$OUT/creds.txt" | head -40

say "export objects (http)"
tshark -r "$P" --export-objects http,"$OUT/http" 2>/dev/null
ls "$OUT/http" 2>/dev/null | head

say "USB HID candidates (bytes)"
tshark -r "$P" -Y 'usb.capdata' -T fields -e usb.capdata 2>/dev/null | tee "$OUT/usb-capdata.txt" | wc -l

say "ascii strings in packets (first 50 chars)"
tshark -r "$P" -Y 'frame' -T fields -e data.data 2>/dev/null | head -20

say "search for 'flag'"
tshark -r "$P" -Y 'frame contains "flag"' 2>/dev/null | head
echo
echo "[*] done -> $OUT/"
