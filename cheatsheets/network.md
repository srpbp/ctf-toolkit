# Network & PCAP

Common tools: Wireshark + tshark, tcpdump, Zeek, Nmap,
aircrack-ng, hcxtools, can-utils, cannelloni, socat, OpenSSL, Impacket.

## Capture

```bash
# Live capture (needs root or BPF perms)
sudo tcpdump -i en0 -w live.pcap
sudo tcpdump -i en0 'tcp port 80 or tcp port 443' -w http.pcap -s0

# Rotate
sudo tcpdump -i en0 -w cap_%Y%m%d_%H%M%S.pcap -G 300 -s0

# Decrypt TLS with SSLKEYLOGFILE
SSLKEYLOGFILE=/tmp/keys.log firefox &
wireshark   # Preferences → Protocols → TLS → (Pre)-Master-Secret log
```

## Overview

```bash
capinfos capture.pcap
tshark -r capture.pcap -q -z io,phs                   # protocol hierarchy
tshark -r capture.pcap -q -z conv,tcp                 # TCP conversations
tshark -r capture.pcap -q -z endpoints,ip
tshark -r capture.pcap -q -z http,tree
```

## Filters cheat (Wireshark display)

```
http.request                        # HTTP requests
http.response.code == 500           # 500s only
http.request.method == "POST"
http.request.uri contains "login"
http.authorization                  # auth headers
http contains "password"
tcp.stream eq 3                     # one TCP flow
ip.src == 10.0.0.5 and tcp.port == 445
dns.qry.name contains "flag"
tls.handshake.extensions_server_name
usb.capdata                         # USB HID captures (keystrokes)
```

Capture filter (BPF, different syntax):
```
tcp port 80
host 10.0.0.5
not port 22
```

## Follow / extract

```bash
# Follow a stream (0-indexed)
tshark -r cap.pcap -q -z follow,tcp,ascii,3

# Export objects
tshark -r cap.pcap --export-objects http,out-http/
tshark -r cap.pcap --export-objects smb,out-smb/
tshark -r cap.pcap --export-objects ftp-data,out-ftp/

# All HTTP URIs
tshark -r cap.pcap -Y http.request -T fields -e http.host -e http.request.uri

# Extract specific field (e.g. all form data)
tshark -r cap.pcap -Y 'http.request.method == "POST"' -T fields -e http.file_data
```

## Credentials from pcap

```bash
# tshark extracts creds for most unencrypted protocols:
tshark -r cap.pcap -Y 'http.authorization' -T fields -e http.authorization
tshark -r cap.pcap -Y 'ftp.request.command == "USER" or ftp.request.command == "PASS"' \
    -T fields -e ftp.request.command -e ftp.request.arg
tshark -r cap.pcap -Y 'telnet' --raw
# NTLM / Kerberos: Impacket helpers can parse hashes once extracted
```

Impacket (approved) parses NTLM/Kerb once you've pulled the raw messages.

## Protocol-specific

### DNS exfil

Signals: many unique long subdomains to one authoritative server; TXT lookups to oddball domain.
```bash
tshark -r cap.pcap -Y 'dns.qry.name' -T fields -e dns.qry.name | sort -u
# decode base32/hex concat
tshark -r cap.pcap -Y 'dns' -T fields -e dns.qry.name | \
  awk -F. '{print $1}' | tr -d '\n' | base32 -d
```

### ICMP exfil

```bash
tshark -r cap.pcap -Y 'icmp.type == 8' -T fields -e data.data
```

### HTTP covert

- Check odd header values, cookies with suspicious entropy.
- `User-Agent` encodes bytes; `Referer` carries chunks.

### USB HID keystrokes

Map USB capdata bytes → keys. Scripts in `scripts/usb-keystrokes.py`.

### TLS

```bash
# Server names seen
tshark -r cap.pcap -Y 'tls.handshake.type == 1' \
  -T fields -e tls.handshake.extensions_server_name | sort -u

# JA3: not on the common approved list. Extract the ClientHello ciphers / extensions /
# curves with tshark and compute MD5 of the concat if a challenge needs it.
```

### Wireless (802.11)

```bash
# Convert pcap → hashcat 22000
hcxpcapngtool -o hash.22000 cap.pcapng
hashcat -m 22000 hash.22000 rockyou.txt
```

## Crafting

```bash
# nping (ships with nmap, approved)
sudo nping --tcp -p 80 --flags syn 10.0.0.1

# scapy via Python (install under uv if not already present)
python3 -c "from scapy.all import *; sendp(Ether()/IP(dst='10.0.0.1')/ICMP())"
```

(hping3, Responder, dnschef are not on the common approved list — skip them.)

## Replay a request

See `scripts/replay.sh` — reads a raw request file and fires it with curl.

## Lab helpers

```bash
# Serve a quick HTTP server for file capture testing
python3 -m http.server 8000

# socat relay / listener
socat -v TCP-LISTEN:9999,fork,reuseaddr TCP:remote:1234
```
