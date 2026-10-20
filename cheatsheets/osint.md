# OSINT

> Many CTFs ban online analysis services (VirusTotal, CrackStation, dehashed,
> Shodan, holehe, etc.). The OSINT verbs that work offline on a typical Kali
> VM are: ExifTool (image/doc metadata), pdftotext, Subfinder (DNS), curl /
> OpenSSL (certs), offline SecLists / PayloadsAllTheThings. Treat the rest of
> this file as pre-event prep / defensive-sim reference.

## Mindset

Pivot from one data point to the next: handle → real name → email → breach data → social → location → employer → tech stack.

Keep a target.md with everything you find — half the game is correlation.

## Google dorks

```
site:target.com                        # all indexed pages
site:*.target.com -www                 # subdomains
inurl:admin  site:target.com
intitle:"index of"  site:target.com    # directory listings
filetype:pdf   site:target.com
filetype:env OR filetype:yml OR filetype:ini  site:target.com
intext:"BEGIN RSA PRIVATE KEY"  site:target.com
"@target.com"  site:pastebin.com
"@target.com"  site:github.com
```

Github dorks (classic leak surfaces):
```
"api_key"       user:TARGET
"BEGIN RSA"     user:TARGET
"password"      filename:.env
"TARGET_API"    extension:yml
"authorization: bearer"  org:TARGET
```

Searching old content:
- `cache:` keyword in Google (deprecated but try Bing).
- `web.archive.org/web/*/target.com/*` — wayback.
- `cachedview.com`.

## People

| Starting point | Pivot to |
|---|---|
| Handle | sherlock, namechk → list of platforms using same handle |
| Email | haveibeenpwned, dehashed, holehe → services the email registered at |
| Phone | truecaller, Phoneinfoga, phonenumbers (lib) |
| Face / photo | yandex > google > tineye for reverse image search |
| Name + city | pipl, whitepages, voter rolls, LinkedIn |
| Username | WhatsMyName.app |

```bash
sherlock username
holehe email@target.com
h8mail -t email@target.com -c config.ini      # breach data (needs API keys)
```

## Domain / infra

```bash
whois target.com
dig +short target.com any
dig +short target.com ns
dig txt target.com

# Cert transparency (subdomain goldmine)
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Shodan (needs API)
shodan search 'hostname:target.com'
shodan host 1.2.3.4

# Censys
censys search 'target.com'

# Favicon hash to find other hosts running same site
# https://github.com/devanshbatham/FavFreak
```

Reverse-IP (what else lives on this box):
- `viewdns.info/reverseip`
- `securitytrails.com`
- `shodan.io` host page

## Image EXIF (people's photos)

```bash
exiftool photo.jpg | grep -iE 'gps|date|device|owner|camera'
```

Even stripped photos leak via: visible background (streetview reverse-lookup), language of signs, time-of-day shadow angle (sunearthtools.com shadow calc), aircraft contrails (adsb history), weather on date (wunderground history).

## Social

- LinkedIn: X-ray via Google — `site:linkedin.com/in "Software Engineer" "TargetCo"`.
- Twitter advanced search: `from:handle since:2024-01-01 until:2024-01-31`.
- Instagram: `instaloader -L user profile` (archive).
- Facebook graph search mostly dead; try `inteltechniques.com/tools`.

Deleted content: wayback, archive.today, nitter (twitter mirror), teddit.

## Business / money

- OpenCorporates — company registrations.
- SEC EDGAR for US filings.
- Companies House (UK), Pappers (FR), etc.
- LinkedIn company pages → employee count, hire velocity.
- `builtwith.com` — tech stack.

## Images: reverse search beyond Google

Order of effectiveness for people/places:
1. **Yandex** — strongest for faces, Eastern European sites.
2. **Baidu** — Chinese sources.
3. **Google Images** — generic.
4. **TinEye** — exact matches, finds earliest upload.

## Metadata on documents

```bash
exiftool doc.pdf     doc.docx     slides.pptx
# Scrape doc metadata at scale:
./FOCA / metagoofil -d target.com -t pdf,docx -l 50 -n 50 -o out/
```

## Breach data

- HIBP (haveibeenpwned.com) — presence check, no plaintext.
- `dehashed.com` — paid, actual plaintext/hashes.
- `scylla.sh` and successors — rotate periodically.
- `IntelX.io` — pastes + leaks + archives.

Keep this ethical: breach data pivots are useful for defensive sim and ctf, but misuse crosses legal lines fast.

## Tools roundup

```
sherlock / maigret         — username enum across sites
holehe                     — email → account presence
amass / subfinder          — subdomains
spiderfoot                 — all-in-one, GUI
osintgram                  — IG posts/followers/metadata
twint                      — twitter scraper (broken intermittently)
WhatsMyName (web)          — handle enum
IntelOwl                   — pluggable OSINT platform
```

## Workflow template

```
# target.md
## Identity
- handles: 
- real name: 
- aliases: 

## Contact
- emails: 
- phones: 
- addresses: 

## Infrastructure
- domains: 
- IPs: 
- certs: 

## Social
- platforms + urls: 

## Breaches
- hibp hits: 
- plaintexts found: 

## Open questions
- 
```
