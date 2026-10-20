# Recon & Enumeration

Common tools: nmap (+ ncat / nping), rustscan, Subfinder,
ffuf, Gobuster, Feroxbuster, Katana, curl, wget, OpenSSL, Hydra, searchsploit
(offline). Online recon services (Shodan, Censys) are **not permitted** during
the event.

## Network

```bash
# Fast top-1000 TCP
nmap -T4 -F $TARGET

# Full TCP, versions, default scripts
nmap -T4 -p- -sV -sC -oN nmap-full.txt $TARGET

# UDP top-100 (slow)
sudo nmap -sU --top-ports 100 $TARGET

# Rustscan (faster alt): hand off ports to nmap for versioning
rustscan -a $TARGET -r 1-65535 --ulimit 5000 -- -sV -sC
```

## Web

### Directory busting

```bash
# ffuf — fast, flexible
ffuf -u http://$TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403 -ac

# gobuster
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak -t 50

# Recursive with raft
ffuf -u http://$TARGET/FUZZ -w ~/wordlists/raft-medium-directories.txt -recursion -recursion-depth 2
```

### Vhost / subdomain

```bash
# Vhost (same IP, different Host header)
ffuf -u http://$TARGET -H "Host: FUZZ.$DOMAIN" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
     -fs <baseline-size>

# Subdomain brute via Subfinder (approved)
subfinder -d $DOMAIN -all
```

### Parameter discovery

```bash
# ffuf against a param-name wordlist
ffuf -u "http://$TARGET/endpoint?FUZZ=test" \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -fs <baseline>

# Or use Burp Suite's intruder / param miner
```

### Fingerprinting

```bash
curl -I http://$TARGET
curl -s http://$TARGET | head -40           # look at <head> for CMS fingerprints
openssl s_client -connect $TARGET:443 -servername $TARGET </dev/null 2>&1 | openssl x509 -noout -subject -issuer -ext subjectAltName

# Crawl for every linked path
katana -u http://$TARGET -silent -o katana.txt
```

## DNS

```bash
dig +short $DOMAIN any
dig +short txt $DOMAIN
dig +short mx  $DOMAIN
# Note: online services like crt.sh / wayback are generally NOT permitted
# during the event — rely on Subfinder + nmap + what's reachable from the VM.
```

## Offline wordlists & templates

```bash
ls /usr/share/wordlists/                       # includes rockyou.txt
ls /usr/share/seclists/Discovery/              # web / DNS / usernames
ls /opt/tools/PayloadsAllTheThings/            # payload reference
```

## Default creds to try

```
admin:admin  admin:password  admin:changeme
root:root    root:toor       root:password
tomcat:tomcat  manager:manager
guest:guest  test:test
```

Check `/robots.txt`, `/sitemap.xml`, `/.git/HEAD`, `/.env`, `/backup.zip`, `/phpinfo.php`, `/server-status`, `/admin`, `/api/`.
