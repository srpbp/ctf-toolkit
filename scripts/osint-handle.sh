#!/usr/bin/env bash
# osint-handle.sh — probe common sites for a username.
#
# usage: osint-handle.sh <handle>
#
# No external tools required. For deeper searches use `sherlock` or `maigret`.

set -u

H="${1:-}"
if [[ -z "$H" ]]; then
    echo "usage: $0 <handle>"
    exit 1
fi

SITES=(
    "GitHub        https://github.com/$H"
    "GitLab        https://gitlab.com/$H"
    "Twitter       https://twitter.com/$H"
    "Instagram     https://www.instagram.com/$H/"
    "Reddit        https://www.reddit.com/user/$H"
    "HackerNews    https://news.ycombinator.com/user?id=$H"
    "StackOverflow https://stackoverflow.com/users/filter/people?filter=$H"
    "Keybase       https://keybase.io/$H"
    "Medium        https://medium.com/@$H"
    "Pinterest     https://www.pinterest.com/$H/"
    "Steam         https://steamcommunity.com/id/$H"
    "YouTube       https://www.youtube.com/@$H"
    "TikTok        https://www.tiktok.com/@$H"
    "Twitch        https://www.twitch.tv/$H"
    "DEV           https://dev.to/$H"
    "Codeberg      https://codeberg.org/$H"
    "HackTheBox    https://app.hackthebox.com/profile/$H"
    "TryHackMe     https://tryhackme.com/p/$H"
    "LinkedIn      https://www.linkedin.com/in/$H"
    "AboutMe       https://about.me/$H"
    "LeetCode      https://leetcode.com/$H"
)

echo "[*] probing $H across ${#SITES[@]} sites"
for row in "${SITES[@]}"; do
    name="${row%% *}"
    url="${row##* }"
    code=$(curl -sko /dev/null -w "%{http_code}" -A "Mozilla/5.0" -m 5 "$url")
    case "$code" in
        200) echo "  [+] $name    $url"            ;;
        301|302) echo "  [?] $name  (redirect)  $url"   ;;
        403) echo "  [?] $name  (blocked by site)   $url"  ;;
        404) : ;;
        *)   echo "  [-] $name  http $code  $url"  ;;
    esac
done

echo
echo "[*] Note: this script only issues direct HTTP(S) requests to the sites a"
echo "    username might live on — no aggregators or online analysis services."
