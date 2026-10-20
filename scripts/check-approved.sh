#!/usr/bin/env bash
# check-approved.sh — verify which common CTF tools are present.
#
# Reports installed / missing / version mismatch for each CLI we expect.
# Run this on the Kali AWS VM (or Windows WSL) first thing to confirm the
# environment is as advertised.

set -u

# Format: "bin_name|category|optional_version_flag"
TOOLS=(
    # Web
    "sqlmap|web|--version"
    "ffuf|web|-V"
    "gobuster|web|version"
    "feroxbuster|web|--version"
    "katana|web|-version"
    "subfinder|web|-version"
    "hydra|web|-h"
    "jwt_tool|web|"
    "nmap|web|--version"
    "msfconsole|web|--version"
    "impacket-GetUserSPNs|web|-h"

    # Crypto
    "hashcat|crypto|--version"
    "john|crypto|--version"
    "hashid|crypto|--version"
    "openssl|crypto|version"
    "bkcrack|crypto|--version"
    "sage|crypto|--version"
    "gp|crypto|--version"
    "RsaCtfTool|crypto|-h"

    # Forensic
    "autopsy|forensic|-h"
    "fls|forensic|-V"
    "icat|forensic|-V"
    "vol|forensic|--help"
    "foremost|forensic|-V"
    "bulk_extractor|forensic|-V"
    "testdisk|forensic|/version"
    "exiftool|forensic|-ver"
    "chainsaw|forensic|--version"
    "hayabusa|forensic|-h"
    "rip.pl|forensic|"
    "regripper|forensic|"
    "log2timeline.py|forensic|--version"
    "psort.py|forensic|--version"
    "pdfid.py|forensic|-h"
    "pdf-parser.py|forensic|-h"
    "olevba|forensic|--version"
    "peepdf-3|forensic|-h"
    "pyhindsight|forensic|--version"
    "qpdf|forensic|--version"
    "mutool|forensic|-v"

    # Network
    "wireshark|network|-v"
    "tshark|network|-v"
    "tcpdump|network|--version"
    "zeek|network|-v"
    "aircrack-ng|network|--help"
    "hcxpcapngtool|network|-v"
    "candump|network|"
    "cannelloni|network|-h"
    "socat|network|-V"

    # Stego
    "zsteg|stego|--version"
    "binwalk|stego|-h"
    "steghide|stego|--version"
    "stegseek|stego|-h"
    "stegsnow|stego|-h"
    "zbarimg|stego|--version"
    "pngcheck|stego|-h"
    "jpeginfo|stego|-v"
    "sox|stego|--version"
    "sonic-visualiser|stego|--version"
    "ffmpeg|stego|-version"
    "convert|stego|-version"
    "gmic|stego|-help"

    # Reversing
    "ghidraRun|reversing|"
    "r2|reversing|-v"
    "gdb|reversing|-v"
    "x64dbg|reversing|"
    "jadx|reversing|-h"
    "apktool|reversing|-version"
    "dex2jar|reversing|"
    "upx|reversing|--version"
    "die|reversing|--version"
    "floss|reversing|-V"
    "yara|reversing|-v"
    "capa|reversing|-h"
    "ROPgadget|reversing|--version"
    "checksec|reversing|--version"
    "ltrace|reversing|-V"
    "strace|reversing|-V"
    "nasm|reversing|-v"
    "objdump|reversing|-v"
    "pypykatz|reversing|-h"
    "frida|reversing|--version"

    # MISC / shared
    "python3|misc|--version"
    "uv|misc|--version"
    "go|misc|version"
    "node|misc|-v"
    "cargo|misc|-V"
    "jq|misc|--version"
    "rg|misc|--version"
    "git|misc|--version"
    "docker|misc|--version"
    "curl|misc|--version"
    "wget|misc|--version"
    "searchsploit|misc|-h"
    "gitleaks|misc|version"
)

# optional category filter
FILTER="${1:-}"

printf "%-30s  %-10s  %-10s  %s\n" "TOOL" "CATEGORY" "STATUS" "VERSION"
printf '%s\n' "--------------------------------------------------------------------------------"

ok=0 missing=0
for row in "${TOOLS[@]}"; do
    IFS='|' read -r bin cat vflag <<<"$row"
    [[ -n "$FILTER" && "$cat" != "$FILTER" ]] && continue
    if command -v "$bin" >/dev/null 2>&1; then
        if [[ -n "$vflag" ]]; then
            ver=$("$bin" $vflag 2>&1 | head -1 | tr -d '\r')
            ver="${ver:0:40}"
        else
            ver="(present)"
        fi
        printf "%-30s  %-10s  \033[32m%-10s\033[0m  %s\n" "$bin" "$cat" "OK" "$ver"
        ok=$((ok+1))
    else
        printf "%-30s  %-10s  \033[33m%-10s\033[0m\n" "$bin" "$cat" "MISSING"
        missing=$((missing+1))
    fi
done

echo
echo "Summary: $ok present, $missing missing."
echo "Missing is normal when outside the Kali VM; run this on the AWS Kali image to verify."
