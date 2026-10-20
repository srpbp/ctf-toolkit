#!/usr/bin/env bash
# install.sh — symlink scripts into a bin directory on your PATH.
#
# usage:
#   ./install.sh                     # install into ~/.local/bin
#   ./install.sh /opt/ctf-bin        # install into custom dir
#   ./install.sh --uninstall         # remove symlinks (same default dir)
#
# After install, run `cipher-id --help`, `jwt decode <token>`, etc.
# Short names drop the .py/.sh extension (sqli-smoketest.sh -> sqli-smoketest).

set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="$HERE/scripts"

MODE="install"
BIN="${1:-$HOME/.local/bin}"
if [[ "${1:-}" == "--uninstall" ]]; then
    MODE="uninstall"
    BIN="${2:-$HOME/.local/bin}"
fi

mkdir -p "$BIN"

count=0
for src in "$SCRIPTS"/*.{sh,py}; do
    [[ -f "$src" ]] || continue
    name="$(basename "$src")"
    short="${name%.py}"; short="${short%.sh}"
    dest="$BIN/$short"

    if [[ "$MODE" == "install" ]]; then
        chmod +x "$src"
        ln -sf "$src" "$dest"
        echo "  linked  $dest"
    else
        if [[ -L "$dest" && "$(readlink "$dest")" == "$src" ]]; then
            rm "$dest"
            echo "  removed $dest"
        fi
    fi
    count=$((count+1))
done

if [[ "$MODE" == "install" ]]; then
    echo
    echo "Installed $count scripts to $BIN"
    case ":$PATH:" in
        *":$BIN:"*) echo "  $BIN is already on your PATH" ;;
        *) echo "  WARNING: $BIN is NOT on your PATH"
           echo "  Add this line to your shell rc (~/.zshrc / ~/.bashrc):"
           echo "    export PATH=\"$BIN:\$PATH\"" ;;
    esac
    echo
    echo "Try:  cipher-id --help"
else
    echo "Uninstalled."
fi
