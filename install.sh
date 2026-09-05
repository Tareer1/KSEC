#!/usr/bin/env bash
# KSEC — one-command installer for Kali Linux / Debian-based Linux.
#
# Usage:
#   From an existing clone:  bash install.sh
#   Anywhere (auto-clone):   bash <(curl -fsSL https://raw.githubusercontent.com/Tareer1/KSEC/main/install.sh)
#   Anywhere (auto-clone):   curl -fsSL https://raw.githubusercontent.com/Tareer1/KSEC/main/install.sh | bash
#
# What it does:
#   1. Uses the current directory if it is a KSEC clone; otherwise clones
#      the repository into ~/KSEC (override the destination with KSEC_DIR).
#   2. Creates a virtualenv at <repo>/.venv — Kali's system Python is
#      externally managed (PEP 668), so pip refuses system-wide installs
#      and a venv is the supported path.
#   3. pip-installs KSEC into that venv (editable, zero dependencies).
#   4. Symlinks the ksec command into ~/.local/bin and makes sure that
#      directory is on PATH (zsh/bash), so `ksec` works in any NEW
#      terminal — no activation, no manual rc-file editing.
#
# Safe to re-run: it upgrades an existing install in place.
# No sudo required. Nothing outside the repo + ~/.local/bin is touched.
set -euo pipefail

REPO_URL="https://github.com/Tareer1/KSEC.git"
RC_FILE=""

say()  { printf '%s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- locate the repo -------------------------------------------------------
SRC="${BASH_SOURCE[0]:-}"
if [ -n "$SRC" ] && [ -f "$SRC" ]; then
    HERE="$(cd "$(dirname "$SRC")" && pwd)"
else
    HERE="$(pwd)"          # running from a pipe (curl | bash): use cwd
fi

if [ -f "$HERE/pyproject.toml" ] && [ -d "$HERE/src/ksec" ]; then
    ROOT="$HERE"                                   # already a KSEC checkout
    say "Using existing KSEC checkout: $ROOT"
else
    ROOT="${KSEC_DIR:-$HOME/KSEC}"
    if [ -d "$ROOT" ]; then
        [ -f "$ROOT/pyproject.toml" ] || die "$ROOT exists but is not a KSEC checkout — remove it or set KSEC_DIR to another location."
        say "Using existing directory: $ROOT"
    else
        command -v git >/dev/null 2>&1 || die "git is required (sudo apt install git)"
        say "Cloning KSEC into $ROOT ..."
        git clone --depth 1 "$REPO_URL" "$ROOT" || die "clone failed — check your network/access to $REPO_URL"
    fi
fi
cd "$ROOT"

# --- Python 3.11+ ----------------------------------------------------------
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || die "python3 not found — install it with: sudo apt install python3"
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
    die "KSEC requires Python 3.11+ (found: $("$PY" -V 2>&1))"
fi
if ! "$PY" -m venv -h >/dev/null 2>&1; then
    die "python venv support is missing — install it with: sudo apt install python3-venv  (Kali: python3-full)"
fi

# --- virtualenv ------------------------------------------------------------
if [ ! -x ".venv/bin/python" ]; then
    say "Creating virtualenv (.venv) ..."
    "$PY" -m venv .venv
else
    say "Using existing virtualenv (.venv) ..."
fi

# --- install (editable, zero dependencies) ---------------------------------
say "Installing ksec into the venv ..."
.venv/bin/pip install -e . >/dev/null

# --- expose the ksec command globally --------------------------------------
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
ln -sf "$ROOT/.venv/bin/ksec" "$BIN_DIR/ksec"

# --- make sure ~/.local/bin is on PATH for new terminals -------------------
case ":$PATH:" in
    *":$BIN_DIR:"*) : ;;
    *)
        for f in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
            if [ -f "$f" ]; then RC_FILE="$f"; break; fi
        done
        [ -n "$RC_FILE" ] || { RC_FILE="$HOME/.bashrc"; touch "$RC_FILE"; }
        # guard on the marker (not the expanded path) so re-runs never duplicate it
        if ! grep -qsF '# ksec installer' "$RC_FILE"; then
            printf '\n# ksec installer\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$RC_FILE"
            say "Added ~/.local/bin to PATH in $RC_FILE"
        fi
        ;;
esac

# --- done ------------------------------------------------------------------
VERSION="$("$BIN_DIR/ksec" version 2>/dev/null | sed -n 's/.*"ksec"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
VERSION="${VERSION:-installed}"

say ""
say "KSEC ${VERSION} ready."
say "  command: ksec      ($BIN_DIR/ksec)"
say "  repo:    $ROOT"
say "  venv:    $ROOT/.venv"
say ""
say "Open a NEW terminal (or run: source ${RC_FILE:-your shell rc}), then:"
say "  ksec init --username admin --password 'change-me'"
say "  ksec status"
say ""
say "No sudo was used. KSEC state lives in ~/.config/ksec — nothing leaves your machine."
