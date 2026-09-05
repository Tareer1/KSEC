#!/usr/bin/env bash
# KSEC — uninstaller: reverses everything install.sh did.
#
# Usage:
#   bash uninstall.sh                       # remove the ksec command + PATH entry
#   bash uninstall.sh -y                    # also delete the virtualenv (.venv)
#   bash uninstall.sh -y --purge-state      # ALSO delete KSEC data + the repo clone
#
# Removed by default (safe, reversible):
#   - ~/.local/bin/ksec symlink (only if it points into this install)
#   - the PATH export block install.sh added to your shell rc
#
# With -y:
#   - <repo>/.venv  (the virtualenv install.sh created)
#
# With --purge-state (asks for confirmation unless -y):
#   - KSEC data dir   ($KSEC_HOME, default ~/.local/share/ksec)
#   - config dir      (~/.config/ksec)
#   - the repo clone itself (<repo>)
#
# Without --purge-state your data and the repo stay on disk, so you can
# reinstall (bash install.sh) or inspect things afterwards.
set -euo pipefail

REPO_URL="https://github.com/Tareer1/KSEC.git"
PURGE=0
YES=0

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- parse flags -----------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        -y|--yes)          YES=1 ;;
        --purge-state)     PURGE=1 ;;
        -h|--help)         sed -n '2,15p' "$0"; exit 0 ;;
        *) die "unknown argument: $arg (try -h)" ;;
    esac
done

# --- locate the repo (mirrors install.sh) ----------------------------------
SRC="${BASH_SOURCE[0]:-}"
if [ -n "$SRC" ] && [ -f "$SRC" ] && [ -f "$(dirname "$SRC")/pyproject.toml" ] \
   && [ -d "$(dirname "$SRC")/src/ksec" ]; then
    ROOT="$(cd "$(dirname "$SRC")" && pwd)"
else
    ROOT=""
    for cand in "${KSEC_DIR:-}" "$HOME/KSEC"; do
        [ -n "$cand" ] || continue
        if [ -f "$cand/pyproject.toml" ] && [ -d "$cand/src/ksec" ]; then
            ROOT="$cand"
            break
        fi
    done
    [ -n "$ROOT" ] || die "cannot locate the KSEC install — run this from inside the clone, or set KSEC_DIR."
fi
say "Repo: $ROOT"

# --- 1. remove the ~/.local/bin/ksec symlink -------------------------------
BIN_LINK="$HOME/.local/bin/ksec"
if [ -L "$BIN_LINK" ]; then
    TARGET="$(readlink "$BIN_LINK")"
    if [ "$TARGET" = "$ROOT/.venv/bin/ksec" ]; then
        rm -f "$BIN_LINK"
        say "Removed $BIN_LINK"
    else
        say "Left $BIN_LINK alone — it points at $TARGET, not this install."
    fi
elif [ -e "$BIN_LINK" ]; then
    say "Left $BIN_LINK alone — it is a real file, not our symlink."
fi
rmdir "$HOME/.local/bin" 2>/dev/null || true

# --- 2. remove the PATH export block from the shell rc files ---------------
remove_path_block() {
    local f="$1"
    [ -f "$f" ] || return 0
    grep -qsF '# ksec installer' "$f" || return 0
    local tmp
    tmp="$(mktemp)"
    awk '
        /^# ksec installer$/ { drop_next = 1; next }
        drop_next && /^export PATH="\$HOME\/\.local\/bin:\$PATH"$/ { drop_next = 0; next }
        { if (drop_next) drop_next = 0; print }
    ' "$f" > "$tmp" && mv "$tmp" "$f"
    say "Removed ksec PATH entry from $f"
}
for f in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
    remove_path_block "$f"
done

# --- 3. (optional) delete the virtualenv ------------------------------------
if [ "$YES" = 1 ] && [ -d "$ROOT/.venv" ]; then
    rm -rf "$ROOT/.venv"
    say "Removed virtualenv: $ROOT/.venv"
fi

# --- 4. (optional, destructive) delete data + repo ---------------------------
if [ "$PURGE" = 1 ]; then
    DATA_DIR="${KSEC_HOME:-$HOME/.local/share/ksec}"
    CONFIG_DIR="$HOME/.config/ksec"
    if [ "$YES" = 0 ]; then
        if [ -t 0 ]; then
            read -r -p "This deletes ALL KSEC data ($DATA_DIR, $CONFIG_DIR) and the repo ($ROOT). Type 'yes' to continue: " ans
            [ "$ans" = "yes" ] || die "aborted."
        else
            die "--purge-state needs confirmation — re-run with -y (e.g. bash uninstall.sh -y --purge-state)."
        fi
    fi
    rm -rf "$DATA_DIR" "$CONFIG_DIR" "$ROOT"
    say "Purged: $DATA_DIR, $CONFIG_DIR, $ROOT"
    say "Done. KSEC is fully removed."
    exit 0
fi

# --- done ------------------------------------------------------------------
say ""
say "KSEC command removed."
if [ "$YES" = 0 ]; then
    say "Kept for reinstall/inspection:"
    say "  repo:    $ROOT"
    say "  venv:    $ROOT/.venv"
    say "  data:    ${KSEC_HOME:-$HOME/.local/share/ksec}"
    say "Re-run with -y to also delete the .venv, or -y --purge-state to delete everything."
else
    say "Kept for reinstall/inspection:"
    say "  repo:    $ROOT"
    say "  data:    ${KSEC_HOME:-$HOME/.local/share/ksec}"
    say "Re-run with -y --purge-state to delete data + the repo clone too."
fi
say ""
say "To close the current shell's PATH change, open a new terminal."
