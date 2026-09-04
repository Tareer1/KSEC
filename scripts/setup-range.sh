#!/usr/bin/env bash
# KSEC cyber-range bootstrap — multi-persona environment setup.
#
# Creates the four team personas (red/blue/purple/learner) with their own
# workspace sessions and an engagement with scope, so the team can work
# side by side against the same shared database — the multi-terminal
# operating model from spec 01 ("Terminal 1 -> Red Team, ...").
#
# Usage:
#   bash scripts/setup-range.sh [--target example.com] [--password range-pass]
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/src"
export KSEC_HOME="${KSEC_HOME:-$HOME/.ksec}"
export KSEC_CONFIG="${KSEC_CONFIG:-$KSEC_HOME/config.toml}"
BIN="python3 -m ksec.main"

TARGET="${1:-example.com}"
PASS="${2:-range-pass}"

"$BIN" init --username admin --password "$PASS" --display-name "Range Admin" >/dev/null 2>&1

for u in red blue purple learner; do
  "$BIN" admin user create --username "$u" --password "$PASS" --role operator >/dev/null 2>&1 || true
done

"$BIN" engagement create --name "Cyber-Range-1" --description "multi-persona environment" >/dev/null 2>&1
"$BIN" engagement scope add --engagement 1 --target "$TARGET" >/dev/null 2>&1

"$BIN" session open --user red     --password "$PASS" --workspace RED_TEAM            >/dev/null 2>&1
"$BIN" session open --user blue    --password "$PASS" --workspace BLUE_TEAM           >/dev/null 2>&1
"$BIN" session open --user purple  --password "$PASS" --workspace RESEARCH_OSINT      >/dev/null 2>&1
"$BIN" session open --user learner --password "$PASS" --workspace LEARN_WORK          >/dev/null 2>&1

echo "cyber range ready (target=$TARGET)"
echo "  red     -> RED_TEAM          : ksec run recon $TARGET --engagement 1 --user red --password $PASS"
echo "  purple  -> RESEARCH_OSINT    : ksec intel ioc add --value <evil> --type DOMAIN --confidence high"
echo "  blue    -> BLUE_TEAM         : ksec soc rule add ... && ksec soc ingest ..."
echo "  learner -> LEARN_WORK        : ksec learn complete --id ... --user learner --password $PASS"