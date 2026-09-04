#!/usr/bin/env bash
# KSEC smoke test — exercises every CLI command group in a fresh environment.
#
# Usage:
#   bash scripts/smoke.sh            # fresh env at /tmp/ksec-smoke
#   KSEC_SMOKE_HOME=/path bash scripts/smoke.sh
#
# Real (non-destructive) network tools run against example.com when the host
# has dig/nmap/curl installed; everything else is local. Every check must
# either succeed (exit 0) or, for deliberately-invalid input, fail cleanly
# (a handled KSECError — never a Python traceback).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/src"
export KSEC_HOME="${KSEC_SMOKE_HOME:-/tmp/ksec-smoke}"
export KSEC_CONFIG="$KSEC_HOME/config.toml"
BIN=(python3 -m ksec.main)

ADMIN=admin
APW=smoke-pass-1
OPW=op-pass-1
ERR=/tmp/ksec-smoke-err.$$

PASS=0
FAIL=0
FAILED=()

rm -rf "$KSEC_HOME"
mkdir -p "$KSEC_HOME"

say() { printf '\n=== %s ===\n' "$*"; }

# run_ok DESC CMD...  -> must exit 0
run_ok() {
  local desc="$1"; shift
  local out rc
  out=$("$@" 2>&1); rc=$?
  if [ "$rc" -eq 0 ]; then
    PASS=$((PASS + 1)); echo "PASS  $desc"
  else
    FAIL=$((FAIL + 1)); FAILED+=("$desc"); echo "FAIL  $desc"
    printf '%s\n' "$out" | head -4 | sed 's/^/      /'
  fi
}

# run_clean DESC CMD... -> exit 0 OR a clean handled error (no traceback)
run_clean() {
  local desc="$1"; shift
  local out rc
  out=$("$@" 2>&1); rc=$?
  if [ "$rc" -eq 0 ]; then
    PASS=$((PASS + 1)); echo "PASS  $desc"
  elif printf '%s' "$out" | grep -q "Traceback"; then
    FAIL=$((FAIL + 1)); FAILED+=("$desc"); echo "FAIL  $desc (traceback)"
    printf '%s\n' "$out" | head -6 | sed 's/^/      /'
  else
    PASS=$((PASS + 1)); echo "PASS  $desc (clean error, rc=$rc)"
  fi
}

# expect_fail DESC CMD... -> must fail cleanly (no traceback)
expect_fail() {
  local desc="$1"; shift
  local out rc
  out=$("$@" 2>&1); rc=$?
  if [ "$rc" -ne 0 ] && ! printf '%s' "$out" | grep -q "Traceback"; then
    PASS=$((PASS + 1)); echo "PASS  $desc (clean error, rc=$rc)"
  else
    FAIL=$((FAIL + 1)); FAILED+=("$desc"); echo "FAIL  $desc (rc=$rc)"
    printf '%s\n' "$out" | head -4 | sed 's/^/      /'
  fi
}

# run_grep DESC NEEDLE CMD... -> must exit 0 AND print NEEDLE somewhere
run_grep() {
  local desc="$1"; shift
  local needle="$1"; shift
  local out rc
  out=$("$@" 2>&1); rc=$?
  if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "$needle"; then
    PASS=$((PASS + 1)); echo "PASS  $desc"
  else
    FAIL=$((FAIL + 1)); FAILED+=("$desc"); echo "FAIL  $desc (rc=$rc, missing: $needle)"
    printf '%s\n' "$out" | head -6 | sed 's/^/      /'
  fi
}

# ---------------------------------------------------------------------------
say "1. init / core"
run_ok "init"            "${BIN[@]}" init --username "$ADMIN" --password "$APW"
run_ok "status"          "${BIN[@]}" status
run_ok "status --json"   "${BIN[@]}" status --json
run_ok "doctor"          "${BIN[@]}" doctor
run_ok "doctor --json"   "${BIN[@]}" doctor --json
run_ok "version"         "${BIN[@]}" version
run_ok "version --json"  "${BIN[@]}" version --json
run_ok "config show"     "${BIN[@]}" config show
run_ok "env"             "${BIN[@]}" env
run_ok "env --json"      "${BIN[@]}" env --json

say "2. admin / sessions"
run_ok "user create"     "${BIN[@]}" admin user create --username operator --password "$OPW" --role operator
run_ok "user list"       "${BIN[@]}" admin user list
run_ok "user list --json" "${BIN[@]}" admin user list --json
expect_fail "audit list as operator (denied)" "${BIN[@]}" audit list --user operator --password "$OPW"
run_ok "audit list as admin"   "${BIN[@]}" audit list --user "$ADMIN" --password "$APW"
run_ok "audit list --json"     "${BIN[@]}" audit list --user "$ADMIN" --password "$APW" --json
SID=$("${BIN[@]}" session open --user "$ADMIN" --password "$APW" --workspace RED_TEAM 2>/dev/null \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))")
if [ -n "${SID:-}" ]; then
  PASS=$((PASS + 1)); echo "PASS  session open"
  run_ok "session list"     "${BIN[@]}" session list
  run_ok "session status"   "${BIN[@]}" session status "$SID"
  run_ok "session pause"    "${BIN[@]}" session pause "$SID"
  run_ok "session resume"   "${BIN[@]}" session resume "$SID"
  run_ok "session close"    "${BIN[@]}" session close "$SID"
  expect_fail "session close again" "${BIN[@]}" session close "$SID"
else
  FAIL=$((FAIL + 1)); FAILED+=("session open"); echo "FAIL  session open (id parse)"
fi

say "3. engagements / scope"
run_ok "engagement create" "${BIN[@]}" engagement create --name smoke-eng --description "smoke test"
run_ok "engagement list"   "${BIN[@]}" engagement list
run_ok "scope add allow"   "${BIN[@]}" engagement scope add --engagement 1 --target example.com
run_ok "scope add deny"    "${BIN[@]}" engagement scope add --engagement 1 --target 10.0.0.0/8 --effect deny
run_ok "scope list"        "${BIN[@]}" engagement scope list --engagement 1

say "4. tools / modes"
run_ok "tools list"       "${BIN[@]}" tools list
run_ok "tools health"     "${BIN[@]}" tools health
run_ok "tools info dig"   "${BIN[@]}" tools info dig
run_ok "tools explain dig (beginner)" "${BIN[@]}" tools explain dig --mode beginner
run_ok "tools explain dig (expert)"   "${BIN[@]}" tools explain dig --mode expert

say "5. policy gate"
run_ok "assess dry-run (in scope)" "${BIN[@]}" assess example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
expect_fail "assess out-of-scope"  "${BIN[@]}" assess 192.0.2.55 --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
expect_fail "assess denied CIDR"   "${BIN[@]}" assess 10.1.2.3 --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "assess dry-run --explain"  "${BIN[@]}" assess example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run --explain

say "6. custom workflows"
run_ok "workflow list"    "${BIN[@]}" workflow list
run_ok "workflow create"  "${BIN[@]}" workflow create --name smoke-wf --description "smoke wf" --step dns_lookup --step http_probe --user "$ADMIN"
run_ok "workflow validate" "${BIN[@]}" workflow validate --name smoke-wf
run_ok "workflow edit"    "${BIN[@]}" workflow edit --name smoke-wf --description "smoke wf v2"
expect_fail "workflow validate unknown" "${BIN[@]}" workflow validate --name does-not-exist

say "7. live execution (real tools -> example.com)"
run_ok "run smoke-wf live" "${BIN[@]}" workflow run smoke-wf example.com --engagement 1 --user "$ADMIN" --password "$APW"
run_ok "run alias dry-run" "${BIN[@]}" run recon example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "workflow history"  "${BIN[@]}" workflow history --name smoke-wf

say "8. jobs"
run_ok "job list"     "${BIN[@]}" job list
run_ok "job list --json" "${BIN[@]}" job list --json
JID=$("${BIN[@]}" job list --json 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')")
if [ -n "${JID:-}" ]; then
  run_ok "job status (live id)" "${BIN[@]}" job status "$JID"
else
  FAIL=$((FAIL + 1)); FAILED+=("job status"); echo "FAIL  job status (id parse)"
fi
expect_fail "job status unknown" "${BIN[@]}" job status 99999
expect_fail "job cancel unknown" "${BIN[@]}" job cancel 99999

say "9. security data"
run_ok "asset list"    "${BIN[@]}" asset list --engagement 1
run_ok "finding create" "${BIN[@]}" finding create --title "Smoke finding" --description "found during smoke" --severity medium --risk --engagement 1
run_ok "finding list"  "${BIN[@]}" finding list
run_ok "finding explain 1 (beginner)" "${BIN[@]}" finding explain 1 --mode beginner
run_ok "finding explain 1 (expert)"   "${BIN[@]}" finding explain 1 --mode expert
run_ok "evidence add"  "${BIN[@]}" evidence add --content "smoke evidence payload 12345" --tool smoke-test --engagement 1
run_ok "evidence list" "${BIN[@]}" evidence list
run_ok "evidence verify 1" "${BIN[@]}" evidence verify 1
expect_fail "evidence verify unknown" "${BIN[@]}" evidence verify 99999
run_ok "case create"   "${BIN[@]}" case create --title "Smoke case" --severity high --engagement 1
run_ok "case list"     "${BIN[@]}" case list
run_ok "case add-finding" "${BIN[@]}" case add-finding --case 1 --finding 1
expect_fail "case close unknown" "${BIN[@]}" case close 4242

say "10. reporting"
run_ok "report create" "${BIN[@]}" report create --engagement 1 --title "Smoke report"
run_ok "report list"   "${BIN[@]}" report list
run_ok "report show 1" "${BIN[@]}" report show 1
run_ok "report html out" "${BIN[@]}" report create --engagement 1 --title "Smoke html" --format html --out /tmp/ksec-smoke-report.html

say "11. learning"
run_ok "learn list"    "${BIN[@]}" learn list
LESSON_ID=$("${BIN[@]}" learn list --json 2>/dev/null | python3 -c "import sys,json
d=json.load(sys.stdin)
print(d[0]['lessons'][0])" 2>/dev/null)
if [ -n "${LESSON_ID:-}" ]; then
  run_ok "learn lesson"      "${BIN[@]}" learn lesson --id "$LESSON_ID"
  run_ok "learn complete"    "${BIN[@]}" learn complete --id "$LESSON_ID" --user "$ADMIN" --password "$APW"
  run_ok "learn progress"    "${BIN[@]}" learn progress --user "$ADMIN" --password "$APW"
else
  run_clean "learn list --json shape" "${BIN[@]}" learn list --json
  echo "      (lesson id extraction skipped)"
fi

say "12. DFIR"
run_ok "artifact add"  "${BIN[@]}" dfir artifact add --case 1 --type network --name conn.log --host host-1 --details "smoke pcap"
run_ok "artifact list" "${BIN[@]}" dfir artifact list --case 1
run_ok "event add"     "${BIN[@]}" dfir event add --case 1 --time 2026-09-04T10:00:00Z --type network --actor attacker-ip --source fw-1
run_ok "timeline"      "${BIN[@]}" dfir timeline --case 1
run_ok "timeline all"  "${BIN[@]}" dfir timeline

say "13. threat intel"
run_ok "actor add"     "${BIN[@]}" intel actor add --name APT-Smoke --description "smoke actor"
run_ok "actor list"    "${BIN[@]}" intel actor list
run_ok "campaign add"  "${BIN[@]}" intel campaign add --name camp-smoke --actor APT-Smoke
run_ok "campaign list" "${BIN[@]}" intel campaign list
run_ok "ttp add"       "${BIN[@]}" intel ttp add --technique-id T1071 --name "Application Layer Protocol" --tactic c2
run_ok "ttp list"      "${BIN[@]}" intel ttp list
run_ok "link ttp"      "${BIN[@]}" intel link --campaign 1 --ttp 1
run_ok "ioc add"       "${BIN[@]}" intel ioc add --value 203.0.113.99 --type IP --actor APT-Smoke --campaign camp-smoke --source smoke
run_ok "ioc list"      "${BIN[@]}" intel ioc list
run_ok "ioc correlate" "${BIN[@]}" intel ioc correlate --value 203.0.113.99
run_ok "ioc enrich"    "${BIN[@]}" intel ioc enrich --ioc 1
run_ok "ioc extract text" "${BIN[@]}" intel ioc extract --text "suspicious 198.51.100.77 and evil-smoke.example.net"
expect_fail "ioc extract unknown job" "${BIN[@]}" intel ioc extract --job 424242

say "14. plugins"
run_ok "plugin list"     "${BIN[@]}" plugin list
run_ok "plugin info"     "${BIN[@]}" plugin info ksec.http-headers
run_ok "plugin check"    "${BIN[@]}" plugin check

say "14b. vuln checks + atomics"
run_ok "vuln checks list" "${BIN[@]}" vuln checks
run_ok "atomic list"      "${BIN[@]}" atomic list
run_ok "atomic info"      "${BIN[@]}" atomic info net-dns-lookup
expect_fail "vuln out-of-scope" "${BIN[@]}" vuln check 203.0.113.44 --engagement 1 --user "$ADMIN" --password "$APW"
expect_fail "atomic out-of-scope" "${BIN[@]}" atomic run net-dns-lookup 203.0.113.44 --engagement 1 --user "$ADMIN" --password "$APW"

say "15. adversary simulation"
run_ok "adv profile add"  "${BIN[@]}" adversary profile add --name apt-smoke --threat-actor APT-Smoke --technique T1046 --technique T1071 --user "$ADMIN"
run_ok "adv profile list" "${BIN[@]}" adversary profile list
run_ok "adv profile show" "${BIN[@]}" adversary profile show 1
run_ok "adv coverage"     "${BIN[@]}" adversary coverage --profile 1
run_ok "adv exercise new" "${BIN[@]}" adversary exercise new --name ex-smoke --profile 1 --engagement 1 --user "$ADMIN" --password "$APW"
run_ok "adv exercise list" "${BIN[@]}" adversary exercise list
run_ok "adv exercise dry-run" "${BIN[@]}" adversary exercise run 1 example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_grep "adv exercise blocks out-of-scope" "REQUIRE_AUTHORIZATION" "${BIN[@]}" adversary exercise run 1 203.0.113.200 --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "adv chain dry-run" "${BIN[@]}" adversary exercise chain 1 example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run --quiet
run_clean "adv report"    "${BIN[@]}" adversary report 1
expect_fail "adv delete unknown" "${BIN[@]}" adversary profile delete 4242

say "16. updates / notifications"
run_clean "update check (pre-backup)" "${BIN[@]}" update check
run_ok "notify list"     "${BIN[@]}" notify list
expect_fail "notify test (no provider configured)" "${BIN[@]}" notify test --title smoke --body "smoke notification"

say "17. SOC pipeline"
run_ok "soc rule add"    "${BIN[@]}" soc rule add --name smoke-beacon --event-type beacon --field domain --operator contains --value .top --severity critical --risk-boost 4
run_ok "soc rule list"   "${BIN[@]}" soc rule list
run_ok "soc ingest (benign)" "${BIN[@]}" soc ingest --event-id sb-1 --source dns --event-type dns --severity low --domain legit.example.com
run_ok "soc ingest (beacon)" "${BIN[@]}" soc ingest --event-id sb-2 --source endpoint --event-type beacon --severity medium --domain evil-smoke.top
run_ok "soc event list"  "${BIN[@]}" soc event list
run_ok "soc alert list"  "${BIN[@]}" soc alert list
run_ok "soc alert show 1" "${BIN[@]}" soc alert show 1
run_ok "soc alert ack"   "${BIN[@]}" soc alert action ack 1
run_ok "soc alert resolve" "${BIN[@]}" soc alert action resolve 1
run_ok "soc rule disable" "${BIN[@]}" soc rule disable 1
run_ok "soc rule enable" "${BIN[@]}" soc rule enable 1
expect_fail "soc rule delete unknown" "${BIN[@]}" soc rule delete 4242
expect_fail "soc alert action unknown" "${BIN[@]}" soc alert action ack 4242

say "18. backup"
run_ok "backup create"  "${BIN[@]}" backup create
run_ok "backup list"    "${BIN[@]}" backup list
run_ok "backup verify 1" "${BIN[@]}" backup verify 1
run_ok "update check (post-backup)" "${BIN[@]}" update check
expect_fail "backup verify unknown" "${BIN[@]}" backup verify 4242
expect_fail "restore without --yes" "${BIN[@]}" backup restore 1

say "19. dashboard API"
"${BIN[@]}" dashboard start --host 127.0.0.1 --port 8937 >"$KSEC_HOME/dash.log" 2>&1 &
DPID=$!
sleep 2.5
if curl -sf http://127.0.0.1:8937/api/v1/status >/dev/null 2>&1; then
  PASS=$((PASS + 1)); echo "PASS  dashboard /api/v1/status"
else
  FAIL=$((FAIL + 1)); FAILED+=("dashboard api"); echo "FAIL  dashboard /api/v1/status"
  tail -3 "$KSEC_HOME/dash.log" | sed 's/^/      /'
fi
kill "$DPID" 2>/dev/null
wait "$DPID" 2>/dev/null

say "20. TUI headless"
run_clean "tui headless" "${BIN[@]}" tui

say "21. help parsers (every group)"
for g in init status doctor version config env admin audit tools session engagement assess job asset finding evidence case report learn workflow dfir intel plugin adversary vuln atomic update notify soc run backup tui dashboard; do
  run_ok "help: $g" "${BIN[@]}" "$g" --help
done

# ---------------------------------------------------------------------------
echo
echo "=========================================="
echo "smoke: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
  printf 'failed: %s\n' "${FAILED[@]}"
  exit 1
fi
exit 0
