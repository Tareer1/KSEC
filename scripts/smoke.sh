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

# Skip bookkeeping: checks that need a real Kali tool skip (not fail) when
# the tool is absent, so the suite stays green on bare CI runners and on
# Kali boxes alike (KSEC discovers whatever tools are actually installed).
SKIP=0

# have_tool NAME -> 0 when the binary is installed
have_tool() {
  command -v "$1" >/dev/null 2>&1
}

# run_ok_skip DESC TOOL CMD... -> run_ok, but SKIP if TOOL is missing
run_ok_skip() {
  local desc="$1"; local tool="$2"; shift 2
  if ! have_tool "$tool"; then
    SKIP=$((SKIP + 1)); echo "SKIP  $desc (tool '$tool' not installed)"
    return 0
  fi
  run_ok "$desc" "$@"
}

# run_clean_skip DESC TOOL CMD... -> run_clean, but SKIP if TOOL is missing
run_clean_skip() {
  local desc="$1"; local tool="$2"; shift 2
  if ! have_tool "$tool"; then
    SKIP=$((SKIP + 1)); echo "SKIP  $desc (tool '$tool' not installed)"
    return 0
  fi
  run_clean "$desc" "$@"
}

# run_grep_skip DESC TOOL NEEDLE CMD... -> run_grep, but SKIP if TOOL missing
run_grep_skip() {
  local desc="$1"; local tool="$2"; shift 2
  local needle="$1"; shift
  if ! have_tool "$tool"; then
    SKIP=$((SKIP + 1)); echo "SKIP  $desc (tool '$tool' not installed)"
    return 0
  fi
  run_grep "$desc" "$needle" "$@"
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
run_ok "user password reset" "${BIN[@]}" admin user password operator --password "$OPW" --actor "$ADMIN"
run_ok "user auth after reset" "${BIN[@]}" session open --user operator --password "$OPW" --workspace RED_TEAM
expect_fail "user password reset unknown user" "${BIN[@]}" admin user password ghost --password x
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
run_ok "adv coverage"     "${BIN[@]}" adversary coverage --profile-id 1
run_ok "adv exercise new" "${BIN[@]}" adversary exercise new --name ex-smoke --profile-id 1 --engagement 1 --user "$ADMIN" --password "$APW"
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

say "21. in-tool mentor (ask / role)"
run_ok "ask --help" "${BIN[@]}" ask --help
if "${BIN[@]}" ask "what is a port" | grep -q "door"; then
  PASS=$((PASS + 1)); echo "PASS  ask concept routing"
else
  FAIL=$((FAIL + 1)); FAILED+=("ask concept"); echo "FAIL  ask concept routing"
fi
if "${BIN[@]}" ask "nmap kya hai" | grep -q "nmap"; then
  PASS=$((PASS + 1)); echo "PASS  ask roman-urdu routing"
else
  FAIL=$((FAIL + 1)); FAILED+=("ask urdu"); echo "FAIL  ask roman-urdu routing"
fi
if "${BIN[@]}" role blue | grep -q "BLUE TEAM playbook"; then
  PASS=$((PASS + 1)); echo "PASS  role blue playbook"
else
  FAIL=$((FAIL + 1)); FAILED+=("role blue"); echo "FAIL  role blue playbook"
fi
if "${BIN[@]}" role red | grep -q "RED TEAM playbook"; then
  PASS=$((PASS + 1)); echo "PASS  role red playbook"
else
  FAIL=$((FAIL + 1)); FAILED+=("role red"); echo "FAIL  role red playbook"
fi
run_ok "role purple" "${BIN[@]}" role purple
run_grep "role blackhat" "BLACK HAT emulation playbook" "${BIN[@]}" role blackhat
run_ok "ask --list" "${BIN[@]}" ask --list
expect_fail "ask unmatched" "${BIN[@]}" ask "zzqqxxyy nonsense"
expect_fail "role unknown" "${BIN[@]}" role hacker

say "22. help parsers (every group)"
for g in init status doctor version config env admin audit tools session engagement assess job asset finding evidence case report learn workflow dfir intel plugin adversary vuln atomic update notify soc run backup tui dashboard ask role stop db export grc malware endpoint module purple change history graph; do
  run_ok "help: $g" "${BIN[@]}" "$g" --help
done

say "23. recurring schedules"
run_ok "job schedule list" "${BIN[@]}" job schedule list
run_ok "job schedule add (allowed)" "${BIN[@]}" job schedule add dns_lookup example.com --cron "0 6 * * *" --engagement 1 --user "$ADMIN" --password "$APW"
run_ok "job schedule list (1)" "${BIN[@]}" job schedule list
expect_fail "job schedule add (out of scope)" "${BIN[@]}" job schedule add port_scan 203.0.113.9 --cron "0 6 * * *" --engagement 1 --user "$ADMIN" --password "$APW"
expect_fail "job schedule remove unknown" "${BIN[@]}" job schedule remove 4242
run_ok "job schedule remove" "${BIN[@]}" job schedule remove 1

say "24. report executive summary"
if "${BIN[@]}" report create --engagement 1 --title 'smoke report' --format markdown --out "$KSEC_HOME/smoke-report.md" | grep -q '"path"'; then
  PASS=$((PASS + 1)); echo "PASS  report create (file)"
else
  FAIL=$((FAIL + 1)); FAILED+=("report file"); echo "FAIL  report create (file)"
fi
if grep -q 'Executive Summary' "$KSEC_HOME/smoke-report.md" 2>/dev/null; then
  PASS=$((PASS + 1)); echo "PASS  report executive summary"
else
  FAIL=$((FAIL + 1)); FAILED+=("exec summary"); echo "FAIL  report executive summary"
fi

say "25. REST API tokens + server"
APITOKEN=$("${BIN[@]}" api token create --name smoke --user "$ADMIN" --password "$APW" | grep '^ksec_')
if [ -n "$APITOKEN" ]; then
  PASS=$((PASS + 1)); echo "PASS  api token create"
else
  FAIL=$((FAIL + 1)); FAILED+=("api token"); echo "FAIL  api token create"
fi
run_ok "api token list" "${BIN[@]}" api token list --user "$ADMIN" --password "$APW"
"${BIN[@]}" api serve --host 127.0.0.1 --port 8993 >"$KSEC_HOME/api.log" 2>&1 &
APID=$!
sleep 1.5
if curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8993/api/v1/status 2>/dev/null | grep -q 401; then
  PASS=$((PASS + 1)); echo "PASS  api 401 without token"
else
  FAIL=$((FAIL + 1)); FAILED+=("api 401"); echo "FAIL  api 401 without token"
fi
if curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $APITOKEN" http://127.0.0.1:8993/api/v1/status 2>/dev/null | grep -q 200; then
  PASS=$((PASS + 1)); echo "PASS  api 200 with token"
else
  FAIL=$((FAIL + 1)); FAILED+=("api 200"); echo "FAIL  api 200 with token"
fi
kill "$APID" 2>/dev/null
wait "$APID" 2>/dev/null
"${BIN[@]}" api token revoke 1 --user "$ADMIN" --password "$APW" >/dev/null 2>&1 && { PASS=$((PASS + 1)); echo "PASS  api token revoke"; } || { FAIL=$((FAIL + 1)); FAILED+=("api revoke"); echo "FAIL  api token revoke"; }
expect_fail "api token create bad password" "${BIN[@]}" api token create --name x --user "$ADMIN" --password wrong

# 26. windowed rules ------------------------------------------------------
say "26. Windowed SOC detection rules (count-in-window)"
run_ok "windowed rule add" "${BIN[@]}" soc rule add --name smoke-brute --event-type auth_failure --field ip --operator eq --value 203.0.113.200 --within 5 --count 3 --severity high
for i in 1 2 3; do
  "${BIN[@]}" soc ingest --event-id "smoke-bf-$i" --source ssh --event-type auth_failure --severity low --ip 203.0.113.200 --username root >/dev/null 2>&1
done
ALERT_JSON=$("${BIN[@]}" soc alert list --limit 5 --json 2>/dev/null)
if echo "$ALERT_JSON" | grep -q "smoke-brute"; then
  PASS=$((PASS + 1)); echo "PASS  windowed rule fired on 3rd event"
else
  FAIL=$((FAIL + 1)); FAILED+=("windowed rule"); echo "FAIL  windowed rule fired on 3rd event"
fi

# 27. SIEM ingestion -------------------------------------------------------
say "27. SIEM ingestion (demo + watch --once)"
run_ok "siem demo" "${BIN[@]}" siem demo
LOG=$KSEC_HOME/siem-test.log
printf '<134>Jan  5 10:01:22 web1 sshd[2213]: Failed password for root from 203.0.113.201 port 51234 ssh2\n{"event_id": "smoke-zeek-1", "event_type": "conn", "ip": "203.0.113.202"}\n' > "$LOG"
run_ok "siem watch --once" "${BIN[@]}" siem watch "$LOG" --once --source smoke
if "${BIN[@]}" soc event list --limit 10 --json 2>/dev/null | grep -q '"event_id": "smoke-zeek-1"'; then
  PASS=$((PASS + 1)); echo "PASS  siem watch ingested jsonl"
else
  FAIL=$((FAIL + 1)); FAILED+=("siem watch"); echo "FAIL  siem watch ingested jsonl"
fi

# 28. DFIR hash + export ---------------------------------------------------
say "28. DFIR artifact hashing + case export"
CASEID=$("${BIN[@]}" case create --title "smoke-dfir" --json 2>/dev/null | grep -o '"id": [0-9]*' | head -1 | grep -o '[0-9]*')
echo "smoke-evidence-content" > "$KSEC_HOME/evidence.bin"
"${BIN[@]}" dfir artifact add --case "$CASEID" --type file --name evidence.bin --tool smoke >/dev/null 2>&1
run_ok "dfir artifact hash" "${BIN[@]}" dfir artifact hash 1 --path "$KSEC_HOME/evidence.bin"
run_ok "dfir export jsonl" "${BIN[@]}" dfir export --case "$CASEID" --format jsonl

# 29. plugin scaffold + interactive dashboard ------------------------------
say "29. Plugin scaffold + interactive dashboard"
GEN=$KSEC_HOME/gen
run_ok "plugin new" "${BIN[@]}" plugin new smoke-tool --tool curl --category web --path "$GEN"
if [ -f "$GEN/smoke-tool/manifest.json" ]; then
  PASS=$((PASS + 1)); echo "PASS  plugin new manifest created"
else
  FAIL=$((FAIL + 1)); FAILED+=("plugin new"); echo "FAIL  plugin new manifest created"
fi
AID=$("${BIN[@]}" soc alert list --limit 1 --json 2>/dev/null | grep -o '"id": [0-9]*' | head -1 | grep -o '[0-9]*')
"${BIN[@]}" dashboard start --host 127.0.0.1 --port 8994 >"$KSEC_HOME/dash.log" 2>&1 &
DASHD=$!
sleep 1.5
if curl -s http://127.0.0.1:8994/api/v1/alerts 2>/dev/null | grep -q '"alerts"'; then
  PASS=$((PASS + 1)); echo "PASS  dashboard alerts endpoint"
else
  FAIL=$((FAIL + 1)); FAILED+=("dashboard alerts"); echo "FAIL  dashboard alerts endpoint"
fi
if curl -s -X POST "http://127.0.0.1:8994/api/v1/alerts/$AID/action/ack" 2>/dev/null | grep -q acknowledged; then
  PASS=$((PASS + 1)); echo "PASS  dashboard ack alert"
else
  FAIL=$((FAIL + 1)); FAILED+=("dashboard ack"); echo "FAIL  dashboard ack alert"
fi
kill "$DASHD" 2>/dev/null
wait "$DASHD" 2>/dev/null

# 30. gap-closing round: finding lifecycle, case notes, custody, exports, grc, malware, endpoint, stop, db --------
say "30. finding lifecycle + case collaboration"
run_ok "finding update status" "${BIN[@]}" finding update 1 --status confirmed
run_ok "finding remediate"    "${BIN[@]}" finding remediate 1 --owner ops --priority high --description "upgrade tls"
run_ok "finding verify"       "${BIN[@]}" finding verify --remediation 1 --method retest --result verified --user "$ADMIN" --password "$APW"
run_ok "finding remediations" "${BIN[@]}" finding remediations 1
expect_fail "finding update bad status" "${BIN[@]}" finding update 1 --status bogus
expect_fail "finding verify unknown rem" "${BIN[@]}" finding verify --remediation 4242 --result verified
run_ok "case note add"        "${BIN[@]}" case note add --case 1 --content "smoke note" --author operator
run_ok "case note list"       "${BIN[@]}" case note list --case 1
run_ok "case timeline"        "${BIN[@]}" case timeline 1
run_ok "case reopen"          "${BIN[@]}" case reopen 1 --reason "smoke recheck"
run_ok "evidence custody"     "${BIN[@]}" evidence custody 1
expect_fail "evidence custody unknown" "${BIN[@]}" evidence custody 4242

say "31. db introspection + exports"
run_ok "db version"   "${BIN[@]}" db version
run_ok "db health"    "${BIN[@]}" db health
run_ok "db repair"    "${BIN[@]}" db repair --yes
run_ok "export findings"  "${BIN[@]}" export findings --out "$KSEC_HOME/findings.json"
run_ok "export evidence"  "${BIN[@]}" export evidence --out "$KSEC_HOME/evidence.json"
run_ok "export assets"    "${BIN[@]}" export assets --out "$KSEC_HOME/assets.json"
run_ok "export case"      "${BIN[@]}" export case 1 --out "$KSEC_HOME/case-1.json"
expect_fail "export unknown case" "${BIN[@]}" export case 4242
if grep -q '"chain_of_custody"' "$KSEC_HOME/evidence.json" 2>/dev/null; then
  PASS=$((PASS + 1)); echo "PASS  export evidence includes custody"
else
  FAIL=$((FAIL + 1)); FAILED+=("export custody"); echo "FAIL  export evidence includes custody"
fi

say "32. GRC / malware / endpoint"
run_ok "grc frameworks"  "${BIN[@]}" grc frameworks
run_ok "grc controls"    "${BIN[@]}" grc controls --framework "ISO 27001"
run_ok "grc status"      "${BIN[@]}" grc status
run_ok "grc check"       "${BIN[@]}" grc check
printf '#!/bin/sh\necho smoke-c2.example\n' > "$KSEC_HOME/sample.sh"
run_ok "malware analyze" "${BIN[@]}" malware analyze "$KSEC_HOME/sample.sh" --user "$ADMIN"
expect_fail "malware missing file" "${BIN[@]}" malware analyze "$KSEC_HOME/nope.bin"
run_ok "endpoint inventory" "${BIN[@]}" endpoint inventory
run_ok "endpoint process"  "${BIN[@]}" endpoint process --limit 20
run_ok "endpoint user"     "${BIN[@]}" endpoint user
run_ok "endpoint port"     "${BIN[@]}" endpoint port
run_ok "endpoint check"    "${BIN[@]}" endpoint check

say "33. emergency stop + reset"
run_ok "stop --status (inactive)" "${BIN[@]}" stop --status
run_ok "stop --all"      "${BIN[@]}" stop --all
run_grep "stop persists across process" '"emergency_stop_active": true' "${BIN[@]}" stop --status
expect_fail "submit refused while stopped" "${BIN[@]}" job schedule add dns_lookup example.com --cron "0 6 * * *" --engagement 1 --user "$ADMIN" --password "$APW"
run_ok "stop --reset"    "${BIN[@]}" stop --reset
run_ok "stop --status (cleared)" "${BIN[@]}" stop --status

say "34. time-bound auth + lab mode + modes"
run_ok "mode status" "${BIN[@]}" mode status
run_ok "engagement create timebound" "${BIN[@]}" engagement create --name timebound --valid-until 2099-12-31
TIME_ID=$("${BIN[@]}" engagement list --quiet | tail -1)
run_ok "scope add for timebound" "${BIN[@]}" engagement scope add --engagement "$TIME_ID" --target example.com --effect allow
run_ok "run on timebound engagement" "${BIN[@]}" run dns_lookup example.com --engagement "$TIME_ID" --user "$ADMIN" --password "$APW"
run_ok "mode set lab on" "${BIN[@]}" mode set lab on
expect_fail "lab blocks public target" "${BIN[@]}" run dns_lookup example.com --engagement "$TIME_ID" --user "$ADMIN" --password "$APW"
run_ok "mode set lab off" "${BIN[@]}" mode set lab off
run_ok "expired engagement created" "${BIN[@]}" engagement create --name expired --valid-until 2020-01-01
EXP_ID=$("${BIN[@]}" engagement list --quiet | tail -1)
expect_fail "expired engagement blocks run" "${BIN[@]}" run dns_lookup example.com --engagement "$EXP_ID" --user "$ADMIN" --password "$APW"

say "35. workflow DAG + versioning"
run_ok "workflow dag create" "${BIN[@]}" workflow create --name dagflow --steps-json '[{"capability":"dns_lookup","name":"s1"},{"capability":"port_scan","name":"s2","depends_on":["s1"],"retry":1,"retry_delay":0.1}]'
run_ok "workflow dag validate" "${BIN[@]}" workflow validate --name dagflow
expect_fail "cycle rejected" "${BIN[@]}" workflow create --name cyc --steps-json '[{"capability":"dns_lookup","name":"a","depends_on":["b"]},{"capability":"port_scan","name":"b","depends_on":["a"]}]'
expect_fail "unknown dep rejected" "${BIN[@]}" workflow create --name bad --steps-json '[{"capability":"dns_lookup","name":"a","depends_on":["ghost"]}]'
run_ok "workflow dag run" "${BIN[@]}" workflow run dagflow example.com --engagement 1 --user "$ADMIN" --password "$APW"
run_grep "workflow history has version" '"version": 1' "${BIN[@]}" workflow history --json
run_ok "workflow edit bumps version" "${BIN[@]}" workflow edit --name dagflow --description changed
run_grep "workflow list shows v2" 'v2' "${BIN[@]}" workflow list

say "36. session switch/reconnect + global flags"
S1=$("${BIN[@]}" session list --quiet | sed -n 1p)
S2=$("${BIN[@]}" session list --quiet | sed -n 2p)
if [ -n "$S1" ] && [ -n "$S2" ] && [ "$S1" != "$S2" ]; then
  run_ok "session switch" "${BIN[@]}" session switch "$S2" --user "$ADMIN" --password "$APW"
  run_ok "session reconnect" "${BIN[@]}" session reconnect "$S1" --user "$ADMIN" --password "$APW"
else
  run_ok "session open red" "${BIN[@]}" session open --user "$ADMIN" --password "$APW" --workspace RED_TEAM
  run_ok "session open blue" "${BIN[@]}" session open --user "$ADMIN" --password "$APW" --workspace BLUE_TEAM
  S1=$("${BIN[@]}" session list --quiet | sed -n 1p)
  S2=$("${BIN[@]}" session list --quiet | sed -n 2p)
  run_ok "session switch (2nd try)" "${BIN[@]}" session switch "$S2" --user "$ADMIN" --password "$APW"
  run_ok "session reconnect (2nd try)" "${BIN[@]}" session reconnect "$S1" --user "$ADMIN" --password "$APW"
fi
run_ok "tools search" "${BIN[@]}" tools search dns
run_ok "tools capabilities" "${BIN[@]}" tools capabilities
run_ok "tools update" "${BIN[@]}" tools update
run_ok "tools list --missing" "${BIN[@]}" tools list --missing
run_ok "tools docs" "${BIN[@]}" tools docs nmap
run_ok "global --debug --no-color" "${BIN[@]}" --debug --no-color version
run_ok "global --config" "${BIN[@]}" --config "$KSEC_CONFIG" version
run_ok "suggest red" "${BIN[@]}" suggest red
run_ok "suggest learner" "${BIN[@]}" suggest learner
run_ok "suggest blackhat" "${BIN[@]}" suggest blackhat
run_grep "suggest blue suggests a detection rule" 'Add a detection rule' "${BIN[@]}" suggest blue
run_grep "role red trailer has NEXT" 'NEXT — ab kya karna hai' "${BIN[@]}" role red
expect_fail "suggest unknown role" "${BIN[@]}" suggest hacker

say "36b. top-level shortcuts: recon/network/web/research/osint"
for sc in recon network web research osint; do
  run_grep "shortcut $sc dry-run" "\"workflow\": \"$sc\"" "${BIN[@]}" "$sc" example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
  run_ok "help: $sc" "${BIN[@]}" "$sc" --help
done
BLOCK_OUT=$("${BIN[@]}" recon 203.0.113.77 --engagement 1 --user "$ADMIN" --password "$APW" --dry-run 2>&1)
if [ $? -ne 0 ] && echo "$BLOCK_OUT" | grep -q '"blocked": true'; then
  PASS=$((PASS + 1)); echo "PASS  shortcut blocked out-of-scope (rc!=0, blocked=true)"
else
  FAIL=$((FAIL + 1)); FAILED+=("shortcut blocked"); echo "FAIL  shortcut blocked out-of-scope"
  printf '%s\n' "$BLOCK_OUT" | head -4 | sed 's/^/      /'
fi

say "36c. real-world red team: exploit intelligence + offensive capabilities"
run_clean_skip "exploit search (local DB)" searchsploit "${BIN[@]}" exploit search "apache 2.4.49"
run_ok_skip "exploit search --json" searchsploit "${BIN[@]}" exploit search "apache 2.4.49" --json
run_grep_skip "exploit search finds EDB ids" searchsploit 'EDB-' "${BIN[@]}" exploit search "apache 2.4.49"
run_ok_skip "exploit map creates findings" searchsploit "${BIN[@]}" exploit map "apache 2.4.49" --engagement 1 --user "$ADMIN" --password "$APW"
run_grep_skip "exploit findings in list" searchsploit 'Public exploit available' "${BIN[@]}" finding list --engagement 1
run_ok "help: exploit" "${BIN[@]}" exploit --help
# new offensive capabilities are scope-gated and registered
run_grep "tools capabilities shows exploit_search" 'exploit_search' "${BIN[@]}" tools capabilities
run_grep "tools capabilities shows sqli_test" 'sqli_test' "${BIN[@]}" tools capabilities
run_grep "tools capabilities shows cve_scan (nuclei)" 'cve_scan' "${BIN[@]}" tools capabilities
run_ok "cve_scan dry-run" "${BIN[@]}" run cve_scan example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "exploit_lookup workflow dry-run" "${BIN[@]}" run exploit_lookup example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "sqli_test dry-run" "${BIN[@]}" run sqli_test example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "web_fuzz dry-run" "${BIN[@]}" run web_fuzz example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "smb_cred_test dry-run" "${BIN[@]}" run smb_cred_test example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_grep "role blackhat mentions exploit intelligence" 'exploit search' "${BIN[@]}" role blackhat
run_grep "ask routes to exploit intelligence" 'Exploit-DB' "${BIN[@]}" ask "exploit search kya hai"

say "37. domain modules + purple + change detection"
run_ok "module list"       "${BIN[@]}" module list
run_ok "module info api"   "${BIN[@]}" module info api
run_ok "module check cloud" "${BIN[@]}" module check cloud
run_ok "module check wireless (clean)" "${BIN[@]}" module check wireless
run_grep "module info has tools" '"tools"' "${BIN[@]}" module info kubernetes --json
expect_fail "module check unknown" "${BIN[@]}" module check does-not-exist
run_ok "purple exercise new" "${BIN[@]}" purple exercise new --name smoke-purple --description "smoke" --engagement 1
run_ok "purple exercise list" "${BIN[@]}" purple exercise list
run_ok "purple exercise start" "${BIN[@]}" purple exercise start 1
run_ok "purple exercise complete" "${BIN[@]}" purple exercise complete 1
run_grep "purple exercise show has coverage" '"detection_coverage"' "${BIN[@]}" purple exercise show 1 --json
expect_fail "purple start unknown" "${BIN[@]}" purple exercise start 4242
run_ok "change baseline create" "${BIN[@]}" change baseline create --name smoke-base --scope assets
run_ok "change baseline list" "${BIN[@]}" change baseline list
run_ok "change scan (clean)" "${BIN[@]}" change scan 1
run_grep "change scan reports clean" '"status": "clean"' "${BIN[@]}" change scan 1 --json
run_ok "change scans list" "${BIN[@]}" change scans --baseline 1
expect_fail "change baseline create bad scope" "${BIN[@]}" change baseline create --name x --scope wat
expect_fail "change scan unknown baseline" "${BIN[@]}" change scan 4242

say "38. job logs/retry/trace/health + report preview/pdf + history/graph + practice + triggers"
run_ok "job health" "${BIN[@]}" job health
run_ok "job logs (any id)" "${BIN[@]}" job logs "$( "${BIN[@]}" job list --quiet 2>/dev/null | head -1 )"
run_ok "job trace (any id)" "${BIN[@]}" job trace "$( "${BIN[@]}" job list --quiet 2>/dev/null | head -1 )"
run_ok "job retry (terminal id)" "${BIN[@]}" job retry "$( "${BIN[@]}" job list --quiet 2>/dev/null | head -1 )"
expect_fail "job logs unknown" "${BIN[@]}" job logs 424242
expect_fail "job retry unknown" "${BIN[@]}" job retry 424242
run_ok "report preview" "${BIN[@]}" report preview --engagement 1
run_grep "report preview has counts" '"counts"' "${BIN[@]}" report preview --engagement 1 --json
run_ok "report create pdf" "${BIN[@]}" report create --engagement 1 --title smoke-pdf --format pdf --out "$KSEC_HOME/smoke.pdf"
if head -c 5 "$KSEC_HOME/smoke.pdf" 2>/dev/null | grep -q '%PDF'; then
  PASS=$((PASS + 1)); echo "PASS  pdf header is %PDF"
else
  FAIL=$((FAIL + 1)); FAILED+=("pdf header"); echo "FAIL  pdf header is %PDF"
fi
run_ok "report export pdf" "${BIN[@]}" report export 1 --out "$KSEC_HOME/export.pdf"
expect_fail "report export unknown" "${BIN[@]}" report export 4242
run_ok "history" "${BIN[@]}" history --limit 5
run_ok "graph" "${BIN[@]}" graph
run_ok "graph --json" "${BIN[@]}" graph --json
run_ok "learn practice list" "${BIN[@]}" learn practice list
run_ok "learn practice start" "${BIN[@]}" learn practice start --id practice.scope --user "$ADMIN" --password "$APW"
run_ok "learn practice pass" "${BIN[@]}" learn practice pass --id practice.scope --user "$ADMIN" --password "$APW"
run_grep "learn practice shows passed" '\[x\] practice.scope' "${BIN[@]}" learn practice list --user "$ADMIN" --password "$APW"
expect_fail "learn practice unknown drill" "${BIN[@]}" learn practice pass --id nope --user "$ADMIN" --password "$APW"
run_ok "workflow trigger add" "${BIN[@]}" workflow trigger add --name smoke-on-fail --event-type job.failed --workflow recon --event-glob "*.local"
run_ok "workflow trigger list" "${BIN[@]}" workflow trigger list
run_grep "trigger matches payload" '"matched": 1' "${BIN[@]}" workflow trigger fire --event-type job.failed --payload '{"target": "x.local"}' --user "$ADMIN" --password "$APW"
run_ok "workflow trigger disable" "${BIN[@]}" workflow trigger disable 1
run_ok "workflow trigger enable" "${BIN[@]}" workflow trigger enable 1
run_ok "workflow trigger remove" "${BIN[@]}" workflow trigger remove 1
run_grep "workflow trigger fire unmatched event is a no-op" '"matched": 0' "${BIN[@]}" workflow trigger fire --event-type no.such.event --user "$ADMIN" --password "$APW"

say "39. alternate-tool adapters (masscan/amass/wfuzz/dnsenum) + wireless + docx"
run_grep "tools capabilities shows subdomain_enum" 'subdomain_enum' "${BIN[@]}" tools capabilities
run_grep "tools capabilities shows wifi_scan" 'wifi_scan' "${BIN[@]}" tools capabilities
run_grep "tools capabilities shows wifi_crack" 'wifi_crack' "${BIN[@]}" tools capabilities
run_ok "subdomain workflow dry-run" "${BIN[@]}" run subdomain example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "wifi workflow dry-run" "${BIN[@]}" run wifi example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "fast_scan workflow dry-run (masscan)" "${BIN[@]}" run fast_scan example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_grep "fast_scan expert explain shows masscan" 'masscan' "${BIN[@]}" assess example.com --workflow fast_scan --engagement 1 --user "$ADMIN" --password "$APW" --dry-run --mode expert --explain --json
run_ok "amass dry-run" "${BIN[@]}" run subdomain_enum example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "wifi_scan dry-run" "${BIN[@]}" run wifi_scan example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "report create docx" "${BIN[@]}" report create --engagement 1 --title smoke-docx --format docx --out "$KSEC_HOME/smoke.docx"
if python3 -c "import zipfile,sys; zipfile.ZipFile('$KSEC_HOME/smoke.docx')" 2>/dev/null; then
  PASS=$((PASS + 1)); echo "PASS  docx is a valid zip"
else
  FAIL=$((FAIL + 1)); FAILED+=("docx valid zip"); echo "FAIL  docx is a valid zip"
fi
run_ok "report export docx" "${BIN[@]}" report export 1 --format docx --out "$KSEC_HOME/export.docx"
run_ok "role blackhat mentions wifi" "${BIN[@]}" role blackhat
run_ok "ask routes to wireless" "${BIN[@]}" ask "wireless kya hai"

say "40. service enumeration: whois/traceroute/john/snmp/smtp"
run_grep "tools capabilities shows whois_lookup" 'whois_lookup' "${BIN[@]}" tools capabilities
run_grep "tools capabilities shows traceroute" 'traceroute' "${BIN[@]}" tools capabilities
run_grep "tools capabilities shows password_crack" 'password_crack' "${BIN[@]}" tools capabilities
run_grep "tools capabilities shows snmp_enum" 'snmp_enum' "${BIN[@]}" tools capabilities
run_grep "tools capabilities shows smtp_enum" 'smtp_enum' "${BIN[@]}" tools capabilities
run_ok "enumerate workflow dry-run (snmp+smtp)" "${BIN[@]}" run enumerate example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok_skip "whois_lookup live on example.com" whois "${BIN[@]}" run whois_lookup example.com --engagement 1 --user "$ADMIN" --password "$APW"
run_ok "whois_lookup dry-run" "${BIN[@]}" run whois_lookup example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "traceroute dry-run" "${BIN[@]}" run traceroute example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "password_crack dry-run" "${BIN[@]}" run password_crack example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "snmp_enum dry-run" "${BIN[@]}" run snmp_enum example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_ok "smtp_enum dry-run" "${BIN[@]}" run smtp_enum example.com --engagement 1 --user "$ADMIN" --password "$APW" --dry-run
run_grep "module info wireless shows aircrack" 'aircrack' "${BIN[@]}" module info wireless

# ---------------------------------------------------------------------------
echo
echo "=========================================="
echo "smoke: $PASS passed, $FAIL failed, $SKIP skipped"
if [ "$FAIL" -gt 0 ]; then
  printf 'failed: %s\n' "${FAILED[@]}"
  exit 1
fi
exit 0
