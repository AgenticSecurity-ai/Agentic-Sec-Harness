#!/usr/bin/env bash
# Copyright (C) 2026 Isao Takaesu
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# bootstrap.sh — rebuild a wiped OpenClaw host runtime for the aisec harnesses.
#
# The repo working tree IS the live deployment (in-place model), and the repo survives a
# WSL reset via GitHub. Everything an operator supplies at deploy time — the OpenClaw
# runtime, credentials, Python venvs, ledgers — does NOT survive. This script re-derives
# the deterministic parts and tells you exactly which secret-bearing steps only a human
# can do. See docs/PERSISTENCE.md for the full durability map.
#
# It is SECRET-FREE by design (nothing here belongs in git that shouldn't) and IDEMPOTENT:
# running it against a healthy host is a near no-op that just reports "present".
#
#   ops/bootstrap.sh            # CHECK: read-only status of every component (default)
#   ops/bootstrap.sh --apply    # APPLY: auto-fix the deterministic pieces; guide the rest
#
# Auto-fixable (under --apply): uv, OpenClaw CLI, Prowler venv, agent registration +
# minimal profile, .env / ledger / evidence restore-from-backup, cron (created disabled).
# Manual (printed, never automated — they need secrets or a gateway-stop edit): Bedrock
# provider creds, Discord bot token + channel allowlist, the operator.admin grant.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- overridable config (defaults match the current host) ----------------------------
PROWLER_VENV="${PROWLER_VENV:-$HOME/.local/share/aisec-vulntriage/prowler-venv}"
OPENCLAW_JSON="${OPENCLAW_JSON:-$HOME/.openclaw/openclaw.json}"
DEVICES_DIR="${DEVICES_DIR:-$HOME/.openclaw/devices}"
PY_VERSION="${PY_VERSION:-3.12}"   # Prowler/Cartography can't build on host py3.14

# agent name -> harness dir (workspace). Order matters only for readability.
AGENT_NAMES=(arxiv aisec-news aisec-vulntriage)
declare -A AGENT_DIR=(
  [arxiv]="harnesses/aisec-arxiv-monitor"
  [aisec-news]="harnesses/aisec-news-monitor"
  [aisec-vulntriage]="harnesses/aisec-vulntriage"
)

APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

# ---- pretty status -------------------------------------------------------------------
c_ok=$'\033[32m'; c_warn=$'\033[33m'; c_err=$'\033[31m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
PASS=0; WARN=0; FAIL=0
pass()  { printf '  %s✓%s %s\n' "$c_ok" "$c_off" "$1"; PASS=$((PASS+1)); }
warn()  { printf '  %s!%s %s\n' "$c_warn" "$c_off" "$1"; WARN=$((WARN+1)); }
fail()  { printf '  %s✗%s %s\n' "$c_err" "$c_off" "$1"; FAIL=$((FAIL+1)); }
info()  { printf '    %s%s%s\n' "$c_dim" "$1" "$c_off"; }
hdr()   { printf '\n%s\n' "$1"; }
run()   { info "\$ $*"; "$@"; }

# ---- backup discovery (for restore) --------------------------------------------------
latest_backup() {
  local root d
  for d in /mnt/c/Users/*/aisec-harness-backups; do
    [[ -d "$d" ]] || continue
    root="$d"; break
  done
  [[ -n "${AISEC_BACKUP_DIR:-}" && -d "$AISEC_BACKUP_DIR" ]] && root="$AISEC_BACKUP_DIR"
  [[ -z "${root:-}" ]] && return 1
  find "$root" -mindepth 1 -maxdepth 1 -type d -name '20*' 2>/dev/null | sort | tail -1
}
restore_file() {  # restore_file <repo-relative-path>; only if missing locally
  local rel="$1" bkp
  [[ -f "$REPO_ROOT/$rel" ]] && return 0
  bkp="$(latest_backup)" || return 1
  if [[ -n "$bkp" && -f "$bkp/$rel" ]]; then
    mkdir -p "$REPO_ROOT/$(dirname "$rel")"
    cp -p "$bkp/$rel" "$REPO_ROOT/$rel"
    info "restored $rel from $bkp"
    return 0
  fi
  return 1
}

# =====================================================================================
hdr "[1/9] uv (manages the py${PY_VERSION} venvs; host py is 3.14)"
if command -v uv >/dev/null 2>&1; then
  pass "uv present ($(uv --version 2>/dev/null))"
elif (( APPLY )); then
  run bash -c 'curl -LsSf https://astral.sh/uv/install.sh | sh' && pass "uv installed" || fail "uv install failed"
else
  fail "uv missing — apply: curl -LsSf https://astral.sh/uv/install.sh | sh"
fi

hdr "[2/9] OpenClaw CLI + Node runtime"
if command -v openclaw >/dev/null 2>&1; then
  pass "openclaw present ($(openclaw --version 2>/dev/null | head -1))"
elif (( APPLY )); then
  run bash -c 'curl -fsSL https://openclaw.ai/install.sh | sh' && pass "openclaw installed" || fail "openclaw install failed"
else
  fail "openclaw missing — apply: curl -fsSL https://openclaw.ai/install.sh | sh"
fi

hdr "[3/9] Model provider (Bedrock) + Discord channel — MANUAL (secrets)"
if [[ -f "$OPENCLAW_JSON" ]] && grep -q 'amazon-bedrock' "$OPENCLAW_JSON" 2>/dev/null; then
  pass "amazon-bedrock provider configured"
else
  fail "Bedrock provider not configured — re-onboard with AWS creds (see docs/HOST-SETUP.md §2)"
fi
if [[ -f "$OPENCLAW_JSON" ]] && grep -q '"discord"' "$OPENCLAW_JSON" 2>/dev/null; then
  pass "discord channel configured"
else
  fail "Discord not configured — re-onboard bot token + channel allowlist (docs/HOST-SETUP.md §3)"
fi
info "these two need secrets a script must not hold; do them by hand, then re-run --apply"

hdr "[4/9] Prowler venv (py${PY_VERSION}, for aisec-vulntriage)"
if [[ -x "$PROWLER_VENV/bin/prowler" ]]; then
  pass "prowler present ($("$PROWLER_VENV/bin/prowler" --version 2>/dev/null | head -1))"
elif (( APPLY )); then
  if command -v uv >/dev/null 2>&1; then
    run uv venv --python "$PY_VERSION" "$PROWLER_VENV" \
      && run uv pip install --python "$PROWLER_VENV" prowler \
      && pass "prowler venv built" || fail "prowler venv build failed"
  else
    fail "need uv first (step 1)"
  fi
else
  fail "prowler venv missing — apply builds it at $PROWLER_VENV"
fi

hdr "[5/9] Agents registered with 'minimal' profile (B2 invariant)"
agent_profile() {  # echo the tools.profile for agent <name> from openclaw.json
  python3 - "$OPENCLAW_JSON" "$1" <<'PY' 2>/dev/null
import json,sys
try:
    d=json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
for a in d.get("agents",{}).get("list",[]):
    if a.get("name")==sys.argv[2]:
        print((a.get("tools") or {}).get("profile","")); break
PY
}
for name in "${AGENT_NAMES[@]}"; do
  ws="$REPO_ROOT/${AGENT_DIR[$name]}"
  if openclaw agents list 2>/dev/null | grep -q "^- $name\b\|^- $name$\|- $name$"; then
    prof="$(agent_profile "$name")"
    if [[ "$prof" == "minimal" ]]; then
      pass "$name registered (minimal)"
    else
      warn "$name registered but profile='${prof:-?}' (must be minimal for B2)"
      (( APPLY )) && info "fix: locate its index in agents.list and: openclaw config set 'agents.list[<idx>].tools' '{\"profile\":\"minimal\"}' && restart"
    fi
  elif (( APPLY )); then
    run openclaw agents add "$name" --workspace "$ws" \
      && info "now set minimal: openclaw config set 'agents.list[<idx>].tools' '{\"profile\":\"minimal\"}'" \
      && warn "$name added — SET minimal profile + restart, then re-run check" || fail "$name add failed"
  else
    fail "$name not registered — apply: openclaw agents add $name --workspace $ws (then set minimal)"
  fi
done

hdr "[6/9] operator.admin scope (cron management) — MANUAL (gateway-stop edit)"
if grep -rq 'operator.admin' "$DEVICES_DIR" 2>/dev/null; then
  pass "operator.admin present on a paired device"
else
  fail "operator.admin missing — with the gateway stopped, add it to a device's scopes/approvedScopes in $DEVICES_DIR/paired.json, then restart (docs/HOST-SETUP.md §4 fallback)"
fi

hdr "[7/9] .env deployment files (non-secret; restore from backup if wiped)"
for name in "${AGENT_NAMES[@]}"; do
  rel="${AGENT_DIR[$name]}/.env"
  if [[ -f "$REPO_ROOT/$rel" ]]; then
    pass "$rel present"
  elif (( APPLY )) && restore_file "$rel"; then
    pass "$rel restored from backup"
  else
    fail "$rel missing — restore from /mnt/c backup, or copy ${rel%.env}.env.example and fill in ids"
  fi
done

hdr "[8/9] State: dedup ledgers + evidence log (restore from backup if wiped)"
for rel in \
  "harnesses/aisec-vulntriage/state/evidence.log" \
  "harnesses/aisec-vulntriage/state/seen.json" \
  "harnesses/aisec-arxiv-monitor/state/seen.json" \
  "harnesses/aisec-news-monitor/state/seen.json"; do
  if [[ -f "$REPO_ROOT/$rel" ]]; then
    pass "$(basename "$(dirname "$(dirname "$rel")")")/$(basename "$rel") present ($(wc -l < "$REPO_ROOT/$rel" | tr -d ' ') lines)"
  elif (( APPLY )) && restore_file "$rel"; then
    pass "$rel restored from backup"
  else
    warn "$rel absent — a fresh start re-posts current open items once (burst, not data loss)"
  fi
done

hdr "[9/9] cron job (vulntriage-weekday) — created DISABLED for safety"
if openclaw cron list 2>/dev/null | grep -qi 'vulntriage'; then
  pass "vulntriage cron exists"
else
  if (( APPLY )); then
    warn "cron absent — NOT auto-creating (needs operator.admin + a deliberate enable decision)"
    info "create disabled: openclaw cron add vulntriage-weekday --schedule '0 8 * * 1-5' --tz Asia/Tokyo \\"
    info "  --command 'python3 $REPO_ROOT/harnesses/aisec-vulntriage/skills/aisec-vulntriage/run.py' \\"
    info "  --command-cwd '$REPO_ROOT/harnesses/aisec-vulntriage' --no-deliver --timeout-seconds 1800 --disabled"
  else
    warn "no vulntriage cron (expected until you deliberately enable scheduling)"
  fi
fi

# ---- summary -------------------------------------------------------------------------
hdr "summary: ${PASS} ok, ${WARN} warn, ${FAIL} fail  ($( ((APPLY)) && echo APPLY || echo check ) mode)"
if (( FAIL > 0 )); then
  info "run 'ops/bootstrap.sh --apply' to auto-fix deterministic items; the MANUAL steps above need you"
fi
info "Neo4j (Stage 2 graph) durability is handled separately: ops/ensure-neo4j.sh"
exit 0
