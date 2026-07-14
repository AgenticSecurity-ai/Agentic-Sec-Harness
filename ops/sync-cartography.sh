#!/usr/bin/env bash
# Copyright (C) 2026 Isao Takaesu
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# sync-cartography.sh — run the Stage 2 Cartography sync with permission-relationships
# baked in PERMANENTLY, so the typed reachability edges survive every recurring sync.
#
# WHY THIS EXISTS. aisec-vulntriage's deeper over-privilege signals (DESIGN §12.11/§12.12)
# key on Cartography's *typed* IAM edges — CAN_PASS_ROLE / GET_SECRET / CAN_READ / … — which
# let the harness flag a principal that can `iam:PassRole` even with no wildcard statement.
# Those edges only exist when the sync is run with `--permission-relationships-file`; a plain
# `cartography` re-sync WRITES NONE of them, so a recurring sync without the flag silently
# strips the edges and the harness reverts to the shallower wildcard proxy (graceful, never
# wrong — just less deep). This script makes the flag the default, so "recurring sync" and
# "reachability stays lit" are the same thing. (Resolves the operational note left open in
# DESIGN §12.9 / §12.12.) It also makes the sync container durable (restart policy), the same
# way ensure-neo4j.sh makes Neo4j durable.
#
#   ops/sync-cartography.sh           # CHECK: report sync readiness + current edge counts
#   ops/sync-cartography.sh --apply   # SYNC:  (make container durable, then) run the sync
#
# SECRET-FREE. The Neo4j password is read from $VULNTRIAGE_NEO4J_PASSWORD, else recovered
# from the running Neo4j container's env (same as ensure-neo4j.sh). AWS is read through the
# READ-ONLY profile ($VULNTRIAGE_AWS_PROFILE, default vulntriage-readonly) mounted into the
# container from ~/.aws — the sync mutates nothing in AWS and needs no IAM beyond the base
# read-only role (permission-relationships is computed from already-synced policy data; see
# DESIGN §12.2 / §12.12). The graph itself is DERIVED and EPHEMERAL — a re-sync just rebuilds
# it from the account, nothing to back up.
#
# MODEL. This targets the containerised Cartography setup (a long-lived `carto` container on
# the `cartonet` Docker network beside `aisec-neo4j`), which is the path a host on a very new
# Python must take anyway (Cartography can't `pip install` on 3.14 — see the harness README
# appendix). Override the names/URIs via the env vars below if your layout differs.

set -uo pipefail

CARTO_CONTAINER="${CARTO_CONTAINER:-carto}"
CARTO_IMAGE="${CARTO_IMAGE:-python:3.12-slim}"
NEO4J_CONTAINER="${NEO4J_CONTAINER:-aisec-neo4j}"
NETWORK="${NEO4J_NETWORK:-cartonet}"
NEO4J_BOLT_URI="${NEO4J_BOLT_URI:-bolt://${NEO4J_CONTAINER}:7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_HTTP="${NEO4J_HTTP:-http://127.0.0.1:7474}"
NEO4J_DB="${NEO4J_DB:-neo4j}"
AWS_PROFILE_SYNC="${VULNTRIAGE_AWS_PROFILE:-vulntriage-readonly}"
AWS_DIR="${AWS_DIR:-$HOME/.aws}"
# Scope the sync to AWS only. Cartography otherwise runs every configured module (azure,
# gcp, …); with only ~/.aws present those stages fail — and, worse, a non-AWS stage that
# crashes AFTER the AWS stage returns a non-zero exit that masks a perfectly good AWS sync.
# The harness only reads AWS nodes, so scope to 'aws'. Override for a multi-cloud graph.
CARTO_MODULES="${CARTO_MODULES:-aws}"

APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

c_ok=$'\033[32m'; c_warn=$'\033[33m'; c_err=$'\033[31m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
pass()  { printf '  %s✓%s %s\n' "$c_ok" "$c_off" "$1"; }
warn()  { printf '  %s!%s %s\n' "$c_warn" "$c_off" "$1"; }
fail()  { printf '  %s✗%s %s\n' "$c_err" "$c_off" "$1"; }
info()  { printf '    %s%s%s\n' "$c_dim" "$1" "$c_off"; }
die()   { fail "$1"; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found"

container_exists() { docker inspect "$1" >/dev/null 2>&1; }
container_running() { [[ "$(docker inspect "$1" --format '{{.State.Running}}' 2>/dev/null)" == "true" ]]; }

neo4j_password() {
  if [[ -n "${VULNTRIAGE_NEO4J_PASSWORD:-}" ]]; then echo "$VULNTRIAGE_NEO4J_PASSWORD"; return; fi
  container_exists "$NEO4J_CONTAINER" \
    && docker inspect "$NEO4J_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
       | sed -n "s#^NEO4J_AUTH=${NEO4J_USER}/##p" | head -1
}

# perm_rel_path — locate the shipped mapping inside the carto container (version-agnostic).
perm_rel_path() {
  docker exec "$CARTO_CONTAINER" python3 -c \
    'import os,cartography;print(os.path.join(os.path.dirname(cartography.__file__),"data","permission_relationships.yaml"))' \
    2>/dev/null
}

# edge_counts <password> — typed permission edges currently in the graph, as "TYPE=N" lines.
edge_counts() {
  curl -s -u "${NEO4J_USER}:$1" -H 'Content-Type: application/json' \
    -d '{"statements":[{"statement":"MATCH ()-[r:CAN_PASS_ROLE|GET_SECRET|CAN_READ|CAN_WRITE|CAN_EXEC|CAN_QUERY|CAN_ADMINISTER|CAN_EXECUTE_COMMAND]->() RETURN type(r) AS t, count(r) AS c ORDER BY t"}]}' \
    "${NEO4J_HTTP}/db/${NEO4J_DB}/tx/commit" 2>/dev/null \
    | grep -o '"row":\[[^]]*\]' | sed 's/"row":\[//; s/\]//; s/",/=/; s/"//g'
}

pass_role_count() { edge_counts "$1" | sed -n 's/^CAN_PASS_ROLE=//p'; }

# ---- check ---------------------------------------------------------------------------
echo "Cartography sync readiness ($CARTO_CONTAINER -> $NEO4J_BOLT_URI)"
READY=1

if container_exists "$CARTO_CONTAINER"; then
  if container_running "$CARTO_CONTAINER"; then pass "sync container '$CARTO_CONTAINER' is running"; else warn "sync container '$CARTO_CONTAINER' exists but is stopped"; READY=0; fi
  restart="$(docker inspect "$CARTO_CONTAINER" --format '{{.HostConfig.RestartPolicy.Name}}' 2>/dev/null)"
  if [[ "$restart" == "unless-stopped" || "$restart" == "always" ]]; then pass "restart policy '$restart' (survives reboot)"; else warn "restart policy '$restart' — sync container is not durable (want unless-stopped)"; READY=0; fi
  if container_running "$CARTO_CONTAINER" && docker exec "$CARTO_CONTAINER" sh -c 'command -v cartography' >/dev/null 2>&1; then
    pass "cartography installed in container"
    PRP="$(perm_rel_path)"
    if [[ -n "$PRP" ]] && docker exec "$CARTO_CONTAINER" test -f "$PRP" 2>/dev/null; then pass "permission_relationships.yaml present"; info "$PRP"; else warn "permission_relationships.yaml not found"; READY=0; fi
  else
    warn "cartography not installed / container not running"; READY=0
  fi
else
  warn "sync container '$CARTO_CONTAINER' does not exist"; READY=0
fi

if ! container_running "$NEO4J_CONTAINER"; then fail "Neo4j container '$NEO4J_CONTAINER' not running — start it (ops/ensure-neo4j.sh)"; READY=0; fi

PW="$(neo4j_password)"
if [[ -n "$PW" ]]; then
  pass "Neo4j password available"
  echo "  current typed reachability edges in the graph:"
  COUNTS="$(edge_counts "$PW")"
  if [[ -n "$COUNTS" ]]; then while IFS= read -r l; do info "$l"; done <<<"$COUNTS"; else info "(none — proxy-only; a permission-relationships sync will create them)"; fi
else
  warn "no Neo4j password (set VULNTRIAGE_NEO4J_PASSWORD or run the Neo4j container)"; READY=0
fi

echo
if (( READY )); then
  pass "ready to sync."
else
  warn "not fully ready (see above)."
fi

if (( ! APPLY )); then
  info "Re-run with --apply to run the permission-relationships sync (rebuilds the graph; read-only against AWS)."
  (( READY )) && exit 0 || exit 1
fi

# ---- apply ---------------------------------------------------------------------------
echo
echo "== running the permission-relationships Cartography sync =="
[[ -z "$PW" ]] && die "no Neo4j password — set VULNTRIAGE_NEO4J_PASSWORD"
container_running "$NEO4J_CONTAINER" || die "Neo4j '$NEO4J_CONTAINER' is not running (ops/ensure-neo4j.sh --apply)"

# 1. ensure the sync container exists, runs, and is durable
docker network inspect "$NETWORK" >/dev/null 2>&1 || { docker network create "$NETWORK" >/dev/null && info "network '$NETWORK' created"; }
if ! container_exists "$CARTO_CONTAINER"; then
  [[ -d "$AWS_DIR" ]] || die "AWS config dir '$AWS_DIR' not found (needed for the read-only profile)"
  info "creating sync container '$CARTO_CONTAINER' ($CARTO_IMAGE, ~/.aws mounted read-only) ..."
  docker run -d --name "$CARTO_CONTAINER" --network "$NETWORK" --restart unless-stopped \
    -v "$AWS_DIR":/root/.aws:ro "$CARTO_IMAGE" sleep infinity >/dev/null \
    || die "failed to create '$CARTO_CONTAINER'"
  info "installing cartography (one-time, a few minutes) ..."
  docker exec "$CARTO_CONTAINER" pip install --quiet cartography >/dev/null \
    || die "cartography install failed"
  pass "sync container created"
else
  container_running "$CARTO_CONTAINER" || { docker start "$CARTO_CONTAINER" >/dev/null && info "started '$CARTO_CONTAINER'"; }
  restart="$(docker inspect "$CARTO_CONTAINER" --format '{{.HostConfig.RestartPolicy.Name}}' 2>/dev/null)"
  if [[ "$restart" != "unless-stopped" && "$restart" != "always" ]]; then
    docker update --restart unless-stopped "$CARTO_CONTAINER" >/dev/null && pass "restart policy set to unless-stopped"
  fi
fi

PRP="$(perm_rel_path)"
[[ -n "$PRP" ]] && docker exec "$CARTO_CONTAINER" test -f "$PRP" || die "permission_relationships.yaml not found in '$CARTO_CONTAINER'"
info "mapping: $PRP"

BEFORE="$(pass_role_count "$PW")"
info "CAN_PASS_ROLE edges before: ${BEFORE:-0}"

# 2. run the sync WITH permission-relationships (the whole point)
info "syncing (AWS_PROFILE=$AWS_PROFILE_SYNC, read-only) — this rebuilds the graph, a few minutes ..."
if docker exec \
     -e NEO4J_SYNC_PW="$PW" \
     -e AWS_PROFILE="$AWS_PROFILE_SYNC" \
     "$CARTO_CONTAINER" \
     cartography --neo4j-uri "$NEO4J_BOLT_URI" \
       --neo4j-user "$NEO4J_USER" --neo4j-password-env-var NEO4J_SYNC_PW \
       --selected-modules "$CARTO_MODULES" \
       --permission-relationships-file "$PRP"; then
  pass "cartography sync completed"
else
  die "cartography sync failed (graph left as-is; re-run once the cause is fixed)"
fi

# 3. verify the typed edges are present (this is what a plain sync would have stripped)
echo
AFTER="$(pass_role_count "$PW")"
COUNTS="$(edge_counts "$PW")"
if [[ -n "$COUNTS" ]]; then
  pass "typed reachability edges present after sync:"
  while IFS= read -r l; do info "$l"; done <<<"$COUNTS"
  info "CAN_PASS_ROLE: ${BEFORE:-0} -> ${AFTER:-0}"
else
  fail "NO typed reachability edges after sync — permission-relationships did not take effect (check the mapping path / cartography version)"
  exit 1
fi

echo
pass "done. Schedule this script (not a bare 'cartography') as your recurring sync so reachability stays lit."
info "Verify from the harness: python3 harnesses/aisec-vulntriage/skills/aisec-vulntriage/collect.py graph-check"
