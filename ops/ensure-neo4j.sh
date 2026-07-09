#!/usr/bin/env bash
# Copyright (C) 2026 Isao Takaesu
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ensure-neo4j.sh — make the Stage 2 graph's Neo4j container DURABLE.
#
# The graph (Cartography-populated Neo4j) backs aisec-vulntriage's Stage 2 exposure /
# blast-radius facts. A hand-started `docker run` leaves it fragile: an anonymous volume
# (lost on `docker rm`), no restart policy (gone after a reboot), and — worse — ports
# published on 0.0.0.0, which contradicts config.toml's "the graph is a sensitive map of
# your asset topology and must never be network-exposed" (DESIGN §12.3).
#
# This script recreates `aisec-neo4j` with:
#   - a NAMED volume (aisec-neo4j-data) so data survives `docker rm` / recreation,
#   - --restart unless-stopped so it auto-starts after a reboot,
#   - ports bound to 127.0.0.1 only (localhost, per config),
#   - the cartonet network kept so the Cartography container can still reach it.
# Existing graph data is migrated from the old anonymous volume (never deleted), and the
# node count is verified equal before/after.
#
#   ops/ensure-neo4j.sh           # CHECK: report current durability, no changes
#   ops/ensure-neo4j.sh --apply   # MIGRATE: recreate durably, preserving data
#
# The Neo4j password is a SECRET: read from $VULNTRIAGE_NEO4J_PASSWORD, else recovered
# from the existing container's env (used only to verify the node count). Preserving the
# volume also preserves the password (Neo4j ignores NEO4J_AUTH once /data is initialized).

set -uo pipefail

CONTAINER="${NEO4J_CONTAINER:-aisec-neo4j}"
IMAGE="${NEO4J_IMAGE:-neo4j:5.26}"
DATA_VOL="${NEO4J_DATA_VOLUME:-aisec-neo4j-data}"
NETWORK="${NEO4J_NETWORK:-cartonet}"
HTTP_PORT="${NEO4J_HTTP_PORT:-7474}"
BOLT_PORT="${NEO4J_BOLT_PORT:-7687}"
HEAP="${NEO4J_HEAP:-1G}"

APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

c_ok=$'\033[32m'; c_warn=$'\033[33m'; c_err=$'\033[31m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
pass()  { printf '  %s✓%s %s\n' "$c_ok" "$c_off" "$1"; }
warn()  { printf '  %s!%s %s\n' "$c_warn" "$c_off" "$1"; }
fail()  { printf '  %s✗%s %s\n' "$c_err" "$c_off" "$1"; }
info()  { printf '    %s%s%s\n' "$c_dim" "$1" "$c_off"; }
die()   { fail "$1"; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found"

container_exists() { docker inspect "$CONTAINER" >/dev/null 2>&1; }
inspect() { docker inspect "$CONTAINER" --format "$1" 2>/dev/null; }

neo4j_password() {
  if [[ -n "${VULNTRIAGE_NEO4J_PASSWORD:-}" ]]; then echo "$VULNTRIAGE_NEO4J_PASSWORD"; return; fi
  container_exists && inspect '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^NEO4J_AUTH=neo4j\///p' | head -1
}

node_count() {  # node_count <http_base> <password> ; echoes integer or nothing
  curl -s -u "neo4j:$2" -H 'Content-Type: application/json' \
    -d '{"statements":[{"statement":"MATCH (n) RETURN count(n) AS n"}]}' \
    "$1/db/neo4j/tx/commit" 2>/dev/null | grep -o '"row":\[[0-9]*\]' | grep -o '[0-9]*' | head -1
}

wait_http() {  # wait_http <port> ; up to ~90s
  local i
  for i in $(seq 1 45); do
    curl -sf "http://127.0.0.1:$1" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}

# ---- current state -------------------------------------------------------------------
echo "Neo4j durability check ($CONTAINER)"
DURABLE=1
if ! container_exists; then
  fail "container '$CONTAINER' does not exist"
  DURABLE=0
else
  restart="$(inspect '{{.HostConfig.RestartPolicy.Name}}')"
  data_vol="$(inspect '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}')"
  # is /data a named volume matching DATA_VOL?
  if [[ "$data_vol" == "$DATA_VOL" ]]; then pass "data on named volume '$DATA_VOL'"; else warn "data on volume '${data_vol:-none}' (want named '$DATA_VOL')"; DURABLE=0; fi
  if [[ "$restart" == "unless-stopped" || "$restart" == "always" ]]; then pass "restart policy '$restart'"; else warn "restart policy '$restart' (want unless-stopped)"; DURABLE=0; fi
  # localhost binding?
  binds="$(inspect '{{range $p,$b := .HostConfig.PortBindings}}{{range $b}}{{.HostIp}} {{end}}{{end}}')"
  if echo "$binds" | grep -qE '0\.0\.0\.0|^ *$|::'; then warn "ports not localhost-only (HostIp: ${binds:-empty}) — want 127.0.0.1"; DURABLE=0; else pass "ports bound to 127.0.0.1"; fi
fi

if (( DURABLE )); then
  pass "already durable — no change needed"
  PW="$(neo4j_password)"
  [[ -n "$PW" ]] && info "node count: $(node_count "http://127.0.0.1:$HTTP_PORT" "$PW") "
  exit 0
fi

if (( ! APPLY )); then
  echo
  info "not durable. Re-run with --apply to migrate (data preserved, node count verified)."
  exit 1
fi

# ---- migrate -------------------------------------------------------------------------
echo
echo "== migrating to a durable Neo4j (data preserved) =="
PW="$(neo4j_password)"
[[ -z "$PW" ]] && warn "no password available — will skip post-migration node-count verification"

# baseline node count (best-effort, before we touch anything)
BASE=""
if container_exists && [[ -n "$PW" ]]; then
  BASE="$(node_count "http://127.0.0.1:$HTTP_PORT" "$PW")"
  info "baseline node count: ${BASE:-unknown}"
fi

# 1. named volume + network
docker volume create "$DATA_VOL" >/dev/null && info "named volume '$DATA_VOL' ready"
docker network inspect "$NETWORK" >/dev/null 2>&1 || { docker network create "$NETWORK" >/dev/null && info "network '$NETWORK' created"; }

# 2. locate old /data volume, stop container, copy data into the named volume (if empty)
if container_exists; then
  OLD_DATA_VOL="$(inspect '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}')"
  info "old /data volume: ${OLD_DATA_VOL:-none}"
  docker stop "$CONTAINER" >/dev/null && info "stopped $CONTAINER"
  # only copy if the named volume is empty and differs from the old one
  if [[ -n "$OLD_DATA_VOL" && "$OLD_DATA_VOL" != "$DATA_VOL" ]]; then
    NAMED_EMPTY="$(docker run --rm -v "$DATA_VOL":/to alpine sh -c 'ls -A /to 2>/dev/null | head -1')"
    if [[ -z "$NAMED_EMPTY" ]]; then
      info "copying data from '$OLD_DATA_VOL' -> '$DATA_VOL' ..."
      docker run --rm -v "$OLD_DATA_VOL":/from:ro -v "$DATA_VOL":/to alpine sh -c 'cp -a /from/. /to/' \
        && info "data copied" || die "data copy failed (old container left stopped; nothing removed)"
    else
      info "named volume already populated — skipping copy"
    fi
  fi
  # 3. remove old container (data is safe in both volumes)
  docker rm "$CONTAINER" >/dev/null && info "removed old container definition"
fi

# 4. recreate durably
AUTH_ARGS=()
[[ -n "$PW" ]] && AUTH_ARGS=(-e "NEO4J_AUTH=neo4j/$PW")   # ignored if /data already initialized
docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  --network "$NETWORK" \
  -p "127.0.0.1:$HTTP_PORT:7474" \
  -p "127.0.0.1:$BOLT_PORT:7687" \
  -v "$DATA_VOL":/data \
  -e "NEO4J_server_memory_heap_max__size=$HEAP" \
  "${AUTH_ARGS[@]}" \
  "$IMAGE" >/dev/null && info "recreated $CONTAINER (named volume, restart=unless-stopped, 127.0.0.1)" \
  || die "docker run failed"

# 5. wait + verify
info "waiting for Neo4j HTTP on 127.0.0.1:$HTTP_PORT ..."
if wait_http "$HTTP_PORT"; then
  pass "Neo4j is up"
else
  die "Neo4j did not become ready in time — inspect: docker logs $CONTAINER"
fi

if [[ -n "$PW" ]]; then
  NOW="$(node_count "http://127.0.0.1:$HTTP_PORT" "$PW")"
  info "post-migration node count: ${NOW:-unknown}"
  if [[ -n "$BASE" && -n "$NOW" ]]; then
    if [[ "$BASE" == "$NOW" ]]; then pass "node count preserved ($NOW)"; else fail "NODE COUNT CHANGED: $BASE -> $NOW (old anon volume still intact for recovery)"; fi
  fi
fi

echo
pass "durable. The old anonymous volume was NOT deleted — reclaim it later with 'docker volume prune' once satisfied."
