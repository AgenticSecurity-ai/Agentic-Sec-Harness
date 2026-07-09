#!/usr/bin/env bash
# Copyright (C) 2026 Isao Takaesu
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# backup-state.sh — copy the irreplaceable, git-ignored host-runtime state to a
# reset-safe location. See docs/PERSISTENCE.md for the durability map.
#
# What it backs up (the two 🔴 "no regeneration path" items):
#   - harnesses/aisec-vulntriage/state/evidence.log   (append-only hash-chained audit trail)
#   - harnesses/*/state/seen.json                       (dedup ledgers; losing them → re-post burst)
#
# Where it writes: a timestamped dir under a backup root. On WSL the default root is the
# first writable /mnt/c/Users/<you> dir (the Windows filesystem survives a WSL distro
# reset, unlike ~). Override with AISEC_BACKUP_DIR=/path.
#
# Safe to run repeatedly (e.g. from cron). Read-only w.r.t. the repo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- resolve a reset-safe backup root -------------------------------------------------
resolve_backup_root() {
  if [[ -n "${AISEC_BACKUP_DIR:-}" ]]; then
    echo "$AISEC_BACKUP_DIR"
    return
  fi
  # WSL: prefer a writable Windows user home (survives a WSL distro reset).
  if [[ -d /mnt/c/Users ]]; then
    for d in /mnt/c/Users/*/; do
      case "$(basename "$d")" in
        Public|Default|"Default User"|"All Users") continue ;;
      esac
      if [[ -w "$d" ]]; then
        echo "${d%/}/aisec-harness-backups"
        return
      fi
    done
  fi
  # Fallback: home dir. NOT reset-safe — warn on stderr.
  echo "WARN: no writable /mnt/c/Users dir found; falling back to \$HOME (NOT WSL-reset-safe)" >&2
  echo "$HOME/aisec-harness-backups"
}

BACKUP_ROOT="$(resolve_backup_root)"
STAMP="$(date +%Y%m%d-%H%M%S)"
DEST="$BACKUP_ROOT/$STAMP"
KEEP="${AISEC_BACKUP_KEEP:-14}"   # how many timestamped snapshots to retain

# git-ignored state worth preserving (relative to repo root). The .env files hold only
# NON-SECRET deployment values (channel ids, agent ids, host paths — see CLAUDE.md #3);
# preserving them makes a rebuild trivial. Secrets (bot token, Neo4j password, model
# creds) live in the host's OpenClaw config / env, never in .env, so they are NOT here.
FILES=(
  "harnesses/aisec-vulntriage/state/evidence.log"
  "harnesses/aisec-vulntriage/state/seen.json"
  "harnesses/aisec-arxiv-monitor/state/seen.json"
  "harnesses/aisec-news-monitor/state/seen.json"
  "harnesses/aisec-vulntriage/.env"
  "harnesses/aisec-arxiv-monitor/.env"
  "harnesses/aisec-news-monitor/.env"
)

mkdir -p "$DEST"
MANIFEST="$DEST/MANIFEST.txt"
{
  echo "aisec-harness state backup"
  echo "created: $STAMP"
  echo "repo:    $REPO_ROOT"
  echo "---"
} > "$MANIFEST"

copied=0
missing=0
for rel in "${FILES[@]}"; do
  src="$REPO_ROOT/$rel"
  if [[ ! -f "$src" ]]; then
    echo "MISSING  $rel" | tee -a "$MANIFEST"
    missing=$((missing + 1))
    continue
  fi
  mkdir -p "$DEST/$(dirname "$rel")"
  cp -p "$src" "$DEST/$rel"
  sum="$(sha256sum "$src" | cut -d' ' -f1)"
  # line/entry count is a cheap integrity signal for the JSONL evidence log and JSON ledgers
  lines="$(wc -l < "$src" | tr -d ' ')"
  printf 'OK  %-52s  lines=%-6s  sha256=%s\n' "$rel" "$lines" "$sum" | tee -a "$MANIFEST"
  copied=$((copied + 1))
done

# --- rotate: keep the newest $KEEP snapshots -----------------------------------------
if [[ -d "$BACKUP_ROOT" ]]; then
  mapfile -t snaps < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -name '20*' | sort)
  n="${#snaps[@]}"
  if (( n > KEEP )); then
    prune=$(( n - KEEP ))
    for ((i = 0; i < prune; i++)); do
      rm -rf "${snaps[$i]}"
      echo "rotated out: ${snaps[$i]}"
    done
  fi
fi

echo "---"
echo "backup dir: $DEST"
echo "copied=$copied missing=$missing (retain last $KEEP snapshots)"
if (( missing > 0 )); then
  echo "note: missing files are expected if a harness has never run on this host yet." >&2
fi
