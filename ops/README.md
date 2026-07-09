# ops/ — host persistence & recovery tooling

Cross-harness operational scripts for the **live deployment**, not part of any harness's
runtime (the harnesses stay self-contained; see [CLAUDE.md](../CLAUDE.md) #1). They exist
because the repo working tree *is* the live deployment (in-place model) and the repo
survives a WSL reset via GitHub, but the host runtime around it — OpenClaw, credentials,
venvs, ledgers, the Neo4j graph — does not. See
[docs/PERSISTENCE.md](../docs/PERSISTENCE.md) for the full durability map.

All three are **secret-free** (they hold no tokens/keys) and **idempotent** (safe to run
against a healthy host — it's a near no-op). Each defaults to a read-only `check` and
takes `--apply` to mutate.

| Script | What it does |
|---|---|
| [`bootstrap.sh`](bootstrap.sh) | Rebuild a wiped OpenClaw host runtime. `check` reports the status of every component (uv, OpenClaw, provider/Discord, Prowler venv, agents+`minimal` profile, `operator.admin`, `.env`, state, cron); `--apply` auto-fixes the deterministic pieces and restores `.env`/ledgers/evidence from the latest backup. Secret-bearing steps (Bedrock creds, Discord token, the `operator.admin` gateway-stop edit) are printed, never automated. |
| [`ensure-neo4j.sh`](ensure-neo4j.sh) | Make the Stage 2 graph's Neo4j container durable: named volume, `--restart unless-stopped`, `127.0.0.1`-only ports. `--apply` migrates the old anonymous volume and verifies the node count is preserved. |
| [`backup-state.sh`](backup-state.sh) | Copy the irreplaceable git-ignored state — `evidence.log` (hash-chained audit trail), the 3 `seen.json` ledgers, and the non-secret `.env`s — to a timestamped, rotated dir under `/mnt/c` (survives a WSL reset), with a sha256 manifest. Run from cron for continuous protection. |

## Typical use

```bash
# After a WSL reset, from a fresh clone of this repo:
ops/bootstrap.sh                 # see what's missing
ops/bootstrap.sh --apply         # rebuild the deterministic parts; follow the printed manual steps
ops/ensure-neo4j.sh --apply      # (Stage 2 only) stand up a durable Neo4j, then re-sync Cartography

# Routine protection (ideally from cron):
ops/backup-state.sh              # snapshot ledgers + evidence + .env to /mnt/c
```

## Overrides (env vars)

- `AISEC_BACKUP_DIR` — backup root (default: first writable `/mnt/c/Users/<you>`).
- `AISEC_BACKUP_KEEP` — snapshots to retain (default 14).
- `PROWLER_VENV`, `PY_VERSION`, `OPENCLAW_JSON`, `DEVICES_DIR` — bootstrap paths.
- `VULNTRIAGE_NEO4J_PASSWORD` — Neo4j secret (else recovered from the running container).
- `NEO4J_CONTAINER`, `NEO4J_IMAGE`, `NEO4J_DATA_VOLUME`, `NEO4J_NETWORK`, `NEO4J_HTTP_PORT`,
  `NEO4J_BOLT_PORT`, `NEO4J_HEAP` — ensure-neo4j overrides.
