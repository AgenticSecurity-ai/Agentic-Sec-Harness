# PERSISTENCE — what survives a WSL reset, and what doesn't

Companion to [HOST-SETUP.md](HOST-SETUP.md). HOST-SETUP is the *first-time* bootstrap;
this file is the **durability map**: which pieces of a running deployment live in git
(and are therefore safe) versus which live only in host runtime (and vanish when the WSL
distro is reset / reinstalled). It exists because this deployment has been wiped and
hand-rebuilt from scratch **multiple times** — each rebuild re-derived the same facts.
This page freezes them so the next rebuild is mechanical, and so we can decide what to
harden.

> **Why this matters.** The repo working tree *is* the live deployment (in-place model:
> the OpenClaw agents' `--workspace` points straight at `harnesses/<name>/`). So the code
> and committed config are as durable as git. But everything an operator supplies at
> deploy time — credentials, the OpenClaw runtime itself, Python venvs, the dedup
> ledgers, the evidence log, the Neo4j graph — is **host runtime state** and is not in
> git. A WSL reset takes all of it.

## The map (verified 2026-07-07)

Legend — **Recovery cost**: 🟢 free/idempotent (regenerates itself or costs nothing to
lose) · 🟡 scripted (a few commands, no judgement) · 🔴 manual/irreplaceable (needs a
human decision or loses history).

### Persistent — survives a WSL reset

| Thing | Where | Notes |
|---|---|---|
| Harness code, `config.toml`, personas, SKILL/DESIGN/README | git (this repo) | The source of truth. In-place: agents run *from* here. |
| `.env.example` templates | git | Documents which non-secret keys each `.env` needs. |
| `~/.aws/config` + credentials (`vulntriage-readonly` profile, `role_arn` → `SecurityAudit`+`ViewOnlyAccess`) | `~/.aws/` | Outside the repo but the user re-placed it; survived the last reset. Not guaranteed by anything — treat as 🔴 if `~` is wiped too. |
| Neo4j graph **data** | Docker **named** volume `aisec-neo4j-data` (`--restart unless-stopped`, bound to `127.0.0.1`) | Survives container recreation and reboots (made durable by [`ops/ensure-neo4j.sh`](../ops/ensure-neo4j.sh)). Even if the whole Docker backend is lost: 🟢 Cartography re-syncs it from AWS (read-only, idempotent). |

### Volatile — wiped by a WSL reset

| Thing | Where | Recovery | Cost |
|---|---|---|---|
| OpenClaw CLI + Node runtime | `~/.npm-global`, npm | `curl openclaw.ai/install.sh` | 🟡 |
| `~/.openclaw/` — provider (Bedrock) creds, Discord bot token + channel allowlist, `openclaw.json`, registered agents, `devices/paired.json` scopes, **cron jobs** | `~/.openclaw/` | Re-onboard: Bedrock provider, Discord token+channels, re-register 4 agents with `minimal` profile, re-grant `operator.admin` in `paired.json`, recreate cron | 🔴 (many steps, secrets, self-approval-loop workaround) |
| `.env` × 3 (non-secret deploy values: channel ids, agent ids, `OPENCLAW_BIN`, `PROWLER_BIN`, `VULNTRIAGE_AWS_PROFILE`) | `harnesses/*/.env` (git-ignored) | Regenerate from `.env.example` + recovered channel/agent ids | 🟡 |
| `VULNTRIAGE_NEO4J_PASSWORD` (secret) | host env | Recover from the Neo4j container's env, or reset the graph | 🟡 |
| Prowler venv (5.32.0, **py3.12**) | `~/.local/share/aisec-vulntriage/prowler-venv` | `uv` → managed py3.12 → `pip install prowler` (host py is 3.14 → Prowler & Cartography won't install on it) | 🟡 |
| Cartography venv / `carto` container (py3.12) | `~/.local/share/.../cartography-venv`, Docker `carto` | Rebuild in a `python:3.12-slim` container (py3.14 can't build `oci`→`crc32c==2.7.1`) | 🟡 |
| `uv` | (not currently installed) | `curl -LsSf astral.sh/uv/install.sh` | 🟢 |
| Dedup ledgers `state/seen.json` × 3 (arxiv 266 / news 270 / vulntriage 160) | `harnesses/*/state/` (git-ignored) | **None.** Losing it → every currently-open item re-posts once (burst, not data loss). vulntriage re-baselines by design. | 🔴 (history) |
| Evidence log `state/evidence.log` (160 entries, hash-chained) | `harnesses/aisec-vulntriage/state/` (git-ignored) | **None.** The audit trail is the point — losing it is losing the chain. | 🔴 (irreplaceable) |

## Drift found while mapping (2026-07-07), and what was done

- **cron fully gone.** `openclaw cron list` → *No cron jobs*. STATUS.md recorded
  `vulntriage-weekday` as recreated-but-disabled; it has since vanished. The deployment
  eroded further between sessions even without a full reset. → bootstrap prints the
  exact (disabled) recreate command; not auto-created (needs a deliberate enable).
- **`uv` gone.** Needed to rebuild the py3.12 venvs. → **Fixed**: `bootstrap.sh --apply`
  reinstalled it.
- **Neo4j was bound to `0.0.0.0:7474/7687`, not localhost** — violating `config.toml
  [graph]` ("the graph is a sensitive map of your asset topology and must never be
  network-exposed"). → **Fixed**: recreated bound to `127.0.0.1` only.
- **Neo4j/carto had `restart=no` + anonymous volumes** (lost on `docker rm`; no
  auto-start on reboot). → **Fixed** for Neo4j: migrated to named volume
  `aisec-neo4j-data` + `--restart unless-stopped` (data preserved, node count verified
  2863 → 2863). The `carto` (Cartography) container is a transient sync worker, not a
  data store — it's fine to recreate on demand.

## Persistence tooling (built — see [`ops/`](../ops/))

All three workstreams are implemented and were validated on the live host (2026-07-07).
Ordered by leverage.

- **(a) One-command rebuild script — [`ops/bootstrap.sh`](../ops/bootstrap.sh).** It
  lives **in the repo**: the repo survives a WSL reset (it re-clones from GitHub), so an
  in-repo script is *more* durable than one under `~`, and it gets versioned + reviewed.
  The constraint is only that it be **secret-free** (it holds no tokens/keys and no
  hardcoded host paths — everything is overridable and secrets stay in the OpenClaw
  config / env). Two modes: default `check` (read-only status of every component) and
  `--apply` (auto-fix the deterministic pieces). Auto-fixable: `uv`, OpenClaw CLI,
  py3.12 Prowler venv, agent registration + `minimal` profile, `.env`/ledger/evidence
  restore-from-backup, cron. Printed-only (need a human/secret): Bedrock creds, Discord
  token + channels, the `operator.admin` gateway-stop edit. Turns 🔴 `~/.openclaw`
  recovery into 🟡. *Highest-leverage single item.* Backups feed it:
  [`ops/backup-state.sh`](../ops/backup-state.sh) copies the git-ignored state (ledgers,
  evidence log, non-secret `.env`s) to `/mnt/c`, and bootstrap restores from there.
- **(b) Durable Neo4j — [`ops/ensure-neo4j.sh`](../ops/ensure-neo4j.sh).** Recreates
  `aisec-neo4j` with a **named volume** + `--restart unless-stopped` + **`127.0.0.1`
  bind**, migrating the old anonymous volume's data and verifying the node count is
  unchanged. A Docker/WSL restart now keeps the graph and it comes back automatically;
  only a full Docker reset needs a Cartography re-sync (idempotent). `check` mode reports
  durability; `--apply` migrates. This is the prerequisite for turning the cron's
  `[graph].enabled=true` on safely.
- **(c) Repo-external backup of irreplaceable state —
  [`ops/backup-state.sh`](../ops/backup-state.sh).** Copies the 🔴 no-regeneration-path
  items — `evidence.log` (audit chain), the 3 `seen.json` ledgers, and the non-secret
  `.env`s — to a timestamped, rotated dir under `/mnt/c` (Windows FS, survives a WSL
  reset), with a sha256 manifest. Run it from cron for continuous protection.

Only after (a)+(b) is it safe to `cron enable` and flip the graph mode live (the
remaining S2.4 item). A natural follow-up: add `backup-state.sh` to cron so the ledgers
and evidence chain are captured on a schedule, not just on demand.
