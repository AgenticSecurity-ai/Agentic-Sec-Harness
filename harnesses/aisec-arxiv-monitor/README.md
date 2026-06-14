# aisec-arxiv-monitor

A self-hosted OpenClaw monitor: on a schedule it fetches new **AI-security papers
from arXiv**, summarizes them, and posts them to a Discord channel.

This directory **is** the agent's OpenClaw workspace. It is self-contained and
ships with **no secrets**. You supply your own Discord bot, target channel, and
model credentials — all configured in your OpenClaw, never in this directory.

---

## What you get per post

```
📡 **<paper title>**
🏷️ <Security for AI | AI for Security | Other>  |  📁 <arXiv categories>  |  📅 <date>
<≤140-char summary, in your configured language>
👤 <authors>
📄 <abstract url>
```

Plus, once per run that posts anything:
`Thank you to arXiv for use of its open access interoperability.`

## Security model (read this — it is the point)

Untrusted paper text never drives system actions. The work is split:

- **Orchestrator** `skills/arxiv-aisec/run.py` — the entry point cron runs. It does
  the privileged, non-LLM work: fetch, post to Discord, write the dedup ledger.
- **The agent** — invoked by the orchestrator as a **tool-less text transform**
  (`minimal` tool profile). It only reads abstracts and writes summaries; it
  **cannot** fetch, post, run code, or write files. So an indirect prompt injection
  hidden in an arXiv abstract can at worst corrupt a summary string — never touch
  your host, other channels, or the ledger.

See `skills/arxiv-aisec/SKILL.md` for the full threat model.

## ⚠️ Important notes before you deploy

- **You must lock the agent to the `minimal` tool profile** (step 3 below). This is
  the core of the security model — skipping it would hand the summarizing agent
  real tools. A global `coding`/`full` profile would otherwise apply.
- **Posting needs the target channel allowed for your bot**, and a non-restrictive
  enough delivery path. The orchestrator posts via `openclaw message send`.
- **arXiv Terms of Use are respected and must stay that way:** the attribution line
  is auto-appended and `fetch.py` rate-limits requests to ≤ 1 / 3 s. Do not remove
  the attribution or parallelize the fetcher.
- **Branding:** if you redistribute or offer this as a service, review arXiv's brand
  guidelines. Do not use the arXiv name/logo/colors to imply endorsement.
- **Secrets never go in this directory.** Discord token + model credentials live in
  your OpenClaw config / credential chain.

## Prerequisites

> **First time setting up the host?** Do the one-time, host-wide bootstrap first
> (model provider + credentials, Discord bot + channel, operator scope):
> [../../docs/HOST-SETUP.md](../../docs/HOST-SETUP.md). The steps below assume it's done.

- OpenClaw installed, with a running gateway.
- A text model configured (defaults assume a Bedrock/Claude-class model; any
  OpenClaw text model works).
- A Discord bot in your server + the target channel id
  (`openclaw directory groups list --channel discord` lists channel ids; or enable
  Discord Developer Mode → right-click channel → Copy Channel ID).
- Python 3.11+ on the host (stdlib only; no third-party deps).

## Setup

### 1. Place the workspace

Clone this repo (or copy this directory) somewhere stable, e.g.
`~/openclaw-workspaces/aisec-arxiv-monitor`.

### 2. Register the agent

```bash
openclaw agents add arxiv --workspace /path/to/aisec-arxiv-monitor \
  --model amazon-bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0
```

Do **not** bind this agent to inbound channels — it only posts on a schedule.

### 3. Lock the agent to the `minimal` tool profile (REQUIRED)

```bash
# find the agent's index in agents.list, then:
openclaw config set 'agents.list[<index>].tools' '{"profile":"minimal"}'
openclaw gateway restart
```

Posting and fetching are done by the orchestrator, not the agent, so `minimal`
removes attack surface without removing functionality.

### 4. Provide secrets in OpenClaw (not here)

- Discord bot token + allow the bot to post in your target channel
  (`openclaw channels add discord ...`).
- Model credentials via your provider (e.g. the AWS credential chain for Bedrock).

### 5. Set your parameters

Edit `config.toml`:
- `arxiv.queries` — tune to your interests (defaults target LLM/agent security).
- `output.language` — summary language (`ja`, `en`, ...).
- `output.max_posts_per_run` — per-run cap.
- `discord.channel_id` — **required**: your target channel id.

### 6. Schedule it

Cron runs the orchestrator as a command. `--no-deliver` stops cron from trying to
deliver the script's stdout (run.py posts on its own).

```bash
openclaw cron add --name arxiv-aisec-daily \
  --cron '0 9 * * *' --tz Asia/Tokyo \
  --command 'python3 /path/to/aisec-arxiv-monitor/skills/arxiv-aisec/run.py' \
  --command-cwd /path/to/aisec-arxiv-monitor \
  --no-deliver
```

(`0 9 * * *` = daily 09:00 in `--tz`. Use `--every 6h` for interval runs. Managing
cron jobs requires an operator token with the `operator.admin` scope.)

### 7. Test before relying on it

Read-only fetch (no posting):
```bash
python3 skills/arxiv-aisec/fetch.py fetch | head
```
Full run (this DOES post to Discord):
```bash
python3 skills/arxiv-aisec/run.py        # direct, or:
openclaw cron run <job-id>               # via cron (debug)
```

## How it stays idempotent

`state/seen.json` records arXiv ids. The orchestrator marks a paper seen only after
its post succeeds (plus papers it deliberately dropped as irrelevant), so a failed
post retries next run — never a silent loss. It ships empty and fills at runtime
(git-ignored).

## What's tunable vs fixed

- **Tune:** `config.toml` (queries, language, caps, channel).
- **Adjust if you change the routine:** `skills/arxiv-aisec/run.py`
  (`build_prompt` = what the agent judges/summarizes; `format_post` = the post
  layout; `fetch.py` = the arXiv query + rate limit).
- **Persona:** `AGENTS.md`, `SOUL.md`, `IDENTITY.md`.

## Layout

```
aisec-arxiv-monitor/
├── README.md                  ← this file
├── config.toml                ← the only file you normally edit
├── AGENTS.md / SOUL.md / IDENTITY.md
├── skills/arxiv-aisec/
│   ├── SKILL.md               ← architecture + threat model
│   ├── fetch.py               ← arXiv fetch + dedup ledger (stdlib)
│   └── run.py                 ← orchestrator: fetch → agent → post → mark
└── state/                     ← runtime ledger lives here (git-ignored)
```
