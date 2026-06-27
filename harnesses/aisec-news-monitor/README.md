# aisec-news-monitor

A self-hosted OpenClaw monitor: on a schedule it reads new **security news from a set
of RSS/Atom feeds** (The Hacker News, Krebs, SecurityWeek, Infosecurity Magazine,
Schneier, Cybersecurity Dive, Dark Reading, BleepingComputer, The Register, Ars
Technica, IEEE Spectrum), keeps only the **AI/ML-security** stories, summarizes them,
and posts them to a Discord channel.

This directory **is** the agent's OpenClaw workspace. It is self-contained and
ships with **no secrets**. You supply your own Discord bot, target channel, and
model credentials — all configured in your OpenClaw, never in this directory.

It is a **feed-reader-style** consumer: it reads each publisher's officially-provided
RSS or Atom feed (same purpose as Feedly) and never crawls or scrapes article pages.

---

## What you get per post

```
📰 **<article headline>**
🏷️ <Security for AI | AI for Security | Other>  |  📅 <date>
<≤140-char summary, in your configured language>
📄 <article url>
🔗 <source name>
```

Plus, once per run that posts anything, a general attribution line.

Most of the feeds are ordinary cybersecurity news with no AI angle; those items are
**dropped** by the relevance judge. Only genuine AI/ML-security stories are posted.

## Security model (read this — it is the point)

Untrusted feed text never drives system actions. The work is split:

- **Orchestrator** `skills/aisec-news/run.py` — the entry point cron runs. It does
  the privileged, non-LLM work: fetch, post to Discord, write the dedup ledger.
- **The agent** — invoked by the orchestrator as a **tool-less text transform**
  (`minimal` tool profile). It only reads excerpts and writes summaries; it
  **cannot** fetch, post, run code, or write files. So an indirect prompt injection
  hidden in a feed item can at worst corrupt a summary string — never touch your
  host, other channels, or the ledger.

See `skills/aisec-news/SKILL.md` for the full threat model.

## Copyright / source terms

This harness is built to respect the publisher's rights:

- It reads only each publisher's **officially-provided RSS/Atom feed** (no page
  scraping) and sends an honest `User-Agent`; the fetcher also rate-limits and backs
  off politely. A site's `robots.txt` AI-crawler rules target HTML crawlers, not
  feed readers — but they are a signal of the publisher's intent, so each feed is a
  deliberate choice, not a default.
- The feed body is the publisher's **editorial excerpt / article text** (copyrighted
  expression). It is **never reposted verbatim** — the fetcher clips it to a short
  excerpt purely as input for the judge, the agent writes its **own** ≤140-char
  transformative summary, and every post **links back to the original** and **names
  the source**.
- **If you add or change a feed**, that source's Terms of Use and any
  `<copyright>`/`<rights>` notice apply to you. Check them, keep the
  summarize-and-link posture (never pipe raw feed text to Discord), and add the
  source's domain to the `SOURCES` map in `run.py` so posts attribute it correctly.

## ⚠️ Important notes before you deploy

- **You must lock the agent to the `minimal` tool profile** (step 3 below). This is
  the core of the security model — skipping it would hand the summarizing agent
  real tools. A global `coding`/`full` profile would otherwise apply.
- **Posting needs the target channel allowed for your bot.** The orchestrator posts
  via `openclaw message send`.
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
`~/openclaw-workspaces/aisec-news-monitor`.

### 2. Register the agent

```bash
openclaw agents add aisec-news --workspace /path/to/aisec-news-monitor \
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

- Discord bot token + allow the bot to post in your target channel.
- Model credentials via your provider (e.g. the AWS credential chain for Bedrock).

### 5. Set your parameters

Two files, split by what they're for:

**`config.toml`** — shippable defaults you commit (no secrets, no per-deployment
state):
- `news.feeds` — the RSS/Atom feeds to read (default: 11 security-news sources).
- `news.lookback_days` — ignore articles older than this window.
- `output.language` — summary language (`ja`, `en`, ...).
- `output.llm_batch_size` — articles per LLM judging call (candidates are chunked
  into separate calls). There is no post cap — every relevant article is posted.

**`.env`** (git-ignored) — the deployment-specific values. Copy the template and
fill it in:

```bash
cp .env.example .env   # then edit
```

| Variable | Purpose | Default |
|---|---|---|
| `NEWS_CHANNEL_ID` | target Discord channel id | **required to post** |
| `NEWS_AGENT_ID` | the agent the orchestrator invokes | `aisec-news` |
| `OPENCLAW_BIN` | the `openclaw` CLI path | `openclaw` (on PATH) |

The target channel is set **only** here (`NEWS_CHANNEL_ID`) — it is not in
`config.toml`, so the committed config carries no deployment state. An exported
shell variable wins over `.env`. **Only non-secret values go in `.env`** — the
Discord bot token and AWS credentials stay in OpenClaw (see the security notes).

### 6. Schedule it

Cron runs the orchestrator as a command. `--no-deliver` stops cron from trying to
deliver the script's stdout (run.py posts on its own).

```bash
openclaw cron add --name aisec-news-daily \
  --cron '0 9 * * *' --tz Asia/Tokyo \
  --command 'python3 /path/to/aisec-news-monitor/skills/aisec-news/run.py' \
  --command-cwd /path/to/aisec-news-monitor \
  --no-deliver
```

(`0 9 * * *` = daily 09:00 in `--tz`. Use `--every 6h` for interval runs. Managing
cron jobs requires an operator token with the `operator.admin` scope.)

### 7. Test before relying on it

Read-only fetch (no posting):
```bash
python3 skills/aisec-news/fetch.py fetch | head
```
Full run (this DOES post to Discord):
```bash
python3 skills/aisec-news/run.py        # direct, or:
openclaw cron run <job-id>              # via cron (debug)
```

## Run on a schedule, or by hand

You can switch freely between scheduled (cron) and manual operation — the cron job
and the orchestrator are independent. First find the job id with
`openclaw cron list` (the `ID` column), then:

| What you want | Command |
|---|---|
| **Run once, now** (leave the schedule as-is) | `openclaw cron run <job-id>` |
| **Pause the daily schedule** (keep the job) | `openclaw cron disable <job-id>` |
| **Resume the daily schedule** | `openclaw cron enable <job-id>` |
| **Change the schedule** (time, interval) | `openclaw cron edit <job-id>` |
| **Run without cron at all** | `python3 skills/aisec-news/run.py` |
| **Dry run** (read-only, no posting) | `python3 skills/aisec-news/fetch.py fetch` |

> **Note for laptop / WSL2 hosts:** a scheduled run only fires while the host is
> awake. If the machine is asleep at the scheduled time, OpenClaw runs the job once
> it wakes (so it may run late), and a day the host never comes up is skipped
> entirely. If that's unreliable for you, prefer manual operation: `disable` the
> schedule and trigger runs by hand with `openclaw cron run <job-id>`.

## How it stays idempotent

`state/seen.json` records article ids. The orchestrator marks an article seen only
after its post succeeds (plus articles it deliberately dropped as irrelevant), so a
failed post retries next run — never a silent loss. It ships empty and fills at
runtime (git-ignored).

## What's tunable vs fixed

- **Tune:** `config.toml` (feeds, language, caps) and `.env` (deployment-specific:
  `NEWS_CHANNEL_ID`, `NEWS_AGENT_ID`, `OPENCLAW_BIN`).
- **Adjust if you change the routine:** `skills/aisec-news/run.py`
  (`build_prompt` = what the agent judges/summarizes; `format_post` = the post
  layout; `fetch.py` = the feed parse + rate limit).
- **Persona:** `AGENTS.md`, `SOUL.md`, `IDENTITY.md`.

## Layout

```
aisec-news-monitor/
├── README.md                  ← this file
├── config.toml                ← shippable defaults (feeds, language, caps)
├── .env.example               ← copy to .env for per-deployment overrides
├── AGENTS.md / SOUL.md / IDENTITY.md
├── skills/aisec-news/
│   ├── SKILL.md               ← architecture + threat model
│   ├── fetch.py               ← RSS fetch + dedup ledger (stdlib)
│   └── run.py                 ← orchestrator: fetch → agent → post → mark
└── state/                     ← runtime ledger lives here (git-ignored)
```
