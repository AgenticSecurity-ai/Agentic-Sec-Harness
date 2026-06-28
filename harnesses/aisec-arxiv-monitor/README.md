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

## How it works: what's automated, what stays manual

Picture the task a human would otherwise do by hand each morning: **fetch new
arXiv papers → skip what you've already seen → judge what's actually relevant →
classify it → summarize it → post to the team channel → credit the source**. This
harness automates most of that, but deliberately keeps judgement and
source-selection with you.

**Who does each step**

- **AI** — the tool-less LLM judges relevance, classifies, and writes summaries.
- **Tool** — the deterministic orchestrator / fetcher does the fetching, posting,
  dedup ledger, and attribution.
- **You** — the human judgement and setup that is *not* automated.

**"Human check?"** is flagged **Yes** when a failure is hard to undo (e.g. an
already-public bad post) OR the output quality varies a lot (judgement / summary
errors).

| Step (what a human would do) | Who | Human check? | Why |
|---|:--:|:--:|---|
| **A.** Decide what to watch (`arxiv.queries`) | You | — | Your call; the monitoring strategy is not automated. |
| **B.** Fetch new papers from arXiv | Tool | No | Deterministic; a failed fetch self-recovers next run — nothing is lost. |
| **C.** Track what's already been seen | Tool | No | Deterministic & idempotent — marked seen only after a post succeeds. |
| **D.** Judge relevance (drop the false matches) | AI | **Yes** | The core triage; quality varies and mis-judgements happen. |
| **E.** Classify (Security for AI / AI for Security / Other) | AI | Yes (light) | Can vary, but the impact is limited to a single label. |
| **F.** Summarize in ≤140 chars | AI | **Yes** | Varies and can hallucinate — verify against the source paper. |
| **G.** Post to Discord | Tool | No\* | URLs/authors come from trusted fetch data, never the LLM. \*See note. |
| **H.** Append the arXiv attribution | Tool | No | Always added once per posting run; cannot be forgotten. |
| **I.** Confirm the post & retry tomorrow | Tool | No | Only successful posts are marked; failures retry — never a silent loss. |

> **\*Note on step G — there is no human-in-the-loop before posting.** The posting
> *mechanism* is safe (it builds the message from trusted metadata, not LLM
> output), but the *content* it posts depends on the AI's steps D–F. Discord posts
> are public and effectively irreversible, so today the human check on D–F is a
> **post-hoc review** (read the channel, fix mistakes) — not an approval gate. If
> you need to catch errors *before* they go public, add an approval step before G
> (e.g. post drafts to a staging channel and publish only after review).

Two things are intentionally **not** automated: **what to monitor** (step A) and
**final responsibility for the AI's judgement** (steps D–F). The security model
above is what makes the rest safe to run unattended — because the summarizing agent
has no tools, a prompt injection hidden in an abstract can at worst corrupt one
summary string; it can never reach the fetch, the post, or the ledger.

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

Two files, split by what they're for:

**`config.toml`** — shippable defaults you commit (no secrets, no per-deployment
state):
- `arxiv.queries` — tune to your interests (defaults target LLM/agent security).
- `output.language` — summary language (`ja`, `en`, ...).
- `output.llm_batch_size` — papers per LLM judging call (candidates are chunked into
  separate calls). There is no post cap — every relevant paper is posted, since the
  arXiv keyword queries already bound the candidate count.

**`.env`** (git-ignored) — the deployment-specific values. Copy the template and
fill it in:

```bash
cp .env.example .env   # then edit
```

| Variable | Purpose | Default |
|---|---|---|
| `ARXIV_CHANNEL_ID` | target Discord channel id | **required to post** |
| `ARXIV_AGENT_ID` | the agent the orchestrator invokes | `arxiv` |
| `OPENCLAW_BIN` | the `openclaw` CLI path | `openclaw` (on PATH) |

The target channel is set **only** here (`ARXIV_CHANNEL_ID`) — it is not in
`config.toml`, so the committed config carries no deployment state. An exported
shell variable wins over `.env`. **Only non-secret values go in `.env`** — the
Discord bot token and AWS credentials stay in OpenClaw (see the security notes).

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
| **Run without cron at all** | `python3 skills/arxiv-aisec/run.py` |
| **Dry run** (read-only, no posting) | `python3 skills/arxiv-aisec/fetch.py fetch` |

`disable`/`enable` toggle the schedule without deleting the job, so you can move
between "fully manual" (disable, then `cron run` when you want it) and "back on a
daily timer" (enable) at any time. Managing cron jobs requires an operator token
with the `operator.admin` scope.

> **Note for laptop / WSL2 hosts:** a scheduled run only fires while the host is
> awake. If the machine is asleep at the scheduled time, OpenClaw runs the job once
> it wakes (so it may run late), and a day the host never comes up is skipped
> entirely. If that's unreliable for you, prefer manual operation: `disable` the
> schedule and trigger runs by hand with `openclaw cron run <job-id>`.

## How it stays idempotent

`state/seen.json` records arXiv ids. The orchestrator marks a paper seen only after
its post succeeds (plus papers it deliberately dropped as irrelevant), so a failed
post retries next run — never a silent loss. It ships empty and fills at runtime
(git-ignored).

## What's tunable vs fixed

- **Tune:** `config.toml` (queries, language, caps) and `.env` (deployment-specific:
  `ARXIV_CHANNEL_ID`, `ARXIV_AGENT_ID`, `OPENCLAW_BIN`).
- **Adjust if you change the routine:** `skills/arxiv-aisec/run.py`
  (`build_prompt` = what the agent judges/summarizes; `format_post` = the post
  layout; `fetch.py` = the arXiv query + rate limit).
- **Persona:** `AGENTS.md`, `SOUL.md`, `IDENTITY.md`.

## Layout

```
aisec-arxiv-monitor/
├── README.md                  ← this file
├── config.toml                ← shippable defaults (queries, language, caps)
├── .env.example               ← copy to .env for per-deployment overrides
├── AGENTS.md / SOUL.md / IDENTITY.md
├── skills/arxiv-aisec/
│   ├── SKILL.md               ← architecture + threat model
│   ├── fetch.py               ← arXiv fetch + dedup ledger (stdlib)
│   └── run.py                 ← orchestrator: fetch → agent → post → mark
└── state/                     ← runtime ledger lives here (git-ignored)
```
