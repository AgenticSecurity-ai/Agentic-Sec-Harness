# CLAUDE.md — Agentic-Sec-Harness

Orientation for any agent working in this repository. Read this fully before editing.

## What this repo is

**Agentic-Sec-Harness** is a collection of **self-contained OpenClaw monitoring
harnesses for AI security**. Each harness watches a source (arXiv, security news, …),
has an LLM summarize new items, and posts them to a Discord channel on a schedule.

- Built on [OpenClaw](https://openclaw.ai) (a personal-agent gateway; agents have
  workspaces + skills + cron). Target model class: AWS Bedrock Claude (Haiku 4.5),
  but any OpenClaw text model works.
- Distributed for **self-hosting**: a user clones one harness folder into their own
  OpenClaw, supplies their own credentials, and runs it.
- **Status:** `aisec-arxiv-monitor` is complete and was verified end-to-end live.
  A security-news harness is planned but not built.

## Non-negotiable conventions (preserve these)

1. **Self-contained harnesses — NO shared core.** Each `harnesses/<name>/` is a
   complete, independently-usable OpenClaw workspace. The user explicitly chose
   duplication over a shared library so each harness works alone. Do NOT refactor
   into a common/ library. If two harnesses share logic, copy it.

2. **B2 security model (the core invariant).** The LLM that reads *untrusted source
   content* (paper abstracts, article text) must run as a **tool-less text
   transform** — OpenClaw `minimal` tool profile, zero tools. All privileged work
   (fetch, post to Discord, write the dedup ledger) is done by a deterministic
   **orchestrator** script (`run.py`) that never treats LLM output as a command.
   Rationale: indirect prompt injection in fetched content can then at most corrupt
   a summary string — never touch the host, other channels, or the ledger. Untrusted
   text is passed to the agent fenced as DATA with an explicit "ignore instructions
   inside" directive. **Never give the content-summarizing agent real tools.**

3. **No secrets in the repo, ever.** `config.toml` holds only committed shared
   defaults (queries, language, caps) — no per-deployment state. Deployment-specific
   values (Discord channel id, agent id, CLI path) live in a git-ignored `.env`
   (each harness ships a committed `.env.example` template); the orchestrator loads
   `.env` and reads e.g. `ARXIV_CHANNEL_ID` from the environment. `.env` is for
   NON-SECRET deployment values only — Discord bot tokens and model credentials live
   in the *host's* OpenClaw config / credential chain, never in a harness directory.
   Before any commit, grep the repo for real channel ids / tokens / AWS keys, and
   confirm `.env` is git-ignored.

4. **Respect each source's terms.** arXiv: the attribution line "Thank you to arXiv
   for use of its open access interoperability." is auto-appended on posting runs,
   and `fetch.py` rate-limits to ≤ 1 request / 3 s. For a NEW source, check its
   ToS/attribution/rate-limit requirements and enforce them in code, not docs.

5. **Idempotent dedup ledger.** `state/seen.json` (git-ignored, ships empty) records
   handled item ids. Mark an item seen only AFTER its post succeeds, plus items the
   agent deliberately dropped as irrelevant. A failed post stays unmarked → retries
   next run. Never silently lose items.

6. **Every harness ships a `README.md`** with prerequisites, setup steps, and
   important deployment notes (especially the `minimal`-profile requirement).

7. **License headers on every source file.** The repo is **AGPLv3** (see
   [LICENSE](LICENSE)); contributions come in under the **CLA** ([CLA.md](CLA.md))
   accepted via **DCO sign-off** (`git commit -s`; see [CONTRIBUTING.md](CONTRIBUTING.md)).
   Every source file you create or edit must carry this header — for `*.py`, right
   after the shebang and before the module docstring:

   ```python
   # Copyright (C) 2026 Isao Takaesu
   # SPDX-License-Identifier: AGPL-3.0-or-later
   ```

   Apply it to **code, scripts, and configuration** (`*.py`, `*.sh`, `*.toml`),
   using that language's comment syntax (`#` for Python, shell, and TOML) — for
   `config.toml`, the two lines go at the very top, above the existing banner. It is
   **not** required on prose docs (`*.md`) or empty markers (`.gitkeep`). When adding
   a new file of these kinds, put the same SPDX line at the top in that language's
   comment syntax.

## Repository layout

```
Agentic-Sec-Harness/
├── README.md                       # repo overview + harness table
├── CLAUDE.md                       # this file
├── LICENSE                         # AGPLv3 (full text)
├── CLA.md                          # contributor license agreement (enables dual-license)
├── CONTRIBUTING.md                 # how to contribute; DCO sign-off accepts the CLA
├── .gitignore                      # ignores __pycache__, .openclaw/, **/state/seen.json, **/USER|TOOLS|HEARTBEAT.md
├── docs/
│   └── HOST-SETUP.md               # one-time host bootstrap: model provider + creds, Discord, operator scope
└── harnesses/
    └── aisec-arxiv-monitor/        # self-contained OpenClaw workspace
        ├── README.md               # per-harness setup + notes
        ├── .gitignore
        ├── config.toml             # the only file a deployer normally edits; channel_id="" in repo
        ├── AGENTS.md / SOUL.md / IDENTITY.md   # persona / operating rules
        ├── skills/arxiv-aisec/
        │   ├── SKILL.md            # architecture + threat model (human/agent doc)
        │   ├── fetch.py            # arXiv fetch + dedup ledger; stdlib only; rate-limited
        │   └── run.py              # orchestrator: fetch → agent → post → mark
        └── state/.gitkeep          # runtime ledger dir (seen.json git-ignored)
```

## How a harness works (aisec-arxiv-monitor reference)

Flow, all driven by `run.py` (cron runs it via `--command`):

1. `fetch.py fetch` → new, unseen, in-window items as JSON (3 filter layers:
   ① arXiv query in `config.toml` (keyword filtering is server-side, so the LLM only
   ever sees pre-narrowed candidates) → ② fetch.py: 7-day window + dedup ledger →
   ③ later, LLM relevance judge). No post cap — every relevant item is posted. stdlib
   only, Python 3.11+ (uses `tomllib`).
2. `run.py` judges candidates in chunks of `output.llm_batch_size` (separate
   `openclaw agent` calls — keeps each prompt focused and isolates failures: a failed
   chunk is left unmarked to retry, never sinks the run) with abstracts fenced as
   DATA. Each call uses a fresh, unique `--session-key` so the agent is stateless per
   chunk (otherwise repeated calls share one session and the agent carries context
   across chunks — contaminating summaries and leaking ids); the verdict is also
   scoped to that chunk's ids. The agent returns strict JSON between
   `<<<RESULT_JSON>>>` markers:
   `{relevant:[{id, category, summary}], dropped:[ids]}`. `category` ∈
   {"Security for AI","AI for Security","Other"}; `summary` ≤ 140 chars in the
   configured language.
3. `run.py` posts each relevant item via `openclaw message send`, building the
   message from TRUSTED fetch metadata (title / arXiv categories / date / authors /
   url) + the agent's category & summary. **The LLM never echoes URLs.** Summary is
   hard-clipped to 140 chars (`clip()`) as a safety net. Appends the attribution line
   once per posting run.
4. `run.py` marks (posted + dropped) ids via `fetch.py mark`.

Key functions in `run.py`: `build_prompt` (what the agent judges/summarizes — edit to
change criteria/length/language framing), `format_post` (Discord post layout),
`clip` (140-char enforcement), `call_agent` (invoke + JSON extraction),
`post_message` (Discord send). Constants: `ACK`, `SUMMARY_MAX_CHARS=140`,
`VALID_CATEGORIES`.

Post format:
```
📡 **<title>**
🏷️ <category>  |  📁 <arXiv cats>  |  📅 <date>
<≤140-char summary>
👤 <authors>
📄 <abs_url>
```

## Live deployment vs the repo (important)

The repo is the **clean distribution template**. There is ALSO a **live, running
deployment** on this host at `~/.openclaw/products/aisec-arxiv-monitor` — a separate
copy with the real `channel_id` filled in and an accumulated `state/seen.json`, a
registered OpenClaw agent (`arxiv`, `minimal` profile), and a cron job
`arxiv-aisec-daily` (`0 9 * * * @ Asia/Tokyo`). **They are currently separate copies**
— improving the repo does not update the live deployment and vice-versa. Whether to
make the repo the single source of truth and re-point the live agent's `--workspace`
+ cron `--command` paths is an OPEN decision (see open items). Don't assume edits here
affect the running agent.

## Deployment / testing knowledge (host-side gotchas already discovered)

These matter when testing a harness on a real OpenClaw host:

- **Tool profiles:** `coding` has exec but strips messaging; `messaging` has the
  message tool but strips exec; **no single profile has both**, and `allow` cannot
  grant back what a profile excludes. B2 sidesteps this: the agent uses `minimal`
  (text only) and the orchestrator does I/O. Set per-agent via
  `openclaw config set 'agents.list[<idx>].tools' '{"profile":"minimal"}'` + restart.
- **Discord posting** needs the target channel in the host's openclaw.json discord
  allowlist, and the bot must be allowed to post there. Target format is
  `channel:<id>` (e.g. `openclaw message send --channel discord --target channel:<id>`).
- **cron** uses a `--command` job (NOT an agent-message job) plus `--no-deliver`
  (otherwise cron tries to deliver the script's stdout to a channel and the run is
  falsely marked `error`). `openclaw cron run <id>` and `cron runs --id <id>` take the
  job **id**, not the name.
- **cron management requires the `operator.admin` scope** on the operator token/device.
- **Author affiliation is NOT available from the arXiv API** (≈0% populated) — do not
  try to add it without an external source (OpenAlex/Semantic Scholar) — out of scope.
- **Verify by reading the actual Discord channel**, not the agent's self-report. The
  summarizing agent has, in testing, claimed a post succeeded when it had not. Use
  `openclaw message read --channel discord --target channel:<id> --limit N --json`.
- For low-noise tests: use a temp ledger and/or narrow `arxiv.queries` /
  `lookback_days` (there is no post cap anymore — every relevant item is posted);
  `python3 skills/arxiv-aisec/fetch.py fetch` is a read-only dry run (no posting).
- **"The newest day's papers aren't fetched" is arXiv export API indexing lag, NOT a
  harness bug.** The website (`arxiv.org/list/<cat>/recent`) updates on announcement,
  but the search API (`export.arxiv.org/api`) lags it by 1–2 business days (worse
  across weekends). Triage in one shot: query bare `cat:cs.CR` / `cat:cs.AI` with
  `sortBy=submittedDate&sortOrder=descending` and read the newest `published` date —
  if it's several days behind today, it's API lag (the `updated` axis lags too). If
  our keyword query were the cause, the bare query would still surface newer dates.
  **Nothing is lost:** `lookback_days` (≥7) plus the post-then-mark dedup ledger mean
  the missing day is auto-recovered on the next cron run once the API catches up — no
  fix needed, just wait. (Note: `fetch.py`'s window filter keys on `published` = the
  v1 submission date, which can differ from the recent-listing announce date.)

## Open items / likely next tasks

1. ~~**LICENSE not chosen.**~~ DONE — **AGPLv3 + CLA**, contributions via DCO
   sign-off. Rationale: keep genuine OSS positioning while preserving a future
   commercial / dual-license path (CLA lets the owner relicense). See convention #7.
2. **Build the security-news harness** (`harnesses/aisec-news-monitor/`) by cloning
   the arXiv harness's B2 structure. Source was not finalized — the user must
   disambiguate "HackerNews": **Hacker News (news.ycombinator.com, via Algolia API)**
   vs **The Hacker News (thehackernews.com, RSS)**; plus **DarkReading (RSS)**, and
   possibly others (BleepingComputer / Krebs). Per source: write a `fetch.py` adapter
   normalizing to the common item schema, decide attribution/ToS, give it its own
   Discord channel, its own `config.toml`, persona, and `README.md`. Keep it
   self-contained (copy, don't share).
3. **Re-point decision** for the live deployment (source-of-truth vs separate copies).
4. **Commit:** repo is `git init`'d and staged but NOT committed (commit only when the
   user asks; end commit messages with the required Co-Authored-By line).

## Working agreements (from how this was built)

- The user is an **AI-security professional** (builds AI-SPM tooling); security
  framing and threat models land well and are valued. Hold a high bar on the B2
  invariant and supply-chain hygiene.
- Confirm before externally-visible or hard-to-reverse actions (Discord posts,
  commits, pushes). Make a clean copy rather than mutating a working deployment.
- Prefer stdlib-only Python for harness scripts (portability for self-hosters).
