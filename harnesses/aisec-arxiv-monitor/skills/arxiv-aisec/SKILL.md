---
name: arxiv-aisec
description: Monitoring routine that delivers new AI-security arXiv papers to a Discord channel. An orchestrator fetches and posts; a tool-less agent only judges relevance and writes summaries. Triggered on a schedule (cron).
---

# arxiv-aisec — arXiv AI-security monitoring routine (security profile B2)

This routine is built around a **trust separation** so that untrusted paper text
can never drive system actions.

## Components

- **Orchestrator** `skills/arxiv-aisec/run.py` — the entry point cron runs. It does
  the privileged, NON-LLM work: fetch papers, post to Discord, record the ledger.
- **Fetcher** `skills/arxiv-aisec/fetch.py` — arXiv API fetch + dedup ledger (stdlib).
- **Config** `config.toml` — queries, language, caps, `discord.channel_id`.
- **The agent** — invoked by the orchestrator as a **tool-less text transform**
  (minimal profile). It receives the abstracts as *data*, decides relevance, and
  writes summaries. It cannot fetch, post, run code, or write files.

## Flow (run.py)

1. `fetch.py fetch` → new, unseen, in-window papers (relevant + noise, unmarked).
2. If none, stop.
3. Call the agent with the abstracts fenced as untrusted DATA. The agent returns
   strict JSON: `{relevant:[{id,category,summary}], dropped:[ids]}` — a relevance
   verdict, a "Security for AI" / "AI for Security" / "Other" classification, and a
   ≤140-char summary (in `output.language`) for each kept paper.
4. The orchestrator posts each relevant paper to `discord.channel_id`, building the
   message from TRUSTED fetch metadata (title / arXiv categories / submission date /
   authors / url) plus the agent's category + summary — the LLM never echoes URLs.
   The summary is hard-clipped to 140 chars as a safety net. It appends the arXiv
   attribution line once per run.
5. `fetch.py mark` records (successfully-posted relevant) + (agent-dropped). A paper
   whose post FAILED is left unmarked, so it retries next run.

## Why this shape (threat model)

arXiv abstracts are untrusted external content and a classic **indirect prompt
injection** vector. By giving the summarizing agent **no tools**, a malicious
abstract can at most corrupt a summary string — it cannot touch the host, other
channels, or the ledger. All privileged actions live in deterministic code paths
that never read LLM output as a command.

## Tuning

Behavior is controlled by `config.toml` (queries, language, caps, channel). The
fetch rate limit (arXiv ToU: 1 request / 3 s) is enforced in `fetch.py`. Leave the
scripts and this file alone unless changing the routine itself.
