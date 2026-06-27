---
name: aisec-news
description: Monitoring routine that delivers new AI-security news from a set of security-news RSS/Atom feeds to a Discord channel. An orchestrator fetches and posts; a tool-less agent only judges relevance and writes summaries. Triggered on a schedule (cron).
---

# aisec-news — security-news AI-security monitoring routine (security profile B2)

This routine is built around a **trust separation** so that untrusted feed text can
never drive system actions.

## Components

- **Orchestrator** `skills/aisec-news/run.py` — the entry point cron runs. It does
  the privileged, NON-LLM work: fetch articles, post to Discord, record the ledger.
- **Fetcher** `skills/aisec-news/fetch.py` — RSS 2.0 / Atom fetch + dedup ledger
  (stdlib; format auto-detected per feed). Feed-reader-style: reads each publisher's
  officially-provided feed (same purpose as Feedly); it does NOT crawl or scrape
  article pages. The feed body is clipped to a short excerpt before the agent sees it.
- **Config** `config.toml` — committed shared defaults: feed URLs, language,
  `llm_batch_size`.
  Deployment-specific values live in `.env` (git-ignored): `NEWS_CHANNEL_ID` (the
  target channel — set only here), `NEWS_AGENT_ID`, `OPENCLAW_BIN`. `.env` holds
  only non-secret deployment values; the Discord bot token and AWS credentials stay
  in OpenClaw, never in this workspace.
- **The agent** — invoked by the orchestrator as a **tool-less text transform**
  (minimal profile). It receives the feed excerpts as *data*, decides AI-security
  relevance, and writes summaries. It cannot fetch, post, run code, or write files.

## Flow (run.py)

1. `fetch.py fetch` → new, unseen, in-window articles (relevant + noise, unmarked),
   each normalized to a common schema (id/title/url/date/author/summary).
2. If none, stop.
3. Judge the candidates in chunks of `output.llm_batch_size` — separate agent calls
   with the excerpts fenced as untrusted DATA (smaller chunks keep each prompt
   focused and isolate failures: a chunk whose JSON won't parse is left unmarked to
   retry next run, it does not sink the others). Each call uses a fresh, unique
   `--session-key`, so the agent is stateless per chunk — chunks cannot contaminate
   each other's summaries or leak ids between themselves; the verdict is also scoped
   strictly to that chunk's ids. The feed is GENERAL security news, so the agent's
   primary job is to DROP the non-AI-security majority. Each call returns strict JSON:
   `{relevant:[{id,category,summary}], dropped:[ids]}` — a relevance verdict, a
   "Security for AI" / "AI for Security" / "Other" classification, and a ≤140-char
   summary (in `output.language`) for each kept article.
4. The orchestrator posts each relevant article to the configured channel
   (`NEWS_CHANNEL_ID`), building the message from TRUSTED fetch metadata
   (title / date / url) plus the agent's category + summary — the LLM never echoes
   URLs. The summary is hard-clipped to 140 chars as a safety net. It appends the
   source attribution line once per run.
5. `fetch.py mark` records (successfully-posted relevant) + (agent-dropped). An
   article whose post FAILED is left unmarked, so it retries next run.

## Why this shape (threat model)

Feed item text is untrusted external content and a classic **indirect prompt
injection** vector. By giving the summarizing agent **no tools**, a malicious excerpt
can at most corrupt a summary string — it cannot touch the host, other channels, or
the ledger. All privileged actions live in deterministic code paths that never read
LLM output as a command.

## Copyright / source terms

The feed body is each publisher's editorial excerpt / article text (their copyrighted
expression), not bare facts. This routine **never reposts it verbatim**: the fetcher
clips it to a short excerpt used only as judge input, the agent writes its own
≤140-char transformative summary, and the post links back to the original and names
the source (resolved per-article from its URL host via the `SOURCES` map in `run.py`).
The fetcher reads only officially-provided RSS/Atom feeds (it does not scrape article
pages) and sends an honest `User-Agent`. If you add or change a feed, check that
source's Terms of Use and any `<copyright>`/`<rights>` notice, keep the
summarize-and-link posture, and add its domain to `SOURCES`.

## Tuning

Behavior is controlled by `config.toml` (feeds, language, `llm_batch_size`) and
`.env` (channel, agent, CLI path). The fetch retry/backoff and rate limit are
enforced in `fetch.py`. Leave the scripts and this file alone unless changing the
routine itself.
