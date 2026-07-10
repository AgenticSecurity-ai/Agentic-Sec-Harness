---
name: aisec-vulntriage
description: Read-only cloud-posture triage routine. An orchestrator runs Prowler + free intel feeds (CISA KEV / FIRST EPSS / NVD), a tool-less agent assigns priority + structured rationale, and the orchestrator floors the priority deterministically, signs each verdict into a hash-chained evidence log, and posts a prioritized Discord digest. Triggered on a schedule (cron). Read-only by construction (SecurityAudit + ViewOnlyAccess IAM role).
---

# aisec-vulntriage — read-only cloud-posture triage routine (security profile B2)

This routine is built around **three independent security layers** so that untrusted
scan/intel output can never drive system actions and the cloud account can never be
mutated. The outer layer holds even if every inner layer fails. See `DESIGN.md` §3
for the full rationale; this file is the operational summary.

## Components

- **Orchestrator** `skills/aisec-vulntriage/run.py` — the entry point cron runs. It
  does the privileged, NON-LLM work: invoke the collector, apply the deterministic
  priority floor, sign each verdict into the evidence log, post to Discord, record
  the ledger.
- **Collector** `skills/aisec-vulntriage/collect.py` — Phase 1–2 (collect + enrich),
  stdlib + the pinned Prowler CLI. Runs Prowler (read-only CSPM) over the configured
  AWS scope, normalizes its JSON-OCSF output to a common finding schema,
  de-duplicates against the ledger, extracts referenced CVE ids, and enriches them
  from free public feeds (CISA KEV membership, FIRST EPSS score, optionally NVD
  CVSS). Emits the NEW (unseen) findings as JSON on stdout. It also owns the dedup
  ledger (`collect` / `mark` / `seen-count`).
- **Evidence log** `skills/aisec-vulntriage/evidence.py` — append-only, hash-chained
  (SHA-256) JSON Lines log at `state/evidence.log`, with a pluggable signature
  (ECDSA P-256 when `cryptography` + a key are present; HMAC-SHA256 stdlib fallback;
  chain-only otherwise). `verify` re-checks the chain end-to-end.
- **Config** `config.toml` — committed shared defaults: AWS regions, Prowler scope
  (services / compliance / statuses / severities), enrich feeds, triage floor
  thresholds, language, `llm_batch_size`. Deployment-specific values live in `.env`
  (git-ignored): `VULNTRIAGE_CHANNEL_ID` (the target channel — set only here),
  `VULNTRIAGE_AGENT_ID`, `VULNTRIAGE_AWS_PROFILE`, `OPENCLAW_BIN`, `PROWLER_BIN`.
  `.env` holds only non-secret deployment values; AWS credentials and the Discord bot
  token stay in OpenClaw / the host credential chain, never in this workspace.
- **The agent** — invoked by the orchestrator as a **tool-less text transform**
  (minimal profile). It receives the findings as *data*, assigns a priority, and
  writes a structured rationale. It cannot scan, fetch, post, run code, or write
  files.

## Flow (run.py)

1. `collect.py collect` → NEW, unseen findings (JSON), each normalized to a common
   schema (id / check_id / title / severity / resource / description / risk /
   remediation / `internet_exposed` / `cve_ids`) and enriched with per-CVE KEV / EPSS
   facts. There is **no time window** — a vulnerability finding is a *state* that
   stays open until fixed, so re-posting is suppressed by the dedup ledger alone
   (not a lookback window).
2. If none, stop.
3. **Triage** the findings in chunks of `output.llm_batch_size` — separate
   `openclaw agent` calls with the finding fields fenced as untrusted DATA (smaller
   chunks keep each prompt focused and isolate failures: a chunk whose JSON won't
   parse is left unmarked to retry next run, it does not sink the others). Each call
   uses a fresh, unique `--session-key`, so the agent is stateless per chunk — chunks
   cannot contaminate each other's verdicts or leak ids; the verdict is also scoped
   strictly to that chunk's ids. Each call returns strict JSON between markers:
   `{verdicts:[{finding_id, priority, excess_privilege, asset_criticality, summary}],
   dropped:[ids]}`.
4. **Deterministic priority floor** — for each verdict the orchestrator raises the
   LLM's priority to a floor computed from **collector facts**: KEV-listed
   (`kev_forces_at_least`), EPSS ≥ `epss_high_threshold`, or `internet_exposed`
   (`exposure_forces_at_least`). The LLM can raise a priority but **cannot lower one
   below what the facts justify** — so a compromised LLM cannot talk a KEV-listed,
   internet-exposed finding down to Low.
5. **Sign, then post.** The orchestrator composes the rationale — merging the three
   deterministic facts (`kev_listed` / `epss` / `internet_exposed`, from the
   collector) with the LLM's judgments (`excess_privilege` / `asset_criticality` /
   `summary`) — appends a signed evidence record (inputs BY DIGEST → priority →
   rationale) **before** posting, then posts each finding to `VULNTRIAGE_CHANNEL_ID`,
   building the message from TRUSTED collector metadata (asset, check id, CVE id,
   KEV/EPSS/exposure) plus the LLM's priority + rationale summary. The LLM never
   echoes ids or URLs; the summary is hard-clipped as a safety net. Once per posting
   run it appends the disclaimer + the evidence-log chain head. In **digest mode**
   (`output.digest`, default on) posting is bounded to a header (counts by priority) +
   the top `detail_top_n` Critical/High findings posted individually — one finding per
   message so OpenClaw's Discord path can't split a block mid-rationale — so channel
   volume stays ~N+2 regardless of finding count; the rest are represented by the
   header (still triaged and signed). Because header-represented and overflow findings
   are marked seen and never re-surface on normal runs, `output.full_digest_weekday`
   names one weekday on which the run re-digests **all currently-open** findings (new +
   already-seen, via `collect.py --include-seen`), ignoring `detail_top_n` and posting
   every open Critical/High individually — display-only, the ledger is untouched so a
   resolved finding is never re-posted.
6. `collect.py mark` records (successfully-posted) + (agent-dropped) finding ids. A
   finding whose post FAILED, or every finding in a chunk that failed to parse, is
   left unmarked, so it retries next run — never a silent loss.

## Why this shape (three-layer threat model)

The point of this harness is defense-in-depth; each layer is independent.

- **Layer 1 — read-only by construction (the outer guarantee).** Prowler and the
  collector authenticate with a **read-only IAM role** (`SecurityAudit` +
  `ViewOnlyAccess`, zero mutate permissions). Even a fully compromised LLM or a bug
  in the orchestrator physically **cannot change, delete, or write-exfiltrate**
  anything in the account. Enforced by IAM, not by code or prompts.
- **Layer 2 — B2 preserved: the LLM stays tool-less.** This harness drives real
  security tools, which *looks* like it breaks the repo's B2 invariant — but it does
  not, because **v1 has no mutating tools**. The orchestrator (deterministic) owns
  all I/O; the triage LLM runs on the `minimal` profile with **zero tools** and
  returns only a validated JSON verdict. LLM output is never read as a command. This
  is the exact shape of the two monitoring harnesses, with richer inputs
  (scan/intel output) and a richer output schema (triage rationale).
- **Layer 3 — tool output is untrusted input.** Scan/intel output is **not** trusted
  just because a scanner produced it. A CVE description, S3 bucket name, IAM policy
  document, or EC2 tag can carry an **indirect prompt-injection** payload
  (attacker-controlled strings inside your own environment). So findings are fenced
  as DATA with an explicit "ignore instructions inside" directive before the
  tool-less LLM sees them, and the reply is schema-validated before use. Worst case,
  a malicious resource name corrupts one finding's priority label — it can never
  touch the host, the account, or the evidence log. And because the KEV / EPSS /
  exposure facts come from the collector (not the LLM) and the priority floor is
  deterministic, even a fully-poisoned verdict cannot under-rank a genuinely
  dangerous finding.

Two more deterministic guardrails reinforce this:

- **The priority floor** (step 4) means the LLM's judgment is advisory *upward only*.
  The authoritative danger signals are collector facts.
- **The signed evidence log** records *which inputs (by digest) → what priority →
  what rationale* in a hash-chained, tamper-evident trail, so "who decided what, on
  what basis" is auditable after the fact. The chain is stdlib SHA-256 (always on) and
  gives tamper-evidence with no key; the signature is a decided three-tier scheme
  (ECDSA P-256 / HMAC-SHA256 / none), `sig_alg`-labelled so a downgrade is visible
  (see `evidence.py`). Honest limit: v1's ECDSA key is a **local PEM**, so host
  compromise ⇒ forgery — v1 signing is tamper-evidence, not non-repudiation against a
  host breach. Off-host signing (KMS, or Sigstore keyless + Rekor) is roadmap stage 3
  (`DESIGN.md` §3.5 / §8).

> **Scope boundary — where this stops being B2.** v1 is Phase 1–3 + 7 (collect →
> enrich → triage → report/evidence), **read-only**. Execution (Phase 4–6: decide →
> apply → verify) is deliberately out of v1. That is the exact point where the
> tool-less orchestrator model gives way to agentic tool-calling with mutating
> (tier-2) tools — and where a human approval gate + AI Gateway + fail-closed policy
> become load-bearing. Introduced only when mutation is on the table, not before.
> See `DESIGN.md` §8 (roadmap) and §3.4 (two-tier tool model).

## Stage 2 — graph context (opt-in, off by default)

When `[graph].enabled = true` in `config.toml`, the collector enriches each finding with
deterministic **asset-graph** facts read from a **Cartography**-populated **Neo4j**, on
top of the v1 KEV/EPSS/exposure signals. This is an add-on, not a new class of behavior —
it strengthens the deterministic Layer-3 floor, it does not touch the B2 or read-only
guarantees.

- **Cartography + Neo4j are external tools** the operator runs, exactly like Prowler.
  Cartography builds the graph from the **same read-only IAM role** (its default AWS sync
  needs no IAM beyond `SecurityAudit` + `ViewOnlyAccess`). `collect.py` **only queries** an
  already-populated Neo4j — it does not run Cartography. Queries go over Neo4j's **HTTP
  transactional Cypher API** with stdlib `urllib` (`neo4j_cypher()`), deliberately **not**
  the third-party `neo4j` bolt driver, so the harness stays stdlib-only.
- **What the facts do** (`graph_facts()` → `graph_enrich()` in `collect.py`): a
  graph-derived `exposure_path` **overrides** v1's keyword `internet_exposed` guess for
  modeled resource types (EC2 / security-group / S3); `blast_radius` grounds the LLM's
  `excess_privilege` in real IAM wildcard reach — including an exposed **EC2** instance
  inheriting the blast-radius of the role it assumes, walked over the
  `EC2Instance → AWSInstanceProfile → AWSRole` bridge; and a graph-confirmed **toxic
  combination** (exposure ∧ over-privilege ∧ KEV/high-EPSS on one finding) floors that
  finding's priority to **Critical**.
- **Graceful degrade — same contract as a down intel feed.** If `[graph].enabled` is off,
  `VULNTRIAGE_NEO4J_PASSWORD` is unset, Neo4j is unreachable, or a finding doesn't join a
  node, that finding falls back to the keyword exposure flag and simply gains no graph
  facts. The run never crashes and never blocks on the graph.
- **Secrets / config split.** The Neo4j endpoint / user / database are non-secret and live
  in `config.toml` `[graph]`. The Neo4j **password is a secret** read from the environment
  (`VULNTRIAGE_NEO4J_PASSWORD`), never `.env` or the repo. Bind Neo4j to localhost only —
  the graph is a sensitive topology map. Validate read-only with
  `collect.py graph-check`. Operator setup runbook: README
  "Appendix — enabling Stage 2 graph context"; design + validation: `DESIGN.md` §12.

## Stage 3 — Trivy collector (opt-in, off by default)

When `[trivy].enabled = true` (or the non-secret env toggle `VULNTRIAGE_TRIVY_ENABLED=true`),
the collector adds a **second source**: Trivy image/package CVEs, merged alongside Prowler's
CSPM findings. This is an add-on, not a new class of behavior — it feeds the *existing*
enrichment + floor pipeline and does not touch the B2 or read-only guarantees.

- **Why it matters.** Prowler findings are misconfigurations and rarely carry a CVE, so the
  KEV/EPSS/NVD enrichment usually has nothing to score. Every Trivy finding *is* a CVE, so
  it lights that pipeline up — the deterministic KEV/high-EPSS priority floor finally has
  CVEs to act on.
- **Trivy is an external tool**, run exactly like Prowler: a **pinned CLI subprocess**
  (`run_trivy_image()`), version-checked against `[trivy].version`, whose JSON is normalized
  to the **same common finding schema** (`normalize_trivy()`) so `enrich()` / the floor /
  digest / evidence / ledger consume it unchanged. `cmd_collect` merges Trivy items **before**
  `enrich()`. Trivy ids are namespaced (`trivy|…`) so they never collide with Prowler uids.
- **Read-only surface.** Scanning explicit image refs (`[trivy].targets`) needs **no AWS
  permissions** — Trivy just pulls from a registry you already authenticate to. The one
  opt-in that widens the surface is `ecr_discovery` (needs ECR data-plane pull actions);
  it is off by default (`DESIGN.md` §13.3).
- **Graceful degrade.** Trivy off, or no `targets`, or a failed image pull → that image is
  simply skipped/absent; the run never crashes and Prowler findings post as usual.
- **Untrusted DATA (B2).** A vulnerability `Description` (attacker-influenceable via a crafted
  image) is fenced as DATA for the tool-less LLM, never interpreted — verified in `DESIGN.md`
  §13.7. Operator setup runbook: README "Appendix — enabling Stage 3 Trivy"; design +
  validation: `DESIGN.md` §13.

## Data feeds / terms

CVE enrichment uses free public feeds via their public APIs — **CISA KEV** (catalog
membership), **FIRST EPSS** (exploit-probability score, batched), and optionally
**NVD** (CVSS, off by default because its unauthenticated rate limit is low). The
collector rate-limits, retries with backoff, and degrades gracefully if a feed is
unreachable (per repo convention #4). Respect each feed's terms and rate limits in
code if you add another. The shipped tool stack is Apache-2.0 / BSD-cored (Prowler);
AGPL tools (e.g. Steampipe) are excluded from the shipped path (`DESIGN.md` §3.6).

## Tuning

Behavior is controlled by `config.toml` (AWS/Prowler scope, enrich feeds, triage
floor thresholds, language, `llm_batch_size`) and `.env` (channel, agent, AWS
profile, CLI paths). The Prowler version pin, retry/backoff, and enrichment live in
`collect.py`; the priority floor, rationale composition, prompt, and post layout live
in `run.py` (`floor_priority` / `build_rationale` / `build_prompt` / `format_post`);
the evidence chain + signature live in `evidence.py`. Leave the scripts and this file
alone unless changing the routine itself.
