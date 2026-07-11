# aisec-vulntriage — DESIGN (v1)

> **Status: design draft — not yet implemented.** This document is the design a
> future implementer (human or agent) builds against. No `run.py` / `fetch.py`
> exists yet. When the v1 walking skeleton lands, most of this becomes `SKILL.md`
> (architecture + threat model) and `README.md` (setup + operation), mirroring the
> two existing harnesses.

A self-hosted **OpenClaw harness that triages cloud vulnerability & misconfiguration
posture** with an LLM, and delivers a prioritized, evidence-backed report. First
target platform: **AWS**. It sits alongside the two monitoring harnesses
(`aisec-arxiv-monitor`, `aisec-news-monitor`) but is a **different class of harness**:
the monitors *watch a public feed and summarize*; this one *reads your own cloud
posture and decides what matters first*.

It is **read-only and non-destructive by construction** (see Security model). v1 does
not change anything in your account — it collects, triages, reports, and records
signed evidence. Remediation execution is explicitly out of v1 scope.

---

## 1. Why this harness exists

Corporate IT / security teams (情シス) spend disproportionate effort on
vulnerability & patch management: collecting scan output, cross-referencing CVEs
against public intel, deciding *which* findings actually matter for *their* assets,
and producing evidence for audit. Most of that — **collect → enrich → triage →
report/evidence** — is reproducible work an agent can carry, while the *act of
applying a change* stays with a human. This harness automates the reproducible part
and stops precisely at the point where a wrong action would be hard to undo.

The AI's distinctive value is **triage with rationale**: not "here are 400 findings"
but "these 12 are High, and here is the machine-readable *why* for each"
(KEV-listed? EPSS score? internet-exposed? over-privileged? business-critical asset?).
That structured rationale is what a human reviews and what the evidence log signs.

## 2. Scope — v1 = Phase 1–3 + 7 (read-only)

The full vulnerability/patch lifecycle is Phase 0–7. **v1 covers collection through
reporting, and stops before any change.** Execution (Phase 4–6) ships later, gated,
as an explicit evolution (see Roadmap).

| Phase | In v1? | What it does | Who acts |
|---|:--:|---|---|
| 0. Asset inventory | partial | Prowler already reads config/exposure; a full asset graph (Cartography) is a fast-follow | Tool (read-only) |
| 1. Vulnerability collection | ✅ | Prowler (CSPM: config + exposure) + free intel feeds (NVD / CISA KEV / EPSS) | Tool (read-only) |
| 2. Enrich / de-dup | ✅ | Normalize, de-duplicate, correlate findings ↔ assets, attach KEV/EPSS | Tool (deterministic) |
| 3. Triage / prioritize | ✅ | **The core.** LLM assigns priority + emits structured rationale | **AI (tool-less)** |
| 4. Decide remediation | ⛔ v1 | recommendation text only; no plan is enacted | (future) human-gated |
| 5. Apply fix | ⛔ v1 | out of scope — no mutating tool exists in v1 | (future) human-gated |
| 6. Verify | ⛔ v1 | out of scope | (future) |
| 7. Report + evidence | ✅ | Discord digest of prioritized findings + append-only **signed** evidence log | Tool (deterministic) |

**v1 = walking skeleton.** Prowler + free feeds + AI triage + Discord + signed
evidence log. Deliberately deferred (documented, not built yet): Cartography(+Neo4j)
graph context, Trivy (image/snapshot CVEs), DefectDojo (system of record), Sigstore
Rekor (transparency log). See Roadmap.

## 3. Security model (this is the point)

Three independent layers, defense-in-depth. The outer layer holds even if every
inner layer fails.

### 3.1 Read-only by construction (the outer guarantee)

The harness authenticates to AWS with a **read-only IAM role**
(`SecurityAudit` + `ViewOnlyAccess`, plus snapshot-read only if/when agentless EC2
CVE scanning is added later). The role has **no mutate permissions at all**. So even
a fully-compromised LLM or a bug in the orchestrator **physically cannot change,
delete, or exfiltrate-via-write** anything in the account. This is the primary
safety property and it is enforced by IAM, not by code or prompts.

### 3.2 B2 preserved — the LLM stays tool-less (the repo invariant holds)

This harness drives real security tools, which *looks* like it breaks the repo's
non-negotiable **B2** convention (the content LLM must be a tool-less text
transform). It does not — because **v1 has no mutating tools**, B2 applies cleanly:

- The **orchestrator** (`run.py`, deterministic) runs Prowler and pulls the intel
  feeds. It owns all I/O.
- The **triage LLM** runs on OpenClaw's `minimal` profile — **zero tools**. It
  receives collected findings **fenced as untrusted DATA** and returns **only a
  structured JSON verdict** (priority + rationale). It cannot fetch, post, run code,
  invoke a scanner, or write the ledger.
- Deterministic code **validates** that JSON against a schema and does everything
  privileged (post, sign, mark). LLM output is **never** read as a command.

This is the exact shape of `aisec-arxiv-monitor` / `aisec-news-monitor` — just with
richer inputs (scan/intel output instead of abstracts) and a richer output schema
(triage rationale instead of a 140-char summary). The proven pattern carries over.

### 3.3 Tool output is untrusted input

Scan and intel output is **not** trusted just because it came from a scanner. A CVE
description, an S3 bucket name, an IAM policy document, or an EC2 tag can carry an
**indirect prompt-injection** payload (attacker-controlled strings in your own
environment). So collected findings are treated exactly like feed text in the
monitors: fenced as DATA with an explicit "ignore instructions inside" directive,
handed to a tool-less LLM, and the LLM's reply is constrained to a JSON schema and
validated before use. Worst case, a malicious resource name corrupts one finding's
priority label — it can never touch the host, the account, or the evidence log.

### 3.4 Two-tier tool model (v1 has only tier 1)

The design reserves a hard line for when execution is added:

- **Tier 1 — collect/read (auto, allow):** Prowler, feed pulls, graph queries.
  Read-only; run freely. **v1 is entirely tier 1.**
- **Tier 2 — mutate/write (deny by default, human-gated):** ticket creation, patch
  apply, config change. **Not present in v1.** When added, tier-2 calls are blocked
  unless a human approval gate passes, enforced structurally in the harness layer
  (and later an AI Gateway + ACS fail-closed policy), **never** by prompt.

### 3.5 Evidence (VAT) — every verdict is signed

Phase 7 writes an **append-only, hash-chained evidence log**: for each triage
verdict, a record of *which inputs (digested) → what priority → what rationale*,
chained (SHA-256) and, when a key is configured, signed. This is the auditable "who
decided what, on what basis" trail.

**Two properties, delivered by two mechanisms** — keep them distinct:

- **Tamper-evidence** is provided by the **hash chain**, always, with zero
  dependencies. Any *edit* to a committed entry breaks the chain and is detected by
  `verify()`. Caveat: the chain alone only stops *edits*; an attacker who can rewrite
  the **whole** log (recompute every hash from a forged point forward) is stopped only
  by a signature over a key they don't hold.
- **Non-repudiation** (third-party-verifiable "this verdict came from this harness and
  was not altered") requires an **asymmetric signature** over each entry hash. This is
  what a real audit wants and what only ECDSA (below) provides.

**Signing is pluggable — a three-tier scheme, decided for v1:**

1. **ECDSA P-256** — used when the `cryptography` package is importable **and**
   `VULNTRIAGE_EVIDENCE_EC_KEY` points to a PEM EC private key. Asymmetric →
   **third-party verifiable** (holder of the public key verifies; only the private
   key signs). This is the audit-grade mode §3.5 targets.
2. **HMAC-SHA256** — stdlib fallback when `VULNTRIAGE_EVIDENCE_KEY` (a shared secret)
   is set but ECDSA is unavailable. Tamper-evident **to a holder of the secret**, but
   the verifier *is* the forger (symmetric) → **no non-repudiation**. It is a genuine
   integrity check, not audit-grade signing, and `sig_alg` says so — we never dress
   HMAC up as ECDSA.
3. **none** — chain-only when no key is configured (**the default**). The chain still
   makes edits evident; the log is simply unsigned and a one-time warning is emitted.

Deliberately not "always sign": stdlib-only portability (repo convention) forbids
requiring `cryptography`, and forcing a shared secret by default would create a
key-management burden for users who only need tamper-evidence. Honest `sig_alg`
labelling means a downgrade is always visible to an auditor.

**Key management (v1 decision).** The one hard part of signing is not the algorithm,
it is **where the private key lives**.

- **v1 = local PEM on the host.** `VULNTRIAGE_EVIDENCE_EC_KEY` names a PEM file the
  operator generates and protects (filesystem perms; never committed — it lives with
  the host's other secrets, per convention #3, not in this directory). Simple, no cloud
  dependency, works offline.
- **Its limit, documented not hidden:** a local PEM means **host compromise ⇒ signature
  forgery**. An attacker with the key (and the append-only log) can rewrite history and
  re-sign it; the signature then proves nothing against that attacker. So the v1
  signature raises the bar for *outsiders* and gives *tamper-evidence for honest
  operators*, but is **not** non-repudiation against a host-level compromise. This
  limitation is stated in `README.md` and `evidence.py` so no one over-trusts it.
- **The robust answers are deferred, on purpose.** True non-repudiation needs the
  signing authority off the host: (a) **KMS-delegated signing** (AWS KMS asymmetric
  key — the private key never leaves the HSM), or (b) **Sigstore keyless + a Rekor
  transparency log** (short-lived OIDC-bound cert + public append-only log, so even the
  operator cannot silently rewrite history). Both add dependencies (AWS reach / network
  + Sigstore) that a walking skeleton should not require. v1 ships the simple local-PEM
  path; **Sigstore keyless + Rekor is the roadmap stage-3 target** (§8), with KMS as an
  alternative if staying inside AWS is preferred.

### 3.6 License hygiene

The shipped tool stack is **Apache-2.0 / BSD-cored** (Prowler, and later Cartography /
Trivy / DefectDojo / Sigstore) so a future commercial/dual-license path (see repo
`CLA.md`) stays clean. **AGPL tools (e.g. Steampipe) are excluded** from the shipped
path — usable only in a maintainer's own verification, never bundled. Free data
feeds (NVD, CISA KEV, EPSS, OSV.dev) are used via their public APIs; respect each
one's rate limits and terms in code, per repo convention #4.

## 4. Architecture (v1 walking skeleton)

```
   read-only IAM role (SecurityAudit + ViewOnlyAccess)
                      │
                      ▼
        ┌──────────── run.py (orchestrator, deterministic) ────────────┐
        │                                                              │
   [1] collect            [2] enrich           [3] triage        [7] report+evidence
   Prowler (CSPM)   →   normalize/de-dup   →   tool-less LLM   →   Discord digest
   NVD/KEV/EPSS         correlate+attach       (minimal profile)   + signed evidence log
   (free feeds)         KEV/EPSS               structured JSON     + dedup ledger (mark)
        │                                          ▲
        └── findings fenced as untrusted DATA ─────┘
```

- **Deferred (documented, not in v1):** Cartography(+Neo4j) for asset-graph exposure
  context (the "toxic combination" story — public × over-privileged × KEV), Trivy for
  image/snapshot CVEs, DefectDojo as system of record, Sigstore Rekor transparency.

### Flow (`run.py`)

1. **Collect** — run Prowler (read-only) for config/exposure findings; pull NVD /
   CISA KEV / EPSS for the referenced CVEs. Deterministic; rate-limited; stdlib +
   the pinned tool.
2. **Enrich** — normalize to a common finding schema, de-duplicate, correlate each
   finding to its asset, attach KEV membership + EPSS score. No LLM.
3. **Triage** — judge findings in chunks (`llm_batch_size`), each a **separate**
   `openclaw agent` call with a **fresh unique `--session-key`** (stateless per
   chunk — same lesson as the monitors: shared sessions contaminate verdicts). The
   findings are fenced as untrusted DATA. Each call returns strict JSON between
   markers: a priority verdict + structured rationale per finding (see §5). A chunk
   whose JSON won't parse is left unmarked to retry — it does not sink the run.
4. **Report + evidence** — build a prioritized Discord digest from **trusted**
   enrichment metadata (asset, CVE id, KEV/EPSS) plus the LLM's priority + rationale;
   append each verdict to the signed evidence log; **then** mark handled findings in
   the dedup ledger (`state/seen.json`). Post-then-mark = a failed post retries next
   run; nothing is silently lost.

## 5. Triage output — the structured rationale schema

The LLM returns machine-readable rationale, not prose. This single artifact serves
**both** the human reviewer and the VAT signature (a bare score is unauditable). Draft:

```json
{
  "verdicts": [
    {
      "finding_id": "<stable id from enrich>",
      "priority": "Critical | High | Medium | Low",
      "rationale": {
        "kev_listed": true,
        "epss": 0.87,
        "internet_exposed": true,
        "excess_privilege": false,
        "asset_criticality": "high",
        "summary": "<short human-readable why, in output.language>"
      }
    }
  ],
  "dropped": ["<finding_id>", "..."]
}
```

Deterministic code validates the schema, the enum values, and that every id belongs
to the chunk it was sent — then acts. `recall on High` matters more than precision
(a missed High is worse than an over-flagged Medium); this frames the validation and
the eventual eval KPI (agreement with a human analyst's triage as ground truth).

## 6. OpenClaw mapping (same idiom as the monitors)

- **Agent:** registered with `openclaw agents add`, **locked to the `minimal` tool
  profile** — the core of the security model; skipping it hands the triage LLM real
  tools. Not bound to inbound channels; runs on a schedule.
- **Orchestrator:** cron `--command` job running `run.py` with `--no-deliver`.
- **Config split:** `config.toml` = committed shared defaults (AWS regions, Prowler
  checks/scope, `llm_batch_size`, language, priority thresholds) — no secrets, no
  per-deployment state. `.env` (git-ignored) = deployment-specific non-secret values
  (`VULNTRIAGE_CHANNEL_ID`, `VULNTRIAGE_AGENT_ID`, `OPENCLAW_BIN`, AWS
  profile/region). **AWS credentials & Discord token live in the host / OpenClaw
  credential chain — never in this directory** (repo convention #3).
- **State:** `state/seen.json` dedup ledger (git-ignored, ships empty) + the signed
  evidence log.
- **SPDX headers** on every `*.py` / `*.toml` per repo convention #7.

## 7. Output format (draft)

Discord post per prioritized finding (built from trusted metadata + LLM
priority/rationale; the LLM never echoes ids or URLs):

```
🛡️ **[<priority>] <asset> — <CVE / check id>**
📊 KEV: <yes/no>  |  EPSS: <score>  |  Exposure: <internet/internal>
<short rationale, ≤ configured length, in output.language>
🔗 <finding source: Prowler check / NVD url from trusted data>
```

Plus, once per run, an evidence-log reference (chain head hash) so a reader can tie
the digest to the signed record.

## 8. Roadmap (phased evolution)

Four stages, each an explicit escalation. Stages 1–3 are read-only and preserve B2
(tool-less LLM + deterministic orchestrator); stage 4 is the deliberate break, where
mutation forces agentic tools and load-bearing governance. The stage-level plan is
stable; the sub-milestone checklist under stage 1 is the live progress view.

Status legend: ✅ done · 🟡 in progress / unmerged · ⏳ planned, not started.
Sub-milestone status is current as of 2026-07-10 (see the repo-root `STATUS.md` for
the cross-harness session log; this checklist is the vulntriage-specific roadmap view).

1. **v1 — walking skeleton** (this doc) — Prowler + feeds + AI triage + Discord +
   signed evidence log. Read-only, B2-preserving, tier-1 tools only. Sub-milestones:
   - ✅ **S1.1 Design** — v1 scope (Phase 1–3 + 7) + this DESIGN.md (PR #13)
   - ✅ **S1.2 Core** — `collect.py` / `evidence.py` / `run.py`; deterministic priority
     floor; hash-chained evidence log (PR #14)
   - ✅ **S1.3 Persona + distribution docs** — AGENTS / SOUL / IDENTITY / SKILL /
     README, three-layer threat model (PR #15)
   - ✅ **S1.4 Signing scheme finalized** — 3-tier pluggable (ECDSA P-256 / HMAC /
     none); key management v1 = local PEM; off-host non-repudiation deferred to
     stage 3 (PR #16; see §3.5, §10)
   - ✅ **S1.5 Live end-to-end verification** — real Prowler v5 scan → tool-less triage
     → Discord post → evidence verify, confirmed by reading the channel (verification
     only, no PR)
   - ✅ **S1.6 Digest mode** — bound Discord volume to ~N+2 messages regardless of
     finding count; fix invalid `lambda` → `awslambda` service name (PR #17)
   - ✅ **S1.7 Weekly full re-digest** — `output.full_digest_weekday` re-surfaces ALL
     currently-open findings (via `collect.py --include-seen`), countering the digest
     "permanent invisibility" of header-represented / overflow findings; display-only,
     the ledger is untouched (PR #18)
   - 🟡 **S1.8 Operational hardening** — autonomous operation started; one optional
     item remains.
     - ✅ Persistent Prowler install off the volatile scratchpad venv — dedicated venv
       at a stable path (`~/.local/share/aisec-vulntriage/prowler-venv`) wired via
       `PROWLER_BIN`.
     - ✅ Dedicated read-only role — `aisec-vulntriage-readonly` (SecurityAudit +
       ViewOnlyAccess + `prowler-additions`), assumed via a named profile; runbook in
       README Appendix (PR #19).
     - ✅ Cron job — `vulntriage-weekday` (weekdays 08:00 JST, Monday = weekly full
       re-digest); smoke-verified end-to-end under the read-only role, then enabled.
     - ⏳ Evidence signing key (**optional**, deferred) — default `sig_alg=none`
       (chain-only, tamper-evident). Set `VULNTRIAGE_EVIDENCE_EC_KEY` for audit-grade
       ECDSA signing when/if non-repudiation is needed; may be picked up later.
   - ✅ **S1.9 v0.1 OSS release** — read-only, B2-preserving walking skeleton declared
     v0.1; release-prep docs finalized (`.env.example` documents the recommended
     read-only named profile + stable-path Prowler venv; README/DESIGN progress synced).
2. 🟡 **+ Graph context** — add Cartography(+Neo4j); triage rationale gains exposure
   paths / blast radius (the toxic-combination value). Still read-only, still B2.
   Detailed design in **§12**. Sub-milestones:
   - ✅ **S2.0 Design annex** — §12: IAM diff (existing read-only role suffices),
     Neo4j-over-HTTP to keep stdlib-only, Prowler↔Cartography join-key design, B2
     preservation, sub-milestones.
   - ✅ **S2.1 Join validation** — real Cartography sync under `aisec-vulntriage-readonly`:
     only `AccessDenied` is the optional `inspector2` module (§12.2 confirmed); ARN join
     88% / +id-fallback 97% of real resources; EC2 requires the id fallback. Full results
     + per-type table in **§12.8**.
   - ✅ **S2.2 Neo4j HTTP query helper** — `collect.py` `neo4j_cypher()` (stdlib urllib +
     basic-auth), `graph_facts()` exposure/blast-radius Cypher, `graph-check` command.
     Verified on the live graph; details + limits in **§12.9**.
   - ✅ **S2.3 Wire graph facts** — `graph_enrich()` in `collect.py` overrides the keyword
     `internet_exposed` with graph `exposure_path` (keyword kept as the degrade path); `run.py`
     `build_rationale` records graph provenance + grounds `excess_privilege` with blast-radius,
     and `floor_priority` floors a graph-confirmed toxic combination to Critical. Details in
     **§12.10**.
   - ✅ **S2.4 Config/docs** — graph toggle (`[graph].enabled`, default off) shipped in
     S2.2; README "Appendix — enabling Stage 2 graph context" + SKILL "Stage 2" section
     + `.env.example` note (PR #25). No `CARTOGRAPHY_BIN`: the harness only *queries*
     Neo4j, Cartography+Neo4j are operator-run out-of-band tools (docs say so).
   - ✅ **S2.5 Env toggle + live cutover** — non-secret `VULNTRIAGE_GRAPH_ENABLED`
     env toggle (`collect.py` `_graph_enabled`) so an in-place deployment turns graph
     mode on without a config-drift edit `git pull` would revert (PR #27); live cron
     `vulntriage-weekday` cut over to graph mode with the Neo4j password injected via
     `--command-env`, smoke-verified then enabled. **Graph mode is live.**
3. 🟡 **+ More collectors & audit-grade evidence** — three independent tracks: **Trivy**
   (image/package CVEs), **DefectDojo** (system of record), and **off-host signing**
   (Sigstore keyless + Rekor / KMS) to move evidence signing off the host — the
   non-repudiation the v1 local-PEM path deliberately does not provide (§3.5). The Trivy
   track is detailed in **§13**. Sub-milestones (Trivy first, as its own PR):
   - ✅ **S3.0 Design annex** — §13: Trivy scope (image refs default / ECR opt-in),
     the ECR-pull IAM fork + recommendation, schema mapping, dedup key, B2 preservation.
   - ✅ **S3.1 Trivy collector** — `collect.py` `run_trivy_image()` + `normalize_trivy()`
     + `collect_trivy()`, `[trivy]` config (default off), `VULNTRIAGE_TRIVY_ENABLED` env
     toggle, `--trivy-output` dry-run; `cmd_collect` merges Trivy CVE findings before
     `enrich()` so they feed KEV/EPSS/NVD. `run.py` `format_post` labels source honestly.
   - ✅ **S3.2 Live verification** — real Trivy scan of a Log4Shell image → first non-empty
     KEV/EPSS enrichment on real data, floor → Critical on 5 KEV findings, digest posted
     intact; live ledger/evidence untouched (§13.7).
   - 🟡 **S3.3 Config/docs** — README "Appendix — enabling Stage 3 Trivy" (incl. the
     ECR-discovery IAM note), SKILL "Stage 3" section, `.env.example`, this §8 sync.
   - ⏳ **S3.4 DefectDojo** — push signed verdicts to DefectDojo as the system of record
     (separate PR).
   - ⏳ **S3.5 Off-host signing** — Sigstore keyless + Rekor / KMS-delegated signing;
     delivers the non-repudiation the v1 local-PEM path does not (separate PR).
4. ⏳ **Phase 4–6 (execution)** — *this* is where the architecture escalates beyond B2:
   the tool-less orchestrator model gives way to **agentic tool_call** with tier-2
   mutating tools, and the governance the report specifies becomes load-bearing —
   **human approval gate + AI Gateway (LiteLLM/Portkey) + ACS fail-closed policy at
   the tool-execution checkpoint + full VAT**. Introduced exactly when mutation is on
   the table, not before.

## 9. Relationship to the rest of the repo

- **Self-contained** (convention #1): copy this folder, supply creds, run. No shared
  core with the monitors — logic is copied, not imported.
- **Same security ethos, adapted:** the monitors keep untrusted *feed* text away from
  tools; this harness keeps untrusted *scan/intel* output away from tools **and** the
  cloud away from writes (read-only IAM). B2 is preserved for v1; the agentic
  escalation is the documented Phase 4–6 step.
- **Idempotent ledger, no secrets, attribution/ToS in code** — unchanged.

## 10. Open decisions

- **Name.** `aisec-vulntriage` is provisional. The `aisec-` prefix here means "an AI
  agent doing security work," vs the monitors' "monitoring AI-security topics" — same
  prefix, different sense. Confirm keep vs rename (e.g. `aisec-cloud-triage`).
- ~~**Graph context timing.**~~ **Resolved: stage 2, not v1.** Cartography(+Neo4j)
  is deferred to roadmap stage 2 (Neo4j is the heaviest single dependency). v1 ships
  without it; exposure context is approximated by the `internet_exposed` /
  `asset_criticality` flags in the triage schema (§5), accepting that path-based
  "toxic combination" rationale waits for stage 2.
- ~~**Evidence signing key management.**~~ **Resolved (§3.5).** Signing is a decided
  three-tier pluggable scheme — ECDSA P-256 (opt-in, third-party verifiable) / HMAC-
  SHA256 (stdlib fallback, integrity-only) / none (default, chain-only + warn), with an
  honest `sig_alg` label. Key management for v1 = **local PEM** on the host
  (`VULNTRIAGE_EVIDENCE_EC_KEY`), with the host-compromise-⇒-forgery limit documented,
  not hidden. True non-repudiation (off-host signing authority) is deferred: **Sigstore
  keyless + Rekor is the roadmap stage-3 target** (§8), KMS-delegated signing an
  in-AWS alternative.
- **Prowler invocation.** Pinned CLI subprocess vs library; which check packs
  (CIS / exposure) are on by default in `config.toml`.
- **Reviewer surface.** v1 posts to Discord (post-hoc review, like the monitors). If
  a pre-report human gate is wanted even for a read-only report, add a staging step.

## 11. Design lineage

Derived from the 3-part source report (2026): (1) analysis of 情シス security work &
where AI agents / HaaS can substitute; (2) the vulnerability/patch-management agentic
workflow PoC (Phase 0–7, HITL gates, VAT); (3) the AWS-origin, OSS-cored, OpenClaw
orchestration design (Cartography / Prowler / Trivy / DefectDojo / Sigstore; AI
Gateway; ACS / ASSERT / AGT governance). This harness is the v1 slice of that report:
read-only, B2-preserving, walking-skeleton scope, with the report's agentic/governance
machinery placed on the roadmap for the execution phases.

## 12. Stage 2 design annex — graph context (Cartography + Neo4j)

> **Status: design draft for stage 2 — not implemented.** This annex is the detailed
> expansion of roadmap item **§8.2** ("+ Graph context"). Stage 1 (v1) shipped without
> it; this is the design a future implementer builds against. Stage 2 stays **read-only
> and B2-preserving** — it adds *inputs*, not tools or mutation.

### 12.1 What graph context buys

v1 approximates exposure with a keyword heuristic: `internet_exposed` is `true` when the
Prowler `check_id`/`title` contains an exposure hint word (see `collect.py`
`EXPOSURE_HINTS`). That is a proxy for the *check topic*, **not** a claim about the real
network/IAM path to the specific resource. The report's headline differentiator —
**toxic combinations** (a resource that is *publicly reachable* **and** *over-privileged*
**and** carries a *KEV-listed / high-EPSS* CVE) — needs a **path**, not a flag.

Cartography ingests the account into a Neo4j graph (assets as nodes, network/IAM
relationships as edges). Deterministic Cypher over that graph turns the flag into a
fact:

- **`exposure_path`** — is there an actual path from an internet-facing entry
  (IGW → public subnet / public IP / `0.0.0.0/0` security-group ingress, or a public
  S3 bucket policy) to this resource? Replaces the keyword guess with a graph-derived
  answer.
- **`blast_radius`** — what can this resource's IAM principal reach (count / criticality
  of reachable sensitive nodes)? Grounds `excess_privilege`, which v1 leaves entirely to
  the LLM.
- **`toxic_combination`** — the conjunction `exposure_path ∧ over_privileged ∧ (KEV ∨
  high-EPSS)`. When true, it is the strongest deterministic signal we have.

These are **collector-authoritative facts**, computed by the orchestrator — exactly like
KEV/EPSS today (§3.5, §5). They extend the deterministic **priority floor** (Layer 3): a
graph-confirmed toxic combination floors priority to Critical, and a compromised LLM
cannot talk it down. The LLM's role is unchanged — it still only sees findings-as-DATA
and returns JSON.

### 12.2 IAM — the read-only role already suffices (key finding)

Cartography's documented requirement for its AWS sync is the **`SecurityAudit`** managed
policy ("grants access to read security config metadata"). The existing S1.8 role
`aisec-vulntriage-readonly` already attaches **`SecurityAudit` + `ViewOnlyAccess` +
`prowler-additions`**, so:

| Cartography needs | Covered by | Status |
|---|---|---|
| `SecurityAudit` (baseline) | attached directly | ✅ present |
| `ec2:DescribeRegions` (region enumeration) | `SecurityAudit` / `ViewOnlyAccess` `ec2:Describe*` | ✅ present |
| `ecr:DescribePullThroughCacheRules` | `prowler-additions` `ecr:Describe*` | ✅ present |
| `inspector2:*` read (Inspector module only) | — (`AmazonInspector2ReadOnlyAccess`) | ⏳ optional; only if the Inspector sync is enabled |

**Result: no new IAM is required for Cartography's default AWS sync, and none of it
mutates.** The outer safety guarantee (Layer 1, §3.1) extends to stage 2 *for free* — the
graph is built from the same read-only credentials. The only gap is the optional
`inspector2` module; keep it **off by default** so the role stays unchanged, and document
`AmazonInspector2ReadOnlyAccess` as the opt-in for users who enable it. This must still be
**verified empirically** (S2.1) against a real Cartography sync — "no `AccessDenied` in
the sync log," the same acceptance bar used for the Prowler read-only dry run.

### 12.3 Neo4j deployment + the stdlib-only constraint

- **How it runs.** Neo4j is an **external service** (local Docker, `neo4j` official
  image), and Cartography is an **external CLI tool** — the same category as Prowler
  (`PROWLER_BIN`), *not* a Python import into the harness. So the orchestrator invokes
  `cartography` via subprocess (a new `CARTOGRAPHY_BIN`) after the Prowler collect, and
  Neo4j holds the derived graph.
- **stdlib-only is preserved** (repo convention) by **not** using the `neo4j` bolt driver
  (third-party). `collect.py` queries Neo4j over its **HTTP Cypher API** with `urllib`
  (basic-auth header + JSON body/response) — the same shape as the existing
  `http_get_json` used for KEV/EPSS/NVD. External tools do the heavy lifting; harness
  scripts stay pure-stdlib.
- **The graph is derived + ephemeral.** It is fully re-syncable from the account, so
  there is no backup burden and no state to protect beyond secrets. Bind Neo4j to
  **localhost only** — the graph is a sensitive map of your asset topology and must not be
  network-exposed. The Neo4j password is a **secret** → host credential chain / env, never
  `.env` (which is non-secret only, convention #3).
- **License note (decided — acceptable).** Cartography is Apache-2.0 (clean). **Neo4j
  Community Edition is GPLv3.** Because Neo4j runs as a *separate process* accessed over
  bolt/HTTP (mere aggregation, like using PostgreSQL), it does **not** impose GPL on the
  harness's own AGPL/CLA-covered code. Under §3.6 this separate-process posture is
  **confirmed acceptable**: Neo4j is a user-run external service, not bundled or linked into
  the shipped path, so the CLA's dual-license path stays clean. (Recorded here rather than
  re-litigated per stage; Cartography has no non-Neo4j backend, so this is the enabling
  decision for graph context.)

### 12.4 Join-key design — Prowler finding ↔ Cartography node

The correlation hinges on matching each v1 finding to its graph node. The finding schema
(`collect.py` `normalize()`) already carries the fields needed: `resource` (OCSF
`resources[].uid`, typically the **ARN**), `resource_type`, `account`, `region`,
`resource_name`.

- **Primary key: ARN.** Cartography stores `arn` (and `id`) on most AWS nodes; Prowler's
  `resources[].uid` is normally the ARN. Join `finding.resource == node.arn`.
- **Per-type fallback** when ARN is absent or shaped differently (some resource types key
  on id/name, e.g. S3 by bucket name, EC2 by instance id): fall back to
  `(account, region, resource_name)` or the bare resource id, keyed by `resource_type`.
- **Empirical validation is mandatory (S2.1).** The real ARN hit-rate per `resource_type`
  is not assumable — validate it against the **S1.5 captured real Prowler v5 output** and a
  real Cartography sync of the same account, and record the per-type join strategy +
  hit-rate. Findings that don't join degrade gracefully: they keep v1's keyword
  `internet_exposed` and simply gain no graph facts (same graceful-degrade contract as a
  down intel feed).

### 12.5 B2 / layering — unchanged

Stage 2 adds **no tools to the LLM and no mutation to AWS.** Cartography sync (subprocess)
and Cypher queries (deterministic `urllib`) are orchestrator work; the graph-derived
facts join the *trusted* enrichment metadata (never LLM-authored), and the tool-less LLM
still receives findings fenced as DATA and returns only the §5 JSON verdict. The new facts
strengthen the deterministic floor rather than the LLM's discretion — the same
"determinism overrides the LLM" property that makes v1 safe (Layer 3). All three security
layers (read-only IAM / tool-less B2 / deterministic-facts-win) hold as-is.

### 12.6 First implementation steps (proposed sub-milestones)

- ✅ **S2.1 Join validation (do first, no code shipped) — DONE (2026-07-03).** Ran
  Cartography against the test account under `aisec-vulntriage-readonly`; confirmed the
  only `AccessDenied` is the optional `inspector2` module, and measured the ARN join
  hit-rate per `resource_type`. Results, the per-type join + fallback table, and the
  environment are recorded in **§12.8**. Headline: **ARN-only join 88%, ARN + per-type
  id fallback 97%** of real resources.
- ✅ **S2.2 Neo4j HTTP query helper — DONE (2026-07-03).** `collect.py` gains
  `neo4j_cypher()` (stdlib `urllib` + basic-auth over the HTTP transactional endpoint,
  bounded retry, `Neo4jError` on failure), `graph_key()` (the S2.1 ARN-primary + id
  fallback join), `graph_facts()` (the `exposure_path` / `blast_radius` Cypher), and a
  read-only `graph-check` command that exercises them. Verified on the live graph; the
  Cypher, results, and the blast-radius limitation are recorded in **§12.9**. Not yet
  wired into triage (that is S2.3).
- **S2.3 Wire graph facts** into the finding schema, the §5 rationale, and the priority
  floor; replace the keyword `internet_exposed` with the graph-derived `exposure_path`,
  keeping the keyword as the degrade path when the graph is unavailable.
- 🟡 **S2.4 Config/docs — docs DONE (2026-07-06).** `config.toml` graph toggle
  (`[graph].enabled`, default **off** so v1 users are unaffected and the harness degrades
  to keyword exposure) shipped in S2.2. Distribution docs now cover safe operator
  enablement: README **"Appendix — enabling Stage 2 graph context (Cartography + Neo4j)"**
  (Neo4j 5.x localhost-only container, Cartography sync under the read-only role incl. the
  `python:3.12` container fallback, `VULNTRIAGE_NEO4J_PASSWORD` as a host-env secret,
  `[graph].enabled=true`, `graph-check` verify), SKILL **"Stage 2 — graph context"**
  section, and a `.env.example` note. **Correction to the earlier plan:** there is **no
  `CARTOGRAPHY_BIN`** — `collect.py` only *queries* an already-populated Neo4j (HTTP
  Cypher), so Cartography + Neo4j are operator-run **out-of-band** tools (Neo4j endpoint /
  user / db are non-secret in `config.toml [graph]`; only the password is an env secret).
  **Remaining:** stand up a *persisted* Neo4j + Cartography sync and flip a live cron to
  `[graph].enabled=true` (the environment has been volatile across sessions — see §12.11).

### 12.7 Open questions (stage 2)

- ~~**ARN join hit-rate** per resource type~~ — **resolved (S2.1, see §12.8)**: ARN alone
  joins **88%** of real resources; adding the per-type id fallback (ARN tail → Cartography
  `node.id`, required for EC2 instances/security-groups which carry no `arn` property)
  raises it to **97%**. The ~3% residue (EIPs Cartography doesn't sync, unattached
  AWS-managed policies) degrades gracefully to the v1 keyword flag, as designed.
- ~~**Neo4j GPLv3**~~ — **resolved**: the separate-process (bolt/HTTP) posture is accepted
  under §3.6; Neo4j is a user-run external service, not bundled (see §12.3).
- **Sync cadence** — Cartography sync is heavier than a Prowler scan; decide whether it
  runs every triage run or on a slower cadence with the graph cached between runs.

### 12.8 S2.1 validation results (empirical, 2026-07-03)

Ran the join validation end-to-end against a real account. **No harness code was written**
(per §12.6, S2.1 is verify-and-record only). Environment: Cartography **0.138.1**
(Apache-2.0, isolated venv) → **Neo4j 5.26.28 Community** (local Docker, bound to
`127.0.0.1` only) syncing account `278059980943`, `us-east-1`, under the existing
`aisec-vulntriage-readonly` role; joined against a fresh Prowler v5 `json-ocsf` scan of
`ec2,s3,iam,rds,awslambda` (730 records, 189 FAIL / 541 PASS).

**Result 1 — IAM (validates §12.2).** The Cartography default AWS sync produced exactly
**one** authorization failure across the whole run:
`inspector2:ListMembers … not authorized … Skipping…` — i.e. the *single optional module*
§12.2 predicted, which Cartography degrades past gracefully. Every core sync (ec2, s3, iam,
rds, lambda, kms, cloudwatch, …) completed with **zero `AccessDenied`**. The other skips in
the log were non-authorization (CloudTrail needs a `--lookback` flag; GuardDuty/Cognito had
no resources present; `permission_relationships` needs an opt-in mapping file). **Conclusion:
the existing read-only role suffices for Cartography's default AWS sync — no new IAM, no
mutation. Keep `inspector2` off by default; document `AmazonInspector2ReadOnlyAccess` as the
opt-in for users who enable that module.** Layer 1 extends to stage 2 for free, as designed.

**Result 2 — join hit-rate (resolves §12.7).** Of 182 unique Prowler resources, **6 were
account-level pseudo-ARNs** (`…:account`, `…:root`, `…:mfa`, `…:password-policy`) that map
to no discrete resource node by design — these are account-scope findings, handled at
account level, never resource-joined. Of the **176 real resources**:

| join strategy | hit | rate |
|---|---|---|
| ARN primary (`finding.resource == node.arn`) | 155 | **88.1 %** |
| + per-type id fallback (ARN tail → `node.id`) | 170 | **96.6 %** |

**Result 3 — per-type join table (the deliverable §12.4 asked for).**

| Prowler `resource.type` | Cartography label | join key | strategy | hit |
|---|---|---|---|---|
| `AwsIamRole` / `AwsIamUser` / `AwsIamGroup` / `AwsIamPolicy` | `AWSRole` / `AWSUser` / `AWSGroup` / `AWSPolicy` | **`arn`** | primary ARN | 97–100 % |
| `AwsS3Bucket` | `S3Bucket` | **`arn`** (`arn:aws:s3:::name`, exact match) | primary ARN | 100 % |
| `AwsEc2Volume` | `EBSVolume` | **`arn`** | primary ARN | 100 % |
| `AwsEc2NetworkAcl` | `EC2NetworkAcl` | **`arn`** | primary ARN | 100 % |
| `AwsEc2Instance` | `EC2Instance` | **`id`** — *no `arn` property* | fallback: ARN tail `i-…` → `node.id` | 100 % |
| `AwsEc2SecurityGroup` | `EC2SecurityGroup` | **`id`** — *no `arn` property* | fallback: ARN tail `sg-…` → `node.id` | 100 % |
| `AwsEc2Eip` | *(not synced by Cartography)* | — | no node → keep v1 keyword flag | 0 % |
| account-level (`…:root`/`…:mfa`/`…:password-policy`/`…:account`) | `AWSAccount` | — | account-scope, not resource-joined | n/a |

**Key finding for the implementer (S2.2/S2.3):** the per-type fallback §12.4 anticipated is
**mandatory** — Cartography stores EC2 instances and security groups keyed on `id` with **no
`arn` property**, so an ARN-only join silently drops every EC2 resource. The fallback is
simple and total: take the last path component of the Prowler ARN (`…/i-abc` → `i-abc`,
`…/sg-abc` → `sg-abc`) and match `node.id`. IAM and S3, by contrast, join cleanly on `arn`.
With both, real-resource coverage is ~97 %; the residue (EIPs, unattached AWS-managed
policies) is exactly the graceful-degrade set — those findings keep v1's keyword
`internet_exposed` and gain no graph facts.

**Also confirmed:** the Neo4j **HTTP Cypher API** (`/db/neo4j/tx/commit`, basic-auth) is
reachable and returns the node ARNs/ids with a **pure-stdlib `urllib`** client — validating
the §12.3 approach (no `neo4j` bolt driver needed in `collect.py`).

> Reproduction note: the validation used throwaway artifacts (a local Neo4j container, a
> scratch Prowler scan, an ad-hoc `urllib` query script) — none committed, consistent with
> "no code shipped." S2.2 is where the HTTP Cypher helper and the join logic above land in
> `collect.py`.

### 12.9 S2.2 implementation notes (2026-07-03)

Shipped in `collect.py` (stdlib only, read-only, B2-preserving):

- **`neo4j_cypher(endpoint, user, password, statement, params, database)`** — one Cypher
  statement over Neo4j's HTTP transactional endpoint (`POST /db/<db>/tx/commit`), basic-auth
  header, JSON body, rows returned as dicts. Same bounded-retry/backoff as the intel feeds;
  raises `Neo4jError` on a Cypher error, `401/403`, or exhausted retries. Deliberately **not**
  the `neo4j` bolt driver — keeps the harness stdlib-only (validates §12.3).
- **`graph_key(uid)`** — the S2.1 join: ARN primary, with the last-path-component id fallback
  (`…/i-abc` → `i-abc`) that EC2 needs.
- **`graph_facts(graph_cfg, password, findings)`** — bulk-resolves findings to nodes and
  returns `{finding_id: {joined, join_by, node_labels, exposure_path, blast_radius}}`.
- **`graph-check` command** — read-only; prints the facts per finding. Exercises the above
  without touching the ledger/triage. `[graph]` config (default **off**) + secret
  `VULNTRIAGE_NEO4J_PASSWORD` (env, never `.env`) added.

**The Cypher, written against the real graph schema (verified, not assumed):**

- **EC2 exposure** — Cartography does **not** set an `exposed_internet` boolean in this
  version, so exposure is computed: an `EC2Instance` is exposed if it has a
  `publicipaddress` **or** is a member of an internet-open security group. Open-ingress is
  `(:IpRange {id:'0.0.0.0/0'})-[:MEMBER_OF_IP_RULE]->(:IpPermissionInbound)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)`
  — note the inbound rule attaches to the SG via `MEMBER_OF_EC2_SECURITY_GROUP` (not
  `MEMBER_OF_IP_RULE`), and the `IpPermissionInbound` label is what distinguishes an inbound
  rule from the egress rules that also point at `0.0.0.0/0`.
- **S3 exposure** — read off the `S3Bucket` node: `anonymous_access`, and an incomplete
  public-access block (`block_public_acls`/`restrict_public_buckets` not both true).
- **Blast radius (IAM principal)** — `(:AWSRole|:AWSUser {arn})-[:POLICY]->(:AWSPolicy)-[:STATEMENT]->(:AWSPolicyStatement {effect:'Allow'})`,
  counting statements whose `action` contains `*` (`admin_like`) or a `service:*` wildcard.

**Verified results (live graph, `graph-check` over the 153-finding S1.5-style scan):**
143/153 findings joined (10 unjoined = the account-level pseudo-ARNs, as in §12.8);
**exposure_path=true for 9** (7 EC2 instances with public IPs, 2 security groups open to
`0.0.0.0/0` on SSH); **admin-like blast for 19** (e.g. the `full_access` role and the
`AdministratorAccess` SSO role, matched by `Action:*`). Graceful degrade confirmed: an
unreachable endpoint retries then raises, a bad password fails fast — both fall back to the
v1 keyword flag (§12.4), never crash the run.

**Empirical limitation for the S2.3 implementer (like S2.1's EC2-no-arn finding):**
blast-radius is a **wildcard-privilege proxy**, not true reachability. Cartography without the
opt-in `--permission-relationships-file` writes no `CAN_ACCESS` edges to specific resources,
and in this sync **EC2 instances carry no instance-profile→role edge**, so a compute
resource can't be walked to its privileges. Deepening blast-radius means enabling the
permission-relationships mapping (which needs **no extra IAM** — it is computed from
already-synced policy data) and, for compute, the instance-profile edge. `admin_like` is the
honest v1 signal; record the depth ceiling rather than overclaim a path.

### 12.10 S2.3 wiring — graph facts into triage (2026-07-04)

Wires the S2.2 graph facts into the collector schema, the priority floor, and the signed
rationale. Behavior is gated on `[graph].enabled` (default off), so v1 users are unaffected
and every failure mode degrades to the keyword flag.

**collect.py** — `graph_enrich(items, cfg)` runs right after `enrich()` in `cmd_collect`:
when `[graph].enabled` and `VULNTRIAGE_NEO4J_PASSWORD` is set, it calls `graph_facts()`,
attaches the facts to each finding's new `graph` field (schema default `{}`), and lets the
graph-derived `exposure_path.exposed` **override** the keyword `internet_exposed` — but only
for the node types the graph actually models. `graph_facts()` now sets `exposed` to a
definite `True`/`False` only for `EC2Instance` / `EC2SecurityGroup` / `S3Bucket`
(`EXPOSURE_MODELED_LABELS`) and `None` for any other joined type, so a joined IAM/RDS node
whose exposure the graph doesn't compute **keeps the keyword flag** instead of being wrongly
cleared to `False`. Disabled toggle, missing password, unreachable graph (bounded retry then
`Neo4jError`), and unjoined resources all degrade to the keyword flag — verified through the
real `collect` path (exit 0 in every case; never crashes a run).

**run.py** — three deterministic (collector-authoritative) hooks read `item["graph"]`:
- `graph_over_privileged(item)` — `True` when the joined IAM principal's blast-radius has a
  `*` action or a `service:*` statement, `False` for a joined principal without one, `None`
  when the graph has no opinion. The honest wildcard proxy, not reachability (§12.9).
- `build_rationale` — the graph blast-radius **grounds** `excess_privilege`: it can force it
  `True` (collector fact) but never `False` (the proxy is incomplete, so the LLM may still see
  over-privilege it misses). Records a `graph` provenance sub-object (`join_by`, `exposure`,
  `exposure_reasons`, `blast_radius`) in the signed evidence when the resource joined.
- `floor_priority` — a graph-confirmed **toxic combination** (`exposure ∧ over_privileged ∧
  (KEV ∨ high-EPSS)`) floors priority to **Critical**. The floor is wired and unit-tested.

**Honest limitation:** the toxic-combination floor rarely fires *per finding* today, because
`graph_facts()` computes exposure on EC2/SG/S3 nodes and over-privilege on IAM principals
*separately* and does not yet **walk** from an exposed compute node to its role. The two *real*
wins that fire today are (1) graph exposure replacing the keyword guess (removing false
positives and confirming true positives for EC2/SG/S3) and (2) blast-radius grounding
`excess_privilege` for IAM findings. The Critical floor activates once `graph_facts()` walks
the EC2→role bridge (see the split-analysis below — this is a Cypher change on our side, **not**
a Cartography capability gap).

**Split analysis — is the missing EC2→role bridge a Cartography limit? No (schema-confirmed,
2026-07-04).** Cartography's current AWS schema explicitly models the compute→role path:
`(EC2Instance)-[:INSTANCE_PROFILE]->(AWSInstanceProfile)-[:ASSOCIATED_WITH]->(AWSRole)` **and**
a direct `(EC2Instance)-[:STS_ASSUMEROLE_ALLOW]->(AWSRole)` (feature request lyft/cartography
issue #304 → PR #646, merged). `AWSInstanceProfile` is a first-class node type. Crucially there
is **no analysis-job JSON** for this mapping (the only EC2 analysis job is
`aws_ec2_asset_exposure.json`), so these edges are built during **normal sync** — they need
neither an opt-in analysis step nor the `permission_relationships` mapping. So the edge's absence
in the S2.1/S2.2 live graph is a **data/config artifact, not a capability gap** — most likely the
test account's EC2 instances simply had no instance profile attached, so there was nothing to
map. `permission_relationships` (opt-in, for fine-grained `CAN_ACCESS` edges) would *deepen*
blast-radius but is **not** required for this floor: walking EC2→instance-profile→role and reusing
the role's existing wildcard-statement `admin_like` proxy is enough.

**Pending live confirmation (targeted, one query when Neo4j is back):**
`MATCH (p:AWSInstanceProfile) RETURN count(p)` and
`MATCH (i:EC2Instance)-[:INSTANCE_PROFILE]->(:AWSInstanceProfile)-[:ASSOCIATED_WITH]->(:AWSRole) RETURN count(*)`.
count(profiles)>0 with 0 bridges ⇒ test EC2s had no profile attached (data); count(profiles)=0 ⇒
the IAM instance-profile sync module didn't run (config). Either way it is **not** a Cartography
capability limit. Follow-up once confirmed: extend `graph_facts()` to walk the bridge so an
exposed EC2 inherits its role's `blast_radius`, lighting up the toxic-combination floor per finding.

**Verification:** unit-tested offline (`graph_over_privileged`, `floor_priority` including the
toxic path and the not-lowered guarantee, `build_rationale` grounding + provenance, and
`graph_enrich` override + all degrade paths with a stubbed `graph_facts`); the real `collect`
path exercised with a synthetic OCSF fixture for graph-off (no regression), graph-on/no-password,
and graph-on/unreachable. **A live end-to-end run against a populated Cartography graph is still
pending** — it needs the Neo4j container + Cartography venv from S2.1/S2.2, which were not
present in this session's environment. S2.2's live Cypher (join 143 / exposure 9 / admin-like 19)
is unchanged by S2.3 except the `exposed=None`-for-unmodeled refinement (which only relabels
previously-`False` joined non-EC2/SG/S3 nodes).

### 12.11 EC2→role blast-radius bridge — lighting up the toxic floor per finding (2026-07-06)

The follow-up flagged in §12.10 is now implemented in `graph_facts()`. Previously the blast-radius
query keyed only on a finding's **own** ARN, so it produced a `blast_radius` only when the finding's
resource *was* an IAM principal (role/user). An EC2 instance finding — whose over-privilege lives on
the role it assumes, not on the instance — never got one, so `exposed ∧ over_privileged ∧ KEV` could
not co-occur on a single finding and the Critical toxic floor stayed dark.

`graph_facts()` now walks the schema-confirmed bridge:
- **3a** resolves each EC2 instance id → its attached role ARN(s) via
  `(:EC2Instance)-[:INSTANCE_PROFILE]->(:AWSInstanceProfile)-[:ASSOCIATED_WITH]->(:AWSRole)` **and**
  the direct `(:EC2Instance)-[:STS_ASSUMEROLE_ALLOW]->(:AWSRole)` edge.
- **3b** widens the blast-radius query's ARN set to the union of finding-owned principals **and**
  those discovered instance-roles, so both are scored in one pass.
- In the per-finding loop, an EC2 finding with no own-ARN blast inherits the aggregated worst-case
  blast of its role(s) (`admin_like` if **any** role is; max wildcard-statement counts — helper
  `_blast_from_rows`). A `via_instance_role` field records the source role ARN(s) so the signed
  evidence log stays honest that this privilege is the instance's *transitively*, not its own.

Consumers (`graph_over_privileged`, `floor_priority` toxic combination, `build_rationale` provenance)
were already wired in S2.3 and needed **no change** — they simply now see a `blast_radius` on exposed
EC2 findings.

**Verification:** offline test with a stubbed graph modelling both bridge shapes (8 scenarios, 25
checks, all pass): toxic EC2 (exposed + admin role via instance profile + KEV) → **Critical**;
multi-role worst-case → Critical; exposed EC2 with a non-privileged role → High not Critical; exposed
EC2 with no role → High not Critical; direct IAM-role finding still attaches its own blast with no
`via_instance_role` (regression); and `[graph]`-off / no-password / unreachable all degrade to the
keyword flag without crashing.

**Live confirmation (2026-07-06, real account 278059980943).** The environment was rebuilt from
scratch — Neo4j 5.26 container + a fresh Cartography AWS sync via the restored read-only role.
(Cartography ran in a `python:3.12` container: the host's new Python 3.14 has no wheel for `oci`'s
pinned `crc32c==2.7.1` and no compiler, so a host venv couldn't build it.) The §12.10 confirmation
queries resolved the open question: **`AWSInstanceProfile` count = 1 and the
EC2→instance-profile→role bridge count = 1** — the bridge is real; the earlier empty graph was the
account state (6 of 7 instances simply had no profile attached), not a Cartography gap. Running the
harness's own `graph_facts()`/`graph_enrich()` (HTTP Cypher, the real code path) against the live
graph confirmed **both graph legs on real data**: the bridged instance `i-0eb31fe7e6decd64e` inherits
its instance-profile role's blast radius (`wildcard_service_stmts=3`, `allow_stmt_count=54`,
`via_instance_role=[…BedrockAgentCore…]`) → `graph_over_privileged=True`; and all four public-IP
instances resolve `exposure_path.exposed=True`. No single instance in this account is *both* exposed
and over-privileged, so the toxic floor correctly stays at High on the real findings; feeding the
instance's **real** inherited over-privilege + **real** KEV and toggling exposure on flips
`floor_priority` `Low→Critical`, exercising the toxic combination end-to-end. The
instance-profile→role edge needed neither an opt-in analysis job nor `permission_relationships` — it
came from the normal sync, exactly as §12.10 predicted.

## 13. Stage 3 design annex — Trivy collector (image/package CVEs)

> **Status: design draft for stage 3 — sub-milestone S3.1 in progress.** This annex is the
> detailed expansion of the **first** of roadmap item **§8.3**'s three tracks (Trivy →
> DefectDojo → off-host signing). It is scoped to **Trivy only**; DefectDojo (system of
> record) and off-host signing (Sigstore keyless + Rekor / KMS) are separate later
> sub-milestones (S3.4 / S3.5) with their own annexes. Stage 3 stays **read-only and
> B2-preserving** — like Cartography and Prowler, Trivy is an *external tool run as a
> deterministic subprocess*; it adds a new *input source*, not agentic tools or mutation.

### 13.1 What Trivy buys — it fills the enrichment pipeline that has always been empty

The harness already ships a complete CVE intel pipeline — `enrich()` attaches CISA **KEV**
membership, FIRST **EPSS** score, and (opt-in) **NVD** CVSS to any CVE id a finding carries,
and the deterministic **priority floor** (§5, Layer 3) escalates KEV / high-EPSS findings so a
compromised LLM cannot talk them down. But Prowler is a **CSPM** scanner: its findings are
misconfigurations, and they almost never reference a CVE. Every production run to date logs

```
[enrich] no CVE ids referenced by findings; skipping intel feeds
         (expected for CSPM-only v1 — CVE coverage grows with Trivy in stage 3)
```

Trivy is a **vulnerability (SCA/package) scanner**: every finding it emits *is* a CVE, with a
package, an installed vs fixed version, and a severity. Adding Trivy as a second collector
therefore lights up the KEV/EPSS/NVD path **for the first time on real data** — no new
enrichment code, no new floor logic. The CVEs flow straight into the existing `enrich()` →
sort → floor → graph → digest → evidence → dedup chain. This is why Trivy is the highest-value,
lowest-risk of Stage 3's three tracks: it is almost entirely *reuse*.

### 13.2 Scan targets, and the account reality (measured)

Trivy scans an **artifact**, most usefully a container image (`trivy image <ref>`), but also a
filesystem/rootfs or an SBOM. Three target shapes are relevant here:

1. **Explicit image refs** (`[trivy].targets = ["ghcr.io/org/app:tag", …]`) — Trivy pulls and
   scans them with **no AWS involvement at all**. This is the default, portable path and the
   one that keeps the read-only guarantee completely untouched (§13.3).
2. **ECR auto-discovery** — enumerate the account's ECR repositories, resolve the latest (or
   tagged) image per repo, and scan each. This is the AWS-native path named in §8.3, and the
   only one that touches IAM (§13.3).
3. **Agentless EC2 snapshot scan** (`trivy` on a mounted EBS snapshot) — the heavier second
   Trivy mode §8.3 foreshadows. **Out of scope for S3.1**; noted for a later sub-milestone.

**Measured account state (2026-07-10, account 278059980943, read-only role):**
`ecr describe-repositories` returns **0 repositories**. So ECR auto-discovery has nothing to
scan on this account — exactly the `via_instance_role` situation from Stage 2: an *account-state*
gap, not a wiring gap. The design consequence is that **live verification (S3.2) must not depend
on ECR**. It scans an explicit, pinned, publicly-known-vulnerable image ref (target shape 1) to
produce **real** CVEs and exercise the KEV/EPSS→floor→digest→evidence path end-to-end, and proves
the ECR path (shape 2) separately against a captured-output fixture — the same "prove the wiring
offline, don't let account state decide correctness" discipline Stage 2 established.

### 13.3 IAM — the read-only surface, and the one place it would widen

The default path (explicit image refs) needs **no AWS permissions** — Trivy just pulls from a
registry the operator already has creds for. The read-only guarantee (Layer 1, §3.1) is
untouched. This matters: the safety story does not regress for the common case.

**ECR auto-discovery** is the one place the surface could widen, and there is a genuine fork:

- **(A) Trivy pulls & scans the image itself.** Trivy needs the ECR **data-plane pull** actions
  `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer` (plus the
  `ecr:Describe*` the role already has). `SecurityAudit` / `ViewOnlyAccess` grant the *describe*
  actions but **not** the layer-pull actions — so this path **adds three actions** to
  `prowler-additions`. They are still read-only (no mutation), but they let the role **read image
  contents**, a real (if modest) widening of what "read-only" reads. Trivy is the portable,
  registry-agnostic scanner §8.3 names → richest coverage.
- **(B) Consume ECR-native scan findings.** If the repo has Amazon Inspector / basic ECR
  scanning enabled, `ecr:DescribeImageScanFindings` (covered by `SecurityAudit`) returns CVEs
  **without pulling the image** — zero IAM change, zero image-content read. But it is not Trivy
  (coverage is ECR's scanner, only works where scanning is enabled) and it is a different
  normalizer.

**Recommendation (for S3.1):** ship **(A) Trivy** as the scanner because it is what §8.3 commits
to and it is portable, but keep **ECR auto-discovery OFF by default** and gate it behind an
explicit `[trivy].ecr_discovery = true`. The default distribution therefore adds **no IAM and no
image-content read** — a deployer who opts into ECR discovery consciously accepts the three
extra pull actions, which the README documents as the single point where the read-only surface
widens. (B) is recorded as the zero-IAM alternative for Inspector-enabled shops; implementing it
is deferred. This keeps the invariant intact for everyone who doesn't opt in.

### 13.4 Invocation & schema mapping (mirrors the Prowler collector exactly)

Trivy is invoked exactly like Prowler (§3, `run_prowler`): a **pinned CLI subprocess** whose
`--version` must start with a configured prefix (supply-chain hygiene — a surprise upgrade can
change output shape), run in an isolated install off the volatile scratchpad, emitting JSON to a
temp dir that `collect.py` reads. New code is `run_trivy()` + `normalize_trivy()`, structurally
twins of `run_prowler()` + `normalize()`.

Trivy `image --format json` yields `Results[].Vulnerabilities[]`. Mapping one vulnerability to
the **existing common finding schema** (§ `normalize`):

| common schema field | Trivy source |
|---|---|
| `source` | `"trivy"` (Prowler findings are `"prowler"`) |
| `id` (dedup key) | `trivy\|<configured-image-ref>\|<Target>\|<PkgName>\|<VulnerabilityID>` — keyed on the **configured ref** (e.g. `app:latest`), **not** the image digest, so the same package+CVE maps to one id across `:latest` rebuilds (idempotent ledger, CLAUDE.md #5). The digest (`Metadata.ImageID`) is logged for provenance but excluded from the key — see the dedup-stability note in §13.7. Trade-off: a CVE fixed then re-introduced under the same ref is not re-notified daily (mirrors Prowler's resolved→recurred constraint), but the weekly full re-digest (S1.7) re-surfaces still-open findings. |
| `cve_ids` | `[VulnerabilityID]` when it matches `CVE_RE` (Trivy also emits non-CVE advisory ids — GHSA/DLA; keep them in `title`, only CVE-shaped ids go in `cve_ids` so they reach `enrich()`) |
| `severity` | `Severity` lowercased → existing `VALID_SEVERITIES` (`critical/high/medium/low`) |
| `title` | `"<PkgName> <VulnerabilityID> — <Title>"` |
| `resource` / `resource_type` / `resource_name` | image ref / `"container_image"` / `ArtifactName` |
| `description` / `risk` / `remediation` | `Description` / `PrimaryURL` refs / `"upgrade <PkgName> <InstalledVersion> → <FixedVersion>"` — all **untrusted DATA**, fenced by the orchestrator, never interpreted |
| `internet_exposed`, `graph` | left at schema defaults; the image itself has no network path — exposure/blast belong to the *asset running the image*, a stage-2 join deferred here |

Because the schema is shared, everything downstream — `enrich()`, the KEV/EPSS/exposure sort key,
the priority floor, digest folding, evidence hash-chain, the post-then-mark ledger — consumes
Trivy findings **with no change**. `cmd_collect` merges Trivy items into the Prowler item list
**before** `enrich()` so the CVE feeds fire over the union.

### 13.5 B2 preservation (unchanged invariant)

Trivy is an **external deterministic subprocess**, identical in trust posture to Prowler and
Cartography: the orchestrator runs it, parses its JSON with defensive `.get` chains, and passes
the resulting strings to the tool-less LLM as fenced DATA. Untrusted image/package text (a
vulnerability `Description`, a crafted image label) can at most corrupt a summary string — it
never becomes a command, never touches the host, the ledger, or other channels. The B2 boundary
(§3.1) is exactly where it was; Stage 3's Trivy track does **not** move it (that is Stage 4).

### 13.6 Config & distribution defaults

A new `[trivy]` section, **`enabled = false`** in the tracked config (same discipline as
`[graph]`): v1/Stage-1 and Stage-2 users are unaffected, and a deployment turns it on with the
non-secret env toggle `VULNTRIAGE_TRIVY_ENABLED=true` (mirrors `VULNTRIAGE_GRAPH_ENABLED`) so an
upstream `git pull` never reverts it. Keys: `enabled`, `version` (pin prefix), `targets` (explicit
image refs), `ecr_discovery` (default false — the IAM-widening opt-in, §13.3), `severities`
(pre-filter). A `--trivy-output <path>` dry-run flag mirrors `--prowler-output` for offline
fixture runs (no pull, no AWS).

### 13.7 Verification strategy (account-state-independent)

Mirrors S1.5 / S2.1's discipline — prove the wiring on real data where possible, offline where
account state blocks it:

1. **Real CVE path, live (the headline):** `trivy image <pinned-vulnerable-image>` → real CVEs →
   full `run.py` on a **temporary ledger** → confirm **KEV/EPSS enrich fires non-empty for the
   first time**, the floor escalates a KEV CVE, the digest posts intact (one finding per message,
   mid-block-split zero, verified by **reading the real Discord channel**), evidence hash-chains,
   dedup is idempotent → restore the real ledger/evidence to a byte-identical sha256 (the
   S1.8/S2.5 method — leave a Discord trace, never dirty the live ledger).
2. **ECR path, offline:** captured `trivy` JSON fixture through `--trivy-output` proves
   `normalize_trivy()` + merge + dedup independent of the account's 0 ECR repos.

**Live confirmation (2026-07-10).** Trivy 0.72.0 (run containerized via `aquasec/trivy`,
the same "heavy external tool, isolated" pattern as Cartography's `python:3.12`) scanned
`ghcr.io/christophetd/log4shell-vulnerable-app` through the real `collect.py` → `run.py`
path on a throwaway workspace copy (live ledger/evidence untouched — the S1.8/S2.5
method). Results: 18 critical findings, **13 CVEs enriched, EPSS scored 13/13, and 5
KEV-listed findings** (CVE-2021-44228 Log4Shell EPSS 0.99999, CVE-2021-45046,
CVE-2025-24813 Tomcat, CVE-2022-22965 Spring4Shell ×2). The **KEV/EPSS enrichment fired
non-empty for the first time on real data** (Prowler-only runs always logged "no CVE
ids"), the deterministic floor pinned all five KEV findings to Critical, and the digest
posted **8 messages intact** (header + 6 detail + footer, mid-block-split zero, verified
by reading the real channel) each carrying the `KEV: yes` badge. Live `seen-count`
stayed 166 and `evidence.py verify` stayed `ok=True checked=166`. One provenance bug
surfaced and was fixed: `run.py` `format_post` hard-coded a `Prowler:` source label, so
Trivy CVEs mislabelled their collector — now `Trivy:` vs `Prowler:` by `item["source"]`.
An earlier offline dry-run (synthetic Log4Shell fixture via `--trivy-output`) had already
confirmed KEV=`true` / EPSS=0.99999 enrichment, package-scoped dedup ids, the
severity pre-filter, and that an injected instruction string in a vulnerability
`Description` stays inert DATA (B2).

**Review hardening (2026-07-10).** A multi-angle code review of the Trivy diff surfaced
three contract defects, all fixed: (1) a Trivy **setup** failure (binary missing /
version-pin mismatch) raised out of `collect_trivy` and sank the *entire* run, discarding
Prowler findings — now caught so Trivy **degrades to Prowler-only** like a down feed
(the one-time version/binary error, not just per-image pull failures, is inside the
guard); (2) `run.py` `format_post` printed `EPSS: 0.00` for a CVE the EPSS feed never
scored (the `finding_epss` 0.0 default read as a real score) — now `n/a` unless a score
exists, which matters because every Trivy finding is CVE-bearing; (3) a `--prowler-output`
offline replay ("no AWS calls") still triggered **live** Trivy image pulls — now a Prowler
dry run only includes Trivy findings from a captured `--trivy-output`, never a live scan.
Deferred to follow-ups (logged, not fixed here): dedup-id stability across `:latest`
rebuilds, `[trivy].severities` falling back to `[prowler].severities` when unset,
`ecr_discovery` failing loud instead of silently scanning nothing, and a shared
`make_finding()` schema constructor.

**Severities inheritance (2026-07-11, fixed).** The second follow-up above is now
resolved. `collect_trivy` read `[trivy].severities` in isolation, so an unset/empty key
meant "keep all" — asymmetric with the Prowler path, where `[prowler].severities`
governs. Fix: when `[trivy].severities` is unset/empty, inherit `[prowler].severities`
(`sev = tcfg.get("severities") or cfg["prowler"].get("severities", [])`); an explicit
non-empty `[trivy].severities` still wins, and if both are empty the existing `if wanted`
guard keeps everything. Verified offline (6/6): `[trivy].severities` unset +
`[prowler].severities=["critical"]` drops a HIGH finding; an explicit `[trivy]` list
overrides Prowler; both-empty keeps all.

**Dedup-id stability (2026-07-11, fixed).** The first follow-up above is now resolved.
`normalize_trivy` keyed the finding id on `image_digest or image_ref`, where
`image_digest = Metadata.ImageID`. `ImageID` is the local image config hash, which
changes on every `:latest` rebuild — so an unchanged CVE in an unchanged package
re-minted its id and re-posted on each rebuild, violating the idempotent ledger
(CLAUDE.md #5). Fix: key on the **configured image ref only** (`trivy|<ref>|<Target>|
<PkgName>|<VulnerabilityID>`); the digest is computed once per report and logged for
provenance (`[trivy] scanned <ref> (digest <digest>)`) but never enters the key. The
`image_digest` parameter was dropped from `normalize_trivy`. Verified offline: the same
synthetic CVE scanned under two different `Metadata.ImageID` values (same ref) yields
**0 new findings on the second run** (idempotent), while changing the *ref* still mints a
new id. Accepted trade-off is documented in the §13.4 schema-table row above.

**ecr_discovery fail-loud (2026-07-11, fixed).** The third follow-up above is now
resolved. `ecr_discovery=true` is an unimplemented opt-in (§13.3: S3.1 only scans explicit
`[trivy].targets`, ECR repos are never enumerated). The collector merely *logged* a note
and proceeded, so a deployer who flipped it — believing their registry was being covered —
silently scanned nothing, letting an unscanned ECR masquerade as "0 findings = clean."
Fix: `collect_trivy` now raises a `ValueError` when `ecr_discovery=true` on a live scan
(skipped for a `--trivy-output` dry run, which reads a captured report and never
enumerates). This is an operator **config** mistake, not a transient setup failure, so it
is raised *before* the degrade-to-Prowler guard and — being a `ValueError`, which that
guard's `(RuntimeError, OSError)` does not catch — propagates up to abort the run;
`main()` turns it into a clean `[error] …` line (non-zero exit → `run.py` stops the run).
The `config.toml` comment now states the flag fails loud. Verified offline (5/5): live
scan raises with the right message; `--trivy-output` dry run does not; `ecr_discovery=false`
is unaffected; and `cmd_collect` propagates the error rather than swallowing it into the
Prowler-only degrade path. Remaining Trivy follow-ups: shared `make_finding()` schema
constructor (⑨) and source→label/link map (⑩), plus robustness (⑦⑧).

**Source→label/link map (2026-07-11, fixed).** The ⑩ follow-up above is now resolved.
`run.py`'s `format_post` hard-coded provenance display as a ternary
(`label = "Trivy" if source=="trivy" else "Prowler"`) plus an inline NVD link string —
so adding a collector (e.g. DefectDojo) meant scattered edits, and the `else` branch
silently mislabelled any non-Trivy source as "Prowler." Fix: a `SOURCES = {source ->
(label, link_builder)}` map (same shape as the news harness's attribution map), a
`_nvd_link(item)` builder (CVE→NVD detail, `None` when the finding carries no CVE), and a
`source_display(item)` helper that resolves both from the finding's TRUSTED `source`
field. `format_post` now just calls `source_display` and appends the link when present.
An unknown/absent source falls back to `_DEFAULT_SOURCE` (bare `source` label + CVE→NVD
link) so a new collector still posts sensibly before it gets its own row — safe because
both real collectors set `source` explicitly (`collect.py` "trivy"/"prowler"), so the old
default-to-Prowler was only a phantom fallback. Output is byte-identical to the ternary
for every real finding. Verified offline (5/5): Trivy CVE, Prowler ±CVE, unknown source
w/CVE (generic label + NVD link), and absent source w/o CVE (generic label, no link).
Remaining Trivy follow-ups: shared `make_finding()` schema constructor (⑨) and
robustness (⑦⑧, list-safe / empty-file guards).

### 13.8 Sub-milestones (this PR = S3.0–S3.3)

- **S3.0 Design annex** — this §13.
- **S3.1 Trivy collector** — `run_trivy()` + `normalize_trivy()` + `[trivy]` config + `--trivy-output` dry-run + `cmd_collect` merge; env toggle `VULNTRIAGE_TRIVY_ENABLED`.
- **S3.2 Live verification** — pinned vulnerable image → real KEV/EPSS first-light → temp-ledger e2e → byte-identical restore.
- **S3.3 Config/docs distribution** — README "Appendix — enabling Stage 3 Trivy" (incl. the ECR-discovery IAM note), SKILL "Stage 3" section, `.env.example`, DESIGN §8 roadmap sync (also correct the stale S2.4/S2.5 markers).
- **S3.4 DefectDojo** (system of record) — *deferred, separate PR.*
- **S3.5 Off-host signing** (Sigstore keyless + Rekor / KMS) — *deferred, separate PR; delivers the non-repudiation the v1 local-PEM path deliberately does not (§3.5).*
