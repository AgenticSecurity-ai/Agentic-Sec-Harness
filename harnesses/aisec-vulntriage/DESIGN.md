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
chained (SHA-256) and signed (ECDSA P-256). This is the auditable "who decided what,
on what basis" trail. v1 self-implements the hash-chain + signature; posting to a
public transparency log (Sigstore Rekor) is a later option, not required for v1.

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

1. **v1 (this doc)** — Prowler + feeds + AI triage + Discord + signed evidence log.
   Read-only, B2-preserving, tier-1 tools only.
2. **+ Graph context** — add Cartography(+Neo4j); triage rationale gains exposure
   paths / blast radius (the toxic-combination value). Still read-only, still B2.
3. **+ More collectors** — Trivy (ECR image CVEs; then agentless EC2 snapshot scan),
   DefectDojo as system of record, Sigstore Rekor for public transparency.
4. **Phase 4–6 (execution)** — *this* is where the architecture escalates beyond B2:
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
- **Evidence signing key management.** Where the ECDSA key lives / rotates for the
  self-implemented VAT before (if ever) moving to Sigstore keyless + Rekor.
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
