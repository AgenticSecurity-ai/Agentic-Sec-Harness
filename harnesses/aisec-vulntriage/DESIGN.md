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
  path; **off-host signing is the roadmap stage-3 target** (§8, annex §15). Decision (§15.2):
  **KMS-delegated signing ships first** for this deployment class (unattended host, already in
  AWS, and — crucially — verification stays offline/AWS-independent via the exported public key,
  §15.3); **Sigstore keyless + Rekor** is the higher-assurance, cloud-neutral option deferred to
  S3.5b behind its OIDC-identity prerequisite.

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
   - ✅ **S2.6 True reachability** — `graph_facts()` step 3c deepens `blast_radius` from the
     wildcard-privilege proxy into true reachability using Cartography's opt-in
     `permission_relationships` edges (`CAN_PASS_ROLE`/`CAN_READ`/`GET_SECRET`/…);
     `graph_over_privileged` now also fires on an `iam:PassRole` escalation path with no
     wildcard statement. Self-activating on edge presence (no new config), degrades to the
     proxy when absent. Offline 19/19 + live 2-leg on the real graph. Detailed in **§12.12**.
   - ✅ **S2.7 Breadth / secret-read over-privilege knobs** — opt-in, default-off `[triage]`
     config (`blast_breadth_over_priv` / `secret_read_over_priv`) promoting the `reachable`
     breadth and `GET_SECRET` signals to over-privilege inputs; measured to over-fire if blanket
     (secret-read hits 33% of unflagged principals on the real account), so shipped off and
     deployer-tuned (strict fail-safe config typing; `graph-check` reports would-fire counts).
     Offline 35/35 + live 2-leg. Detailed in **§12.12.1**.
3. ✅ **+ More collectors & audit-grade evidence** — three independent tracks, all shipped:
   **Trivy** (image/package CVEs), **DefectDojo** (system of record), and **off-host signing**
   (KMS-delegated; Sigstore keyless + Rekor deferred to S3.5b) to move evidence signing off the host — the
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
   - ✅ **S3.4 DefectDojo** — import findings from DefectDojo (system of record) as a
     **read-only** collector — one integration, N scanners. Design annex **§14** done
     (S3.4.0). **S3.4.1 read collector ✅** (`defectdojo_get` auth+pagination,
     `normalize_defectdojo` + triage-state gate, `collect_defectdojo`, `[defectdojo]`
     config default off + `VULNTRIAGE_DEFECTDOJO_ENABLED` toggle + `--defectdojo-output`
     dry-run, `SOURCES` row; offline captured-envelope gate PASS — KEV/EPSS fires,
     human-triaged findings dropped, dedup idempotent, three-collector merge clean).
     **S3.4.3 docs ✅** (README "Appendix — enabling Stage 3 DefectDojo" incl. read-only-token
     note + write-back deferral, SKILL "Stage 3" DefectDojo section, `.env.example`, this §8
     sync). **S3.4.2 live verification ✅** (throwaway DefectDojo `docker compose`; real
     `/api/v2/findings/` envelope confirmed — CVEs live in `vulnerability_ids[]`, legacy `cve`
     read-only; live collect imported 2 CVE findings, triaged 4 excluded server-side, KEV/EPSS
     re-derived; full `run.py` e2e floored both to Critical + posted intact to the real Discord
     channel with the `DefectDojo:` label; 403 fail-fast / unreachable + missing-token loud
     degrade all live-exercised; live ledger/evidence byte-identical sha256 — §14.8). The
     *write-back* direction §8.3 first named ("push signed verdicts") is split off as a deferred
     opt-in (S3.4b, §14.2) — it would be the first write outside Discord/ledger and is Stage-4-adjacent.
   - ✅ **S3.5 Off-host signing** — moves evidence signing off the host to deliver the
     non-repudiation the v1 local-PEM path does not (§3.5, §15). **S3.5.0 design annex ✅**
     (§15 — analyzes KMS-delegated vs Sigstore keyless+Rekor; **decision: KMS-delegated
     ships first** for this deployment class — unattended cron, already in AWS, verification
     stays offline/AWS-independent, stdlib-only via the `aws kms sign` CLI; a fourth
     `_load_signer()` tier, default off, chain unchanged). **S3.5.1 KMS signer ✅**
     (PR #40 — fourth tier, fail-closed, offline gate 11/11). **S3.5.2 live ✅** (§15.7-2 —
     real throwaway KMS key + scoped signer role signed 3 entries; exported pubkey verified
     them offline AWS-independently, tamper flip → ECDSA mismatch, CloudTrail recorded 3
     `Sign` events under the *signer* role, live ledger byte-identical, key/role torn down).
     **S3.5.3 docs ✅** (README "Appendix — enabling Stage 3 off-host signing": KMS key +
     scoped signer-role provisioning, non-secret key-id/profile env + cron `--command-env`
     injection, public-key export for offline verify; SKILL "Stage 3 — off-host signing"
     section; `.env.example` signing block — mirrors Trivy S3.3 / DefectDojo S3.4.3). **Stage 3
     complete — all three tracks shipped.** **Sigstore keyless + Rekor** = deferred
     higher-assurance, cloud-neutral option (S3.5b) behind its OIDC-identity prerequisite.
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
  not hidden. True non-repudiation (off-host signing authority) is the roadmap stage-3 target
  (§8, annex §15): **KMS-delegated signing ships first** (§15.2 — best fit for this deployment
  class; verification stays offline/AWS-independent, §15.3), with **Sigstore keyless + Rekor**
  the higher-assurance, cloud-neutral option deferred to S3.5b behind its OIDC-identity prerequisite.
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
honest v1 signal; record the depth ceiling rather than overclaim a path. **(Both resolved:
the instance-profile edge in §12.11, the permission-relationships depth in §12.12.)**

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

### 12.12 True reachability — deepening blast-radius past the wildcard proxy (2026-07-13)

The follow-up flagged in §12.9 (and deferred in §12.10 as "not required for the toxic floor") is now
implemented. Until here, `blast_radius` was a **wildcard-privilege proxy**: it counted `*` / `service:*`
Allow statements on a principal as a stand-in for over-privilege (§12.8). That proxy is blind to a whole
class of over-privilege — a principal with **no** wildcard statement that nonetheless holds a concrete,
dangerous permission on many resources. Cartography's opt-in `permission_relationships` module fills
exactly this gap: fed a mapping file (`--permission-relationships-file`), it evaluates IAM policies and
writes **typed** edges from a principal to the concrete resources it can reach.

**What the real edges look like (measured before coding — S2.1's "look at the data first" rule).** The
default mapping produces `(:AWSRole|:AWSUser)-[:CAN_*|:GET_SECRET]->(resource)`, NOT a single generic
`CAN_ACCESS`: `CAN_READ` / `CAN_WRITE` → `S3Bucket`, `GET_SECRET` → `SecretsManagerSecret`,
`CAN_PASS_ROLE` → `AWSRole`, `CAN_EXEC` → `CloudFormationStack` (plus `CAN_QUERY`/`CAN_ADMINISTER` for
DynamoDB/RDS/Redshift and `CAN_EXECUTE_COMMAND` for ECS where those resources exist). A default sync
writes **none** of these; on account 278059980943 the live graph had zero permission edges until the
opt-in sync was run — confirming §12.9. **No extra IAM** is needed — the edges are computed from
already-synced policy data (validating the §12.9 note).

**Implementation** (`graph_facts()` step **3c**, `collect.py`):
- For the same principal ARN set as the 3b proxy, two cheap aggregations: per-capability distinct-target
  counts (`by_rel`, e.g. `{CAN_PASS_ROLE: 38}`) and a **de-duplicated** resource `total` (a bucket
  reachable by both `CAN_READ` and `CAN_WRITE` counts once — `full_access` has 13+13 by_rel but total 85,
  not double-counted).
- The reach fact is attached onto the 3b rows so `_blast_from_rows` folds it into a `reachable` block
  **alongside** the proxy — including inheritance across the §12.11 EC2→role bridge (an exposed instance
  inherits its role's reachability, worst-case union over multiple roles).
- `graph_over_privileged()` gains a second sufficient signal: **`iam:PassRole` reachability**
  (`reachable.can_pass_role`) is a documented privilege-escalation primitive, so a principal that can pass
  roles is over-privileged **even with no wildcard statement**. The wildcard proxy remains the always-on
  v1 signal; reachability only strengthens it.

**Self-activating, zero new config, zero v1 impact.** Reachability keys entirely on edge *presence*: no
`--permission-relationships-file` in the operator's sync ⇒ no edges ⇒ nothing attached ⇒ the wildcard
proxy stands exactly as before. There is deliberately **no** `[graph]` flag for it — like the EC2 bridge,
it lights up when the data supports it and degrades silently when it doesn't. (Consequence: an operator
who wants reachability must add the mapping flag to their **recurring** Cartography sync; a plain re-sync
removes the edges and the harness reverts to the proxy — graceful, never wrong.) `can_read_secret` and the
`total`/`by_rel` breadth are recorded in the signed evidence and shown to the LLM, but did **not** by
themselves raise the floor at S2.6 — only the crisp `can_pass_role` escalation path did. The breadth
threshold and secret-read signals were the "future tuning knob" flagged here; **S2.7 (§12.12.1) adds them
as opt-in, default-off `[triage]` config**, after measuring that a blanket version over-fires.

**Why `can_pass_role` and not "any reachability" (measured, non-noisy).** Of 71 role/user principals in
the account, folding `can_pass_role` into over-privilege newly flags **exactly 2** — the
`BedrockAPIKey-u7ba`/`-msou` users, each able to pass **38** roles with **no** wildcard statement (the
proxy scored them clean). The other 54 non-wildcard principals have no pass-role edge and are untouched;
the 12 wildcard principals that could also pass roles were already flagged. So the deepening catches real
privilege-escalation paths without over-firing.

**Verification.** Offline synthetic-graph test (19 checks, all pass): a no-wildcard `CAN_PASS_ROLE`
principal → `reachable.can_pass_role=True` → over-privileged (**the gap closed**); a read-only-breadth
(`CAN_READ` only) principal → reachability recorded but **not** over-privileged; a wildcard principal →
proxy fires with `reachable` **absent** (regression); a principal with no edges → byte-identical to
pre-change (`reachable` absent, over-priv False); an exposed EC2 inheriting a pass-role role via the
bridge → `exposed ∧ reachability-over-priv ∧ KEV` → **Critical**, while the same finding *without* the
permission edges floors only to High. **Live 2-leg confirmation (2026-07-13, real account 278059980943),
via the harness's own `graph_facts()` HTTP Cypher over the real graph after an opt-in sync:** *leg 1* —
`full_access` resolves `reachable.total=85` with real per-capability counts, `BedrockAPIKey-u7ba` resolves
`total=38` (`CAN_PASS_ROLE` only); *leg 2* — `BedrockAPIKey-u7ba` has `admin_like=False` (no wildcard) yet
`graph_over_privileged=True` **purely via reachability** (the wildcard proxy missed it), `full_access`
still fires via the proxy (regression), and the read-only role carries no `reachable` block and is **not**
over-flagged. The live ledger/evidence were untouched (read-only queries only).

### 12.12.1 S2.7 — breadth / secret-read as opt-in over-privilege signals (2026-07-14)

§12.12 deliberately fired the floor on `can_pass_role` alone and left the `reachable` breadth
(`total`/`by_rel`) and `can_read_secret` as evidence-only, calling a breadth threshold a "future tuning
knob." S2.7 takes that knob — but as **config-gated, default-off** signals, because measurement shows a
blanket version over-fires.

**Two new `[triage]` knobs (both ship OFF):**
- `blast_breadth_over_priv = N` (int, `0`/unset = disabled): a principal reaching **≥ N** distinct
  resources (`blast_radius.reachable.total`) is over-privileged.
- `secret_read_over_priv = false` (bool): a `GET_SECRET` reachability edge (`reachable.can_read_secret`)
  makes a principal over-privileged.

`graph_over_privileged(item, triage_cfg)` gains these two checks **after** the always-on wildcard proxy
and `can_pass_role` (which are unaffected). All three consumers — the LLM `over_privileged` hint
(`build_prompt`), the `excess_privilege` evidence field (`build_rationale`), and the toxic-combination
floor (`floor_priority`) — thread the same `triage_cfg` so they share one over-privilege definition.

**Strict, fail-safe config typing.** Both knobs are parsed strictly rather than coerced, because these are
*safety* controls whose worst failure is a silent enable. `blast_breadth_over_priv` accepts only a plain
positive `int` (`_breadth_over_priv_threshold`) — a bool or string is a config type error and disables the
knob, because `int(True)==1` would otherwise flag every reachable principal and `int("1")` would silently
accept a string. `secret_read_over_priv` requires a real boolean `true` (`_secret_read_over_priv`) — a
truthy string like `"false"` (a common TOML typo) must not enable this noisy signal. A wrong-typed value is
warned about once per run (`warn_bad_triage_knobs`, called in `main()`) and then treated as disabled — fail
safe, never a silent over-flag. The `graph-check` diagnostic reports, alongside the always-on counts, how
many principals the breadth (at the configured threshold) and secret-read signals *would* flag, plus the
max reach, so an operator can size the threshold before enabling.

**Why config-gated, not edge-presence-gated like §12.12.** `can_pass_role` is a crisp, account-independent
escalation primitive, so it lit up on edge presence alone. Breadth and secret-read are **deployment-relative
judgments** — "how many resources is too many" and "is reading a secret abnormal" depend on the account —
so the right shape is a knob the deployer tunes after measuring their own graph, shipped off so the
distribution is byte-identical to pre-S2.7 (`triage_cfg` absent / keys unset ⇒ no new firings).

**Measured firing distribution (real account 278059980943, 71 role/user principals, the S2.6 population).**
Wildcard proxy flags 15; `can_pass_role` adds 2 (the `BedrockAPIKey` users); 17 flagged, 54 unflagged.
- **breadth: 0 new at any N.** The *max* `reachable.total` among the 54 unflagged principals is **1**.
  The genuinely broad principals are already caught — `full_access` (total 85) by the wildcard proxy, the
  `BedrockAPIKey` users (total 38–39) by `can_pass_role`. So on this account breadth adds nothing beyond
  the always-on signals; it is a knob for accounts with broad **non-wildcard** roles, which this one lacks.
- **secret-read: 18 of 54 (33%) new firings** — every `AmazonBedrockAgentCoreSDKRuntime-*` service role,
  each reading exactly **one** secret. This is textbook over-fire: legitimate service roles that read a
  single secret would all be relabelled over-privileged. This measurement is *why* `secret_read_over_priv`
  ships off with a "tune, don't guess" warning in `config.toml`, rather than being always-on like
  `can_pass_role`.

**Verification.** Offline synthetic-graph gate — **35 checks, all pass**: regression (wildcard/`can_pass_role`
fire regardless of cfg; `reachable`-only with knobs off ⇒ byte-identical `False`; no-graph ⇒ `None`);
breadth boundary (`total=50` fires at N≤50, not at N=51; N=0/negative disabled); **strict typing**
(`"50"`/`True`/`"abc"`/`None` all fail safe to disabled — the string and bool cases are the ones the old
`int()` coercion would have wrongly accepted; `secret_read_over_priv="false"`/`"true"`/`1` all disabled,
only bool `True` enables; `warn_bad_triage_knobs` never raises); secret-read (fires only with the flag on
and a real `GET_SECRET`); `can_pass_role` precedence;
`floor_priority` integration (exposed ∧ KEV ∧ breadth/secret-over-priv ⇒ **Critical**; the same finding
with the knob off floors only to **High**; not-exposed ⇒ no Critical); `build_rationale.excess_privilege`
tracks the knob. **Live 2-leg confirmation (2026-07-14, real account 278059980943), through the harness's
own `graph_facts()` HTTP Cypher over the real graph (read-only, ledger/evidence untouched):** *leg 1* — an
`AgentCoreSDKRuntime` role with **no** wildcard, **no** pass-role, only a real `GET_SECRET` edge
(`reachable.total=1`, `can_read_secret=True`) resolves `graph_over_privileged=True` when `secret_read_over_priv`
(or `blast_breadth_over_priv=1`) is set — the new signals materialize on real edges; *leg 2* — with the
knobs off (distribution default) the same role is `False` (byte-identical to pre-S2.7, the 33%-over-fire
suppressed), while the wildcard `AdministratorAccess` role (proxy) and the `BedrockAPIKey` user
(`can_pass_role`) still fire, and `aisec-vulntriage-readonly` carries no `reachable` block and is not
over-flagged.

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

**Shared `make_finding()` schema constructor (2026-07-11, fixed).** The ⑨ follow-up
above is now resolved. `normalize_trivy` and Prowler's `normalize` each hand-built the
same 20-key common finding schema as a separate dict literal — twin dicts that both had
to be edited in lockstep whenever the schema grew (a new intel/graph slot, a renamed
field). Fix: a keyword-only `make_finding(...)` constructor centralizes the field set
and the always-`{}` intel/graph slots (`kev`/`epss`/`nvd`/`graph`), plus the
whitespace-collapse (`" ".join(str(x).split())`) applied to the untrusted free-text
fields (`title`/`description`/`risk`/`remediation`). Each normalizer keeps ALL of its
source-specific extraction (id computation, CVE regex, exposure heuristic) and just
passes the results — so the deliberate independence of the two collectors' *logic*
(their twin was intentional, not accidental duplication) is preserved; only the shared
*shape* is unified. Verified byte-identical to the pre-change `HEAD` by loading both
module versions and diffing `normalize`/`normalize_trivy` output over 8 Trivy + 2 Prowler
fixtures (whitespace-heavy text, GHSA-only ids, UNKNOWN severity, missing fields, digest
vs `:latest` refs) — equal dicts AND equal key order. Remaining Trivy follow-ups:
robustness (⑦⑧, list-safe / empty-file guards).

**Robustness — list-safe / empty-file guards (2026-07-11, fixed).** The ⑦⑧ follow-ups
above are now resolved — the last of the Trivy review items. (⑧) `_read_trivy_json`
did a bare `json.load`, so an empty/truncated report file (Trivy killed mid-write, a
hand-edited capture) or invalid JSON raised `json.JSONDecodeError` — a **`ValueError`**.
On the captured `--trivy-output` path that error is not caught by `collect_trivy`'s
`except (RuntimeError, OSError)` degrade guard (which deliberately excludes `ValueError`,
reserved for the ⑥ `ecr_discovery` abort), so a bad report file aborted the *entire* run
with a traceback instead of degrading. Fix: `_read_trivy_json` now reads the file, raises
`RuntimeError` on empty/whitespace-only content, and re-raises `JSONDecodeError` as
`RuntimeError` — so both the live per-image loop (broad `except Exception` → skip that
image) and the captured path (`collect_trivy`'s guard → degrade to Prowler-only) handle
it cleanly with a clear message. (⑦) `_read_trivy_json` can return a **list** (a capture
holding several reports), but only the captured path unwrapped it; the live-scan path
yielded `run_trivy_image(...)` raw, so a list-shaped report hit `rep.get("Metadata")` →
`AttributeError`, which escapes the degrade guard and sinks the run. Fix: a shared
`_coerce_reports(rep)` helper coerces dict-or-list into a list of **dict** reports
(logging and dropping non-object junk), used by BOTH paths; plus `isinstance(..., dict)`
guards on `Results[]` / `Vulnerabilities[]` elements so a shape drift degrades a field
rather than crashing — the same "defensive `.get` chains" philosophy `normalize_trivy`
already documents. Distribution default stays off, so live is untouched. Verified offline
(15/15): empty/whitespace/malformed files raise `RuntimeError` and degrade `collect_trivy`
to `[]`; a normal single-dict capture still yields the finding byte-identically
(regression); a list capture yields both findings; non-dict list/`Results`/`Vulnerabilities`
elements are skipped while valid siblings survive; and a monkeypatched live scan returning
a list report yields both findings without crashing. **All ten Trivy review items
(①–⑩) are now resolved.**

### 13.8 Sub-milestones (this PR = S3.0–S3.3)

- **S3.0 Design annex** — this §13.
- **S3.1 Trivy collector** — `run_trivy()` + `normalize_trivy()` + `[trivy]` config + `--trivy-output` dry-run + `cmd_collect` merge; env toggle `VULNTRIAGE_TRIVY_ENABLED`.
- **S3.2 Live verification** — pinned vulnerable image → real KEV/EPSS first-light → temp-ledger e2e → byte-identical restore.
- **S3.3 Config/docs distribution** — README "Appendix — enabling Stage 3 Trivy" (incl. the ECR-discovery IAM note), SKILL "Stage 3" section, `.env.example`, DESIGN §8 roadmap sync (also correct the stale S2.4/S2.5 markers).
- **S3.4 DefectDojo** (system of record) — read-only import collector; design annex in **§14** (S3.4.0). **Collector S3.4.1 ✅, docs S3.4.3 ✅, live verification S3.4.2 ✅** (all merged / verified — §14.8). Verdict write-back deferred (§14.2, S3.4b).
- **S3.5 Off-host signing** (Sigstore keyless + Rekor / KMS) — *deferred, separate PR; delivers the non-repudiation the v1 local-PEM path deliberately does not (§3.5).*

## 14. Stage 3 design annex — DefectDojo collector (system of record)

> **Status: design draft for stage 3 — sub-milestone S3.4.** This annex is the detailed
> expansion of the **second** of roadmap item **§8.3**'s three tracks (Trivy → DefectDojo →
> off-host signing), the twin of §13. It is scoped to **DefectDojo only**. Like the Trivy
> annex, this is the *design judgement* written down first; the implementation (S3.4.1) is a
> later step. The headline is that DefectDojo is a **different class of collector** from
> Prowler and Trivy — an *import from a service*, not a *scan by a subprocess* — and it forces
> one genuine design fork (read vs. write, §14.2) that the read-only invariant (§3.1) decides.

### 14.1 What DefectDojo buys — a new collector class (import, not scan)

Prowler and Trivy are **scanners the harness runs**: a pinned CLI subprocess emits JSON that
`collect.py` parses. DefectDojo is not a scanner — it is a **vulnerability system of record**:
an aggregation/orchestration service that ingests findings from *many* scanners (Prowler,
Trivy, Snyk, Nessus/Tenable, Anchore, Burp, Semgrep, …), deduplicates and triages them into a
single database, and tracks each finding's disposition (active, verified, false-positive,
risk-accepted, mitigated) over time. The harness reaches it over its **REST API**
(`/api/v2/findings/`), not a subprocess.

That makes DefectDojo the highest-*leverage* Stage-3 source: **one integration, N scanners.** A
shop that already runs DefectDojo has, in one endpoint, the CVE output of every scanner it
operates — including ones this harness will never wrap natively (a commercial Nessus, a Snyk
seat). Those CVEs flow into the exact same `enrich()` → sort → floor → graph → digest →
evidence → dedup chain Trivy lit up (§13.1), so — as with Trivy — the value is almost entirely
*reuse*: no new enrichment, no new floor logic, a new *input source* only. The novelty is
purely in the **acquisition** (authenticated HTTP + pagination instead of `subprocess.run`) and
in one thing the scanners don't have: **DefectDojo carries human triage state**, which the
harness must respect rather than relitigate (§14.4).

### 14.2 The read vs. write fork (this is the point)

§8.3's one-line roadmap says "**push** signed verdicts to DefectDojo as the system of record."
That phrasing describes a **write**. But the Next-Action framing — and the read-only invariant —
pull toward a **read**. There are genuinely two DefectDojo integrations, and they sit on opposite
sides of the harness's core guarantee:

- **(R) DefectDojo as a source — import (read).** `GET /api/v2/findings/` → normalize to the
  common schema → triage → Discord digest. This is a **read-only collector**, identical in trust
  posture to Prowler/Trivy: it only *reads*, imported text is untrusted DATA (§14.5), and it
  needs only a read-scoped token. It fits Layer 1 (§3.1) and B2 (§3.2) with **zero** movement of
  the security boundary.
- **(W) DefectDojo as a sink — write-back (write).** `POST`/`PATCH` the harness's triaged, signed
  verdicts back into DefectDojo (as a finding note, tag, or a linked record) so the org's system
  of record reflects the harness's judgement. This is the first time the harness would **write
  anywhere other than Discord and its own ledger/evidence.** It needs a **write-scoped** token, it
  **mutates external state**, and — the sharper problem — it pushes **LLM-influenced output** (the
  triage verdict) into an *authoritative* database. Even with the deterministic floor and signed
  rationale, writing machine-triage into a system humans trust as canonical is a governance
  decision, not a plumbing one.

**Recommendation (for S3.4): ship (R) only.** DefectDojo joins as a **read-only source** this
sub-milestone. This keeps the read-only guarantee (§3.1) and the B2 boundary (§3.2) exactly where
they are, mirrors Prowler/Trivy precisely, and delivers the "N scanners in one integration" value
immediately. The write-back **(W)** is split out as a **separate, opt-in** follow-on (default off,
its own **write-scoped** token, writing only to a finding's *notes/tags* — never mutating or
creating the finding itself, never overwriting human triage — and labelling the note as
machine-generated triage). It is the DefectDojo analogue of §13.3's ECR-discovery fork: the one
place the surface would widen, gated behind a conscious opt-in and documented as such. Moving the
harness from read-only *writer of record* toward mutation is squarely Stage-4 territory (§8.4,
where mutation gets a human-approval gate + AI Gateway + fail-closed policy); the write-back
should not smuggle that escalation in ahead of its governance. So the §8.3 bullet is refined here:
**S3.4 = DefectDojo read source; verdict write-back = deferred opt-in (S3.4b / Stage 4-adjacent).**

### 14.3 Auth & API surface — a read-scoped token as a host env secret

DefectDojo's REST API authenticates with a per-user token sent as an
`Authorization: Token <api_key>` header (v2 also supports JWT; token is simplest and stdlib-
friendly). Two consequences for this harness's conventions:

1. **The token is a SECRET → host environment, never the repo.** Per convention #3, the API
   token lives in the host's environment as `VULNTRIAGE_DEFECTDOJO_TOKEN` (like the Neo4j
   password `VULNTRIAGE_NEO4J_PASSWORD`), injected into the live cron via `--command-env`, and is
   **never** written to `config.toml` or `.env`. The **non-secret** connection values — the base
   URL, and any product/engagement/tag scope — are `config.toml [defectdojo]` (like the Neo4j
   endpoint/user in `[graph]`).
2. **Use a read-only DefectDojo token.** DefectDojo has per-user roles and object-level
   permissions; the operator provisions a **view-only user** whose token can `GET` findings but
   cannot mutate. This is the DefectDojo analogue of the read-only AWS role (§3.1, S1.8②): the
   credential *itself* cannot write, so the read-only guarantee holds by construction, not by the
   harness merely choosing not to call write endpoints. (The deferred write-back **(W)** would use
   a *separate*, narrowly write-scoped token — the two are never the same credential.)

**API shape.** `GET /api/v2/findings/` returns a paginated envelope
(`{count, next, previous, results:[…]}`). The collector pages via `next` until exhausted, with a
server-side filter that pulls only genuinely-open findings (§14.4). Implementation note (design,
not code): the existing `http_get_json()` helper sets only a `User-Agent` header — S3.4.1 needs an
**auth-header-capable GET** (either extend `http_get_json` with an optional headers arg or add a
small `defectdojo_get`), reusing the same bounded-retry / backoff / `RETRYABLE_STATUS` machinery,
with **401/403 fail-fast** (bad/expired token → surface loudly, don't silently degrade to empty —
mirrors `neo4j_cypher`'s 401/403 handling, §12.9).

### 14.4 Schema mapping & dedup — respect DefectDojo's own triage

DefectDojo is a dedup engine in its own right, so the mapping is the cleanest of the three
collectors — but it introduces one obligation the scanners don't have: **honour the human triage
state already recorded in DefectDojo.** Mapping one `results[]` finding through the shared
`make_finding()` constructor (§ the `make_finding` note in code, and §13.7's ⑨):

| common schema field | DefectDojo source |
|---|---|
| `source` | `"defectdojo"` |
| `id` (dedup key) | `defectdojo\|<finding.id>` — DefectDojo's own integer finding id, namespaced. It is **stable** (DefectDojo's dedup engine assigns one id per unique finding across re-imports) and **already deduplicated**, making it the most robust key of the three collectors. Trade-off: if the operator rebuilds/wipes their DefectDojo instance, ids reset and every still-open finding re-notifies **once** — the same fresh-ledger behaviour as a wiped `seen.json`, documented, acceptable. |
| `cve_ids` | `vulnerability_ids[].vulnerability_id` (+ legacy `cve`) filtered by `CVE_RE` — only CVE-shaped ids reach `enrich()`; GHSA/CWE/other advisory ids stay in `title`/`description`. |
| `severity` | `severity` lowercased → `VALID_SEVERITIES` (map DefectDojo `"Info"`/`"Informational"`). |
| `status` | **derived from DefectDojo's triage flags, not imported blindly.** Import only findings that are `active=true` AND `false_p=false` AND `duplicate=false` AND `is_mitigated=false` AND `out_of_scope=false` AND `risk_accepted=false`. This is the DefectDojo analogue of Prowler's FAIL-only `_status_allowed` filter — and it is a **hard requirement**, not a nicety: re-surfacing a finding a human already marked false-positive or risk-accepted would fight the org's own triage and erode trust. The server-side query does most of this (`?active=true&false_p=false&duplicate=false&is_mitigated=false`); the normalizer re-checks defensively. |
| `title` | `title`. |
| `resource` / `resource_type` / `resource_name` | `"<component_name> <component_version>"` / `"component"` / the parent product name (from `test`→engagement→product, when included/expanded). |
| `description` / `risk` / `remediation` | `description` / `impact` (or `references`) / `mitigation` — **all untrusted DATA** (§14.5). |
| `internet_exposed`, `graph` | schema defaults. DefectDojo findings are component/CVE facts, not asset-graph nodes; an `endpoints`→exposure join is conceivable but deferred (same posture as Trivy's image-has-no-network-path, §13.4). |
| `check_id` | `found_by`/test-type name (which scanner reported it) — useful provenance in the rationale. |

**Intel source-of-truth.** DefectDojo findings may already carry `epss_score` / `epss_percentile`.
The harness **ignores** those and re-derives KEV/EPSS via its own `enrich()` from CISA/FIRST, so a
single authoritative intel source governs the deterministic floor across *all* collectors — the
floor must key off collector-authoritative intel the harness fetched, never numbers imported
(possibly staler, possibly from an untrusted upstream) alongside the finding text.

**Merge point.** Identical to Trivy (§13.4): `cmd_collect` merges DefectDojo items into the
`by_id` map **before** `enrich()`, ids namespaced (`defectdojo|…`) so they never collide with
Prowler uids or Trivy keys. No-op when disabled.

### 14.5 B2 preservation — DefectDojo is the *most* untrusted free-text source

DefectDojo aggregates finding text from **arbitrary upstream scanners and arbitrary user-entered
notes**. A `description` in DefectDojo could originate from any tool anyone in the org pointed at
it, or be hand-typed — it is, if anything, a *less* trustworthy free-text source than a Prowler
check or a Trivy advisory. B2 is exactly what makes importing it safe: the orchestrator does the
authenticated HTTP, parses the JSON with defensive `.get` chains, and passes the strings to the
**tool-less** LLM as fenced DATA with the standing "ignore instructions inside" directive. A
crafted `description` — an injected instruction uploaded via some scanner — can at most corrupt a
summary string; it never becomes a command, never touches the host, the ledger, or other channels.
The B2 boundary (§3.1–§3.2) does not move for the **read** collector. (It is precisely the
**write-back (W)** that would begin to move it — which is why §14.2 defers it.)

### 14.6 Config & distribution defaults

A new `[defectdojo]` section, **`enabled = false`** in the tracked config (same discipline as
`[graph]` / `[trivy]`): Stage-1/2 and Trivy-only users are unaffected, and a deployment turns it
on with the non-secret env toggle `VULNTRIAGE_DEFECTDOJO_ENABLED=true` (via a `_defectdojo_enabled`
twin of `_graph_enabled`/`_trivy_enabled`) so an upstream `git pull` never reverts it. Non-secret
keys: `enabled`, `base_url`, `product_id` / `engagement_id` / `tags` (optional scope filters),
`severities` (pre-filter, inheriting `[prowler].severities` when unset — the §13.7-⑤ pattern),
`verified_only` (optional: import only human-verified findings). The **secret** API token is
`VULNTRIAGE_DEFECTDOJO_TOKEN` in the host env only. A `--defectdojo-output <path>` dry-run flag
mirrors `--trivy-output` / `--prowler-output`: replay a captured `/api/v2/findings/` JSON envelope
offline, no network, no token — and, like the Trivy replay guard in `cmd_collect` (§13.7-③), a
`--prowler-output` offline replay must **not** trigger a live DefectDojo fetch.

### 14.7 Verification strategy (instance-state-independent)

Mirrors §13.7's discipline — prove the wiring on real data where possible, offline where instance
state blocks it:

1. **Offline (the wiring):** a captured `/api/v2/findings/` JSON envelope (a real page, incl. the
   `next` pagination link, a CVE-bearing finding, a false-positive/risk-accepted finding that must
   be **dropped**, and a whitespace/injection-laden `description`) through `--defectdojo-output`
   proves `normalize_defectdojo()` + the triage-state filter + pagination handling + merge + dedup
   **without a live instance or token.** This is the primary correctness gate (instance-state
   independent, exactly like Trivy's ECR-offline proof, §13.7-2).
2. **Live (first-light, temp ledger):** stand up a throwaway DefectDojo (`docker compose` from the
   official image, or a read-only token against an existing non-prod instance), seed/select a
   CVE-bearing open finding (e.g. a Log4Shell import), run the full `run.py` on a **temporary
   ledger** → confirm KEV/EPSS enrich fires, the floor escalates, the digest posts intact
   (verified by **reading the real Discord channel**), evidence hash-chains, dedup is idempotent →
   restore the live ledger/evidence to a **byte-identical sha256** (the S1.8/S2.5/S3.2 method —
   leave a Discord trace, never dirty the live ledger). A `401/403` path (bad token) is exercised
   to confirm fail-fast, not silent-empty.

### 14.8 Sub-milestones

- **S3.4.0 Design annex** — this §14.
- **S3.4.1 DefectDojo read collector — ✅ done (offline-verified).** `defectdojo_get()`
  (auth-header GET + bounded retry, 401/403 fail-fast as `DefectDojoError`), `_defectdojo_findings`
  (live `next`-link pagination or a captured envelope / list-of-envelopes), `normalize_defectdojo()`
  + the `_defectdojo_open` triage-state gate (drops false_p/duplicate/is_mitigated/out_of_scope/
  risk_accepted/inactive), `collect_defectdojo()` (severity pre-filter inheriting `[prowler]`,
  loud degrade-to-other-collectors on fetch failure — never a silent empty), `[defectdojo]` config
  (default off), `VULNTRIAGE_DEFECTDOJO_ENABLED` env toggle + `VULNTRIAGE_DEFECTDOJO_TOKEN` secret,
  `--defectdojo-output` dry-run; `cmd_collect` merges before `enrich()` (same offline-replay guard
  as Trivy). `run.py` `format_post` got a `"defectdojo"` row in the `SOURCES` map (§13.7-⑩ made this
  a one-line add). **Offline gate (§14.7-1) PASS:** captured `/api/v2/findings/` envelope → CVE
  extracted from `vulnerability_ids[]`, KEV/EPSS enrich fires (CVE-2021-44228 KEV=true EPSS=0.99999),
  5 human-triaged findings dropped, whitespace/injection description collapsed to inert DATA, no-id
  defensively dropped, dedup idempotent (ledger drops re-seen id), and Prowler+Trivy+DefectDojo merge
  with no id collision (33-check unit suite + CLI runs).
- **S3.4.2 Live verification — ✅ done.** Stood up a throwaway DefectDojo (official `docker compose`
  released images, bound to `127.0.0.1`), seeded 7 findings covering every disposition (2 open CVE-
  bearing — Log4Shell/Spring4Shell, 1 open Info, 4 human-triaged: false_p/out_of_scope/is_mitigated/
  duplicate). **Real-API shape confirmed against the hand-authored offline fixtures:** the live
  `/api/v2/findings/` envelope carries CVEs as `vulnerability_ids: [{"vulnerability_id": "CVE-…"}]`
  (dict form the harness reads) with the legacy `cve` field **read-only/`null` on write** — vindicating
  the §14.4 decision to key CVE extraction on `vulnerability_ids[]`. **Live collect (read-only, Prowler
  stubbed empty):** the harness's server-side triage query returned exactly the 3 open findings (the 4
  triaged excluded server-side), the `[defectdojo].severities` gate dropped the Info one → 2 imported
  as `defectdojo|12`/`defectdojo|13`, KEV/EPSS re-derived from the real CVEs (KEV=true, EPSS 0.99999/
  0.99677) — DefectDojo's own `epss_score` in the envelope correctly **ignored**. **Full `run.py` e2e**
  on a throwaway workspace copy + empty ledger: 2 triaged (0 dropped), **floor escalated both to
  Critical** (KEV), evidence hash-chained (2 entries), and the digest posted intact to the **real
  Discord channel** — read-back confirmed header + 2 Critical messages, each rendering the **`DefectDojo:`
  source label** (not `Prowler:` — the §13.7-⑩ `SOURCES` map holds) + NVD link, no mid-block split.
  **Fail-fast + loud degrade** all exercised live: bad token → HTTP 403 fail-fast (no retry) → loud
  "NOT '0 findings = clean'" degrade (collect continues, exit 0); unreachable base_url → bounded retry
  (4×, exp backoff) → same loud degrade; missing token → immediate loud degrade. **Live untouched:**
  used a workspace *copy*, so the live ledger/evidence were never written — sha256 of `state/seen.json`
  and `state/evidence.log` **byte-identical** before/after (seen=166, `evidence verify ok=True checked=166`).
  DefectDojo torn down (`down -v`). **Instance-model caveat (documented):** this DefectDojo build runs
  *legacy* authorization ("global permissions reduce to is_superuser/is_staff"), where RBAC product-/
  global-role membership grants **no** finding read — so a true view-only token can't be minted on it
  (read requires is_staff, which also writes). The harness's read-only guarantee therefore rests on
  **code, not token scope**: the entire DefectDojo path issues only `Authorization: Token` **GET**
  requests (the sole non-GET in `collect.py` is the Neo4j read-Cypher POST). On a modern RBAC DefectDojo
  a Reader role IS view-only, so the §14.3 / S3.4.3 "provision a view-only token" recommendation stands
  as defense-in-depth — but it is instance-config-dependent, not a harness invariant.
- **S3.4.3 Config/docs distribution — ✅ done.** README "Appendix — enabling Stage 3 DefectDojo"
  (read-only view-only token provisioning, `VULNTRIAGE_DEFECTDOJO_TOKEN` host-env/cron `--command-env`
  injection, `[defectdojo]` base_url/scope, `VULNTRIAGE_DEFECTDOJO_ENABLED` toggle,
  `--defectdojo-output` dry-run, and the write-back deferral), SKILL "Stage 3 — DefectDojo import
  collector" section, `.env.example` (`VULNTRIAGE_DEFECTDOJO_ENABLED` / `_TOKEN`), and this §8/§14.8
  roadmap sync. Mirrors Trivy's S3.3.
- **S3.4b Verdict write-back (deferred, opt-in)** — the **(W)** direction of §14.2: push signed
  machine-triage to a finding's notes/tags via a *separate write-scoped* token, default off,
  never overwriting human triage. Documented as the point where the read-only surface would widen;
  its governance is Stage-4-adjacent.

## 15. Stage 3 design annex — off-host evidence signing (KMS-delegated)

> **Status: design draft for stage 3 — sub-milestone S3.5.** This annex is the detailed
> expansion of the **third and last** of roadmap item **§8.3**'s three tracks (Trivy → DefectDojo →
> off-host signing), the twin of §13/§14. It is scoped to **off-host signing only**. Like those
> annexes, this is the *design judgement* written down first; the implementation (S3.5.1) is a
> later step. The headline is that this track is **not a collector** — it adds no input source and
> touches no triage logic. It changes **how the evidence log is signed**, closing the one gap §3.5
> documents but deliberately does not fix in v1: a **local PEM ⇒ host compromise ⇒ signature
> forgery**. It adds a **fourth signer tier** behind the *already-pluggable* `_load_signer()`
> (§3.5), ships **default-off**, and makes one genuine decision (§15.2): **ship KMS-delegated
> signing first**, with **Sigstore keyless + Rekor** analyzed as the higher-assurance, cloud-neutral
> alternative deferred for OIDC-bearing environments.

### 15.1 What off-host signing buys — closing the documented non-repudiation gap

§3.5 ships a decided three-tier scheme: **ECDSA local PEM** / **HMAC-SHA256** / **none** (default).
The *best* of these today — ECDSA over a local PEM — is still a **local key**: an attacker who
compromises the host holds the private key *and* the append-only log, so they can rewrite history
and re-sign it **offline, with zero trace**. §3.5 states this limit honestly rather than hiding it;
this annex is where it gets closed. Off-host signing moves the signing **authority** off the host so
the private key is either **unstealable** (AWS KMS — the key never leaves the HSM) or **nonexistent
and publicly logged** (Sigstore — ephemeral key + a public transparency log). That is the audit-grade
non-repudiation §3.5 targets.

Unlike Trivy (§13) and DefectDojo (§14), off-host signing **adds no untrusted input source** — it
swaps the *output* backend that produces the `sig` bytes. The hash chain, the `entry_hash`, the
record schema (§5), and `verify()`'s chain walk are all **unchanged**; only the origin of the
signature changes. So — as with the other Stage-3 tracks — the value is mostly *reuse*: the whole
evidence machinery (§3.5) stays, one signer tier is added in front of it.

### 15.2 The two off-host paths, and why KMS ships first (this is the fork)

Parallel to §14.2, there are two genuine off-host options, and they differ on a property axis and an
operational axis:

- **(A) KMS-delegated signing.** An AWS KMS **asymmetric** key (`KeyUsage=SIGN_VERIFY`,
  `KeySpec=ECC_NIST_P256`) signs each entry via `aws kms sign`; the private key **never leaves the
  HSM**, and **every `Sign` call is logged off-host in CloudTrail**. Residual limit, stated honestly:
  a host attacker holding the *signing credential* can still request signatures over forged **new**
  entries **while they hold it** — but (a) they cannot rewrite history *offline* (no private key to
  steal), (b) every signature is an off-host-logged API call, and (c) with a separate least-privilege
  credential (§15.4) the blast radius is one key's Sign capability, not the key itself.
- **(B) Sigstore keyless + Rekor.** A short-lived OIDC-bound Fulcio certificate signs, and the
  signature (or its hash) is published to the **public, append-only Rekor transparency log** — so
  even the **operator cannot silently rewrite their own history**. This is the strongest property and
  it is **cloud-neutral**. Its cost: keyless signing needs an **ambient OIDC identity**. CI (GitHub
  Actions) and workload platforms (EKS/GKE) have one; an **unattended WSL cron host does not** — a
  browser flow is impossible in cron, so a machine-identity / workload-token setup must be solved
  *first*.

**Recommendation (for S3.5): ship (A) KMS-delegated signing first.** For this deployment class —
unattended cron, stdlib-only Python, **already using AWS** for the read-only Prowler scan — KMS fits
with zero operational friction: it reuses the existing `~/.aws` reach, the `aws kms sign` **external
CLI** keeps the harness stdlib-only (the Prowler/Trivy "external tool does the heavy lifting" pattern,
no boto3), and it works unattended. It closes the *key-theft* leg of the local-PEM gap and adds an
*off-host audit trail* (CloudTrail) — the concrete new property. **Sigstore (B)** is documented as the
**higher-assurance, cloud-neutral** path, deferred to **S3.5b** behind its OIDC-identity prerequisite
— the signing analogue of §14.2's write-back fork and §13.3's ECR fork ("the stronger option, gated
on a conscious prerequisite"). This **refines §8.3**: *S3.5 = KMS-delegated off-host signing;
Sigstore keyless + Rekor = deferred higher-assurance option (S3.5b).* It also **inverts** §3.5's
earlier "Sigstore is the target, KMS an alternative" phrasing on the basis of the deployment reality
above — with §15.3 showing KMS does not actually couple the harness to AWS.

### 15.3 The coupling question — KMS does *not* couple the harness to AWS (verify stays offline)

The obvious objection to KMS-first is vendor coupling. The precise answer distinguishes three layers,
and only the third has any AWS dependency at all:

1. **Harness architecture — not coupled.** `_load_signer()` already resolves a
   `(sign_fn, alg_label)` tuple by trying tiers in order and returns a backend-agnostic signer; the
   chain / append / `verify` structure never knows which backend produced the bytes. KMS is **one more
   tier**, exactly as ECDSA-local-PEM is one optional tier today. The architecture stays backend-neutral.
2. **Distribution default — not coupled.** The shipped default stays **`none`** (chain-only + warn).
   KMS is **strictly opt-in** via a non-secret env key (`VULNTRIAGE_EVIDENCE_KMS_KEY_ID`). A
   self-hoster who does not use AWS is **entirely unaffected** — no import, no call, no dependency —
   and stdlib-only is preserved because signing shells out to the **`aws kms sign` external CLI**, so
   no boto3 ever enters the harness.
3. **★ Verification — AWS-independent and offline.** Export the public key **once**
   (`aws kms get-public-key` → cache a PEM in `VULNTRIAGE_EVIDENCE_EC_PUBKEY`), and thereafter
   `verify()` checks every ECDSA signature with the **public key + stdlib/`cryptography`** — **no AWS
   access is ever needed to audit the log.** *Signing* needs AWS reach; *verification does not.* This
   is what keeps the audit trail independently verifiable **forever**, including after a cloud
   migration: past KMS-signed entries still verify against the exported public key.

The coupling that genuinely exists is **operational and scoped to deployments that choose KMS**: their
*ongoing signing* depends on a KMS key + AWS reach + a `kms:Sign`-scoped credential — **the same
dependency class Prowler already imposes** for the read-only scan. The one axis where (B) Sigstore is
strictly better is that KMS ties the signing *authority* to AWS, whereas Sigstore's authority is
cloud-neutral public infrastructure — recorded here so S3.5b's rationale is explicit, not rediscovered.

### 15.4 IAM & credential separation — keep the scan role pure read-only

`kms:Sign` and `kms:GetPublicKey` are **not** in `SecurityAudit` / `ViewOnlyAccess`, so signing needs
its own permission — and that permission must **not** be added to the read-only scanning role
(`vulntriage-readonly`, S1.8②). **Hard rule: signing uses a separate credential from scanning.** A
distinct `VULNTRIAGE_EVIDENCE_KMS_PROFILE` (or a dedicated role) is scoped to **exactly**
`kms:Sign` + `kms:GetPublicKey` on the **single key ARN**, and the KMS **key policy** permits `Sign`
only from that principal. The scan role stays pure read-only; the two credentials are never the same.

Note on the read-only-account invariant (§3.1): `kms:Sign` **mutates no account infrastructure** — it
produces a signature and changes no resource — so it does not break the CSPM-sense "read-only account"
ethos. But it *is* a privileged capability, so it is isolated, least-privilege, single-key-ARN, and
CloudTrail-logged rather than folded into the scan role. The key itself is created **out-of-band** by
the operator (like Neo4j in §12 or a DefectDojo instance in §14); the **key ARN is non-secret** →
`config.toml`/env, and — per convention #3 — **no secret material ever enters the repo** (there is no
private key *to* place, which is the whole point).

### 15.5 Implementation shape — a fourth signer tier, chain unchanged

Parallel to §14.4, the mechanics — all inside `evidence.py`, none touching triage:

- **Resolution order becomes `ECDSA-KMS → ECDSA-local-PEM → HMAC → none`.** A `_load_kms_signer()`
  (twin of `_load_ec_signer()`) is tried first when `VULNTRIAGE_EVIDENCE_KMS_KEY_ID` is set; otherwise
  control falls through to the **existing tiers, unchanged** (regression-safe — a deployment with no
  KMS env behaves exactly as today).
- **`sign_fn(entry_hash_hex)` shells out** to
  `aws kms sign --key-id <arn> --message <entry_hash_hex> --message-type RAW --signing-algorithm
  ECDSA_SHA_256 --output text --query Signature`, base64-decodes → hex, honouring the **same return
  contract** as the local-PEM signer. `message-type RAW` signs the **hex `entry_hash` string** — byte-
  for-byte the same input the local signer feeds `key.sign(entry_hash_hex.encode("ascii"), …)` — so a
  KMS-signed and a PEM-signed entry are verifiable by **one code path per curve**, regardless of who
  signed. `sig_alg` label = **`"ECDSA-P256-SHA256-KMS"`** — the honest-label discipline of §3.5: KMS is
  never dressed up as local, and a downgrade is never dressed up as KMS.
- **The chain is unchanged.** `entry_hash = SHA-256(seq\n ts\n prev_hash\n canonical(record))` is
  identical; only the signature bytes' origin differs. A **mixed log** (some entries PEM-signed before
  a cutover, some KMS after) still chain-verifies end-to-end, each entry self-describing its `sig_alg`.
- **`verify()` gains real ECDSA verification.** When a public-key PEM is available
  (`VULNTRIAGE_EVIDENCE_EC_PUBKEY`, exported once from KMS *or* the local key) and `cryptography` is
  importable, each `ECDSA-P256-SHA256*` entry's `sig` is verified against its `entry_hash` with the
  public key — making third-party verification **real** (the point of asymmetric signing). Absent the
  pubkey/lib, ECDSA sigs stay structurally-present-only and the **chain remains authoritative for
  tamper-evidence** (unchanged from today's `verify` docstring).
- **Fail-closed on signing failure — never a silent downgrade.** If KMS is *configured* and `Sign`
  fails (no AWS reach, throttle, `AccessDenied`), the signer does **bounded retry then raise** —
  it must **not** silently write `sig_alg=none`, which would be a false audit downgrade. This is the
  opposite posture from a *collector* failure (§14.3's loud degrade-to-other-sources): a collector is
  an optional add-on, but **evidence integrity is the core product**, so it **fails closed**. This
  composes cleanly with `run.py`'s ordering — verdicts are **signed into the evidence log FIRST, then
  the digest posts, then the ledger marks** (run.py "sign FIRST"). So a KMS failure aborts **before any
  Discord post and before any `mark`**: nothing is posted, nothing is marked, the findings stay
  unmarked and **retry next run** — no double-post, consistent with the per-chunk recovery model.

### 15.6 B2 preservation & threat model — signing is orchestrator-only

Off-host signing lives **entirely** in the deterministic orchestrator (`evidence.py`); the **tool-less
LLM never sees** the key, the KMS credential, or the signing call, and off-host signing introduces **no
new untrusted input** (it is an output backend, not an input source). The B2 boundary (§3.1–§3.2) does
**not** move. The read-only-account invariant is intact — `kms:Sign` mutates no infrastructure and is
isolated to a separate least-privilege credential (§15.4).

**Threat closed, stated honestly (the §3.5 discipline of never overstating the guarantee):** local PEM
⇒ host compromise ⇒ *silent, offline, traceless* rewrite-and-re-sign. KMS closes the **key-theft** leg
(the key is unstealable) and adds **off-host logging** (every `Sign` in CloudTrail). A host attacker
holding the scoped credential can still sign forged **new** entries *while they hold it* — but each is
an off-host-logged call and they cannot rewrite history offline. The **residual gap versus (B)
Sigstore** — an operator (or a sufficiently privileged attacker) can still sign *some* forgery, whereas
Rekor's public log defeats even the operator's own silent rewrite — is named here rather than papered
over, and is exactly what S3.5b would close for deployments that can carry an OIDC identity.

### 15.7 Verification strategy (account-state-independent)

Mirrors §13.7 / §14.7 — prove the wiring offline, then first-light on real KMS without dirtying the
live log:

1. **Offline (the wiring), no AWS:** with `cryptography` available, generate a local EC P-256 keypair
   and **stub the `aws kms sign` shell-out** to sign with it (a local stand-in for the HSM). Prove:
   (a) `_load_signer()` resolves the **KMS tier first** when `VULNTRIAGE_EVIDENCE_KMS_KEY_ID` is set;
   (b) entries carry `sig_alg="ECDSA-P256-SHA256-KMS"`; (c) `verify()` **validates** each sig against
   the exported public key; (d) a **mixed PEM+KMS** log still chain-verifies; (e) a simulated `Sign`
   failure **fails loud** (aborts, no silent `none` downgrade, nothing posted/marked); (f) with **no
   KMS env**, resolution falls through to the existing tiers **unchanged** (regression). This is the
   primary correctness gate — instance-state-independent, like Trivy's ECR-offline proof (§13.7-2).
2. **Live (first-light, temp evidence log):** create a **throwaway** KMS asymmetric key
   (`ECC_NIST_P256`, `SIGN_VERIFY`) + a scoped signing profile, point `VULNTRIAGE_EVIDENCE_KMS_KEY_ID`
   at it, and run the harness against a **temporary evidence log** (never the live one — the
   S1.8/S2.5/S3.2/S3.4.2 copy method). Confirm: real `aws kms sign` produces signatures,
   `aws kms get-public-key` → PEM **verifies them offline** (`evidence.py verify ok`), and **CloudTrail
   shows the `Sign` events** (the off-host audit trail — the actual new property). Confirm the **live**
   evidence log is **byte-identical sha256** before/after. Tear down the throwaway key.

**Live result (§15.7-2, verified).** Throwaway KMS key `ECC_NIST_P256`/`SIGN_VERIFY` + a scoped
`aisec-vulntriage-signer` role (inline policy: `kms:Sign` + `kms:GetPublicKey` on that one key ARN,
assumed via a `vulntriage-signer` named profile **separate from the read-only scan role** per §15.4 —
the role could sign but got `UnauthorizedOperation` on `ec2:DescribeInstances`, proving the split).
The harness's **unmodified** `evidence.EvidenceLog.append` (same record shape as `run.py`:575) signed 3
verdicts against a temp log via real `aws kms sign` — entries carried `sig_alg="ECDSA-P256-SHA256-KMS"`
with real DER sigs. `aws kms get-public-key` → PEM verified all 3 **offline with no AWS/KMS env**
(`evidence.py verify ok=True checked=3`); a one-byte sig flip → `ECDSA signature mismatch at seq 1`
(proving the check runs, not a no-op). **CloudTrail Event history showed 3 `Sign` events**
(`signingAlgorithm=ECDSA_SHA_256`, `messageType=RAW`, no errorCode) attributed to the *signer* role —
the off-host, host-breach-resistant audit trail. The **live** evidence log was untouched (temp-only
writes; sha256 unchanged, 324 entries, `verify ok`). Throwaway key scheduled for deletion (7-day
AWS-min window), role + profile removed, scan role intact. AWS CLI v2 was installed user-local
(`~/.local/bin/aws`, no sudo) since the KMS tier shells out to it.

### 15.8 Sub-milestones

- **S3.5.0 Design annex** — this §15.
- **S3.5.1 KMS signer** — ✅ (PR #40) the fourth `_load_signer()` tier (`_load_kms_signer()` via
  `aws kms sign`), `verify()` ECDSA-public-key support, fail-closed-on-Sign-failure,
  `VULNTRIAGE_EVIDENCE_KMS_KEY_ID` / `_KMS_PROFILE` / `_EC_PUBKEY` env, and the offline gate (§15.7-1,
  11/11). Default off; chain/schema unchanged.
- **S3.5.2 Live verification** — ✅ (§15.7-2 above) real throwaway KMS key, temp evidence log, offline pubkey verify,
  CloudTrail off-host trail, byte-identical live-log restore (§15.7-2).
- **S3.5.3 Config/docs distribution** — ✅ README "Appendix — enabling Stage 3 off-host signing" (KMS
  key + scoped signing role provisioning, non-secret key-id/profile env + cron `--command-env`
  injection, public-key export for offline verify), SKILL "Stage 3 — off-host signing" section,
  `.env.example` signing block, and §8/§15.8 sync. Mirrors Trivy's S3.3 / DefectDojo's S3.4.3.
  **This closes all three Stage 3 tracks.**
- **S3.5b Sigstore keyless + Rekor (deferred, higher-assurance)** — the **(B)** direction of §15.2: the
  cloud-neutral, operator-can't-silently-rewrite path via Fulcio + the public Rekor transparency log.
  Needs a machine-identity / workload-token setup an unattended cron host lacks (its OIDC-identity
  prerequisite). Documented as the stronger option gated on that prerequisite — the signing analogue of
  §14.2's write-back and §13.3's ECR fork.
