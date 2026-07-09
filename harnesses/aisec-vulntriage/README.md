# aisec-vulntriage

A self-hosted OpenClaw harness that **triages your AWS cloud-security posture** with
an LLM and delivers a prioritized, evidence-backed digest to Discord. On a schedule
it runs **Prowler** (read-only CSPM), enriches any referenced CVEs from free intel
feeds (**CISA KEV**, **FIRST EPSS**, optionally **NVD**), has a **tool-less** agent
assign a priority + structured rationale to each finding, floors that priority with
deterministic facts, signs every verdict into a **hash-chained evidence log**, and
posts the result.

This is a **different class of harness** from its siblings (`aisec-arxiv-monitor`,
`aisec-news-monitor`): the monitors *watch a public feed and summarize*; this one
*reads your own cloud posture and decides what matters first*.

This directory **is** the agent's OpenClaw workspace. It is self-contained and ships
with **no secrets**. You supply your own AWS read-only role, Discord bot + channel,
and model credentials — all configured in your OpenClaw / host, never in this
directory.

> **It is read-only and non-destructive by construction.** v1 collects, triages,
> reports, and records signed evidence. It **never changes anything** in your AWS
> account — the IAM role it uses has zero mutate permissions. Remediation execution
> is out of v1 scope (see `DESIGN.md` §2 / §8).

---

## What you get per post

```
🛡️ **[<priority>] <asset> — <CVE / check id>**
📊 KEV: <yes/no>  |  EPSS: <score>  |  Exposure: <internet/internal>
<short rationale, in your configured language>
🔗 Prowler: <check id>  |  <NVD url, if a CVE is present>
```

Priority is `Critical` / `High` / `Medium` / `Low`. Plus, once per posting run, a
disclaimer line and the **evidence-log chain head** (so a reader can tie the digest to
the signed record).

## Security model (read this — it is the point)

Three independent layers, defense-in-depth. The outer layer holds even if every inner
one fails. Full rationale in `skills/aisec-vulntriage/SKILL.md` and `DESIGN.md` §3.

- **Layer 1 — read-only by construction.** The harness authenticates to AWS with a
  **read-only IAM role** (`SecurityAudit` + `ViewOnlyAccess`, zero mutate
  permissions). Even a fully compromised LLM or a bug in the orchestrator physically
  **cannot change, delete, or write-exfiltrate** anything in your account. Enforced
  by IAM, not by code or prompts.
- **Layer 2 — the LLM stays tool-less (B2).** The **orchestrator**
  `skills/aisec-vulntriage/run.py` does the privileged, non-LLM work (run Prowler,
  pull feeds, sign evidence, post, ledger). **The agent** is invoked as a **tool-less
  text transform** (`minimal` profile): it only assigns a priority + rationale and
  **cannot** scan, fetch, post, run code, or write files. An indirect prompt
  injection hidden in a finding can at worst corrupt one finding's priority label —
  never touch your host, account, or evidence log.
- **Layer 3 — deterministic facts win.** The KEV / EPSS / exposure signals come from
  the **collector**, not the LLM, and a deterministic **priority floor** can only
  raise a priority. So a poisoned or compromised LLM **cannot talk a KEV-listed,
  internet-exposed finding down** to Low.

## How it works: what's automated, what stays manual

Picture the task a security engineer (情シス) would otherwise do by hand: **scan the
cloud account → drop what's already been handled → look up each CVE against public
intel → decide which findings actually matter for these assets → write the *why* →
post to the team channel → keep an audit trail**. This harness automates most of that,
but deliberately keeps the *act of changing anything* — and final judgement — with a
human.

**Who does each step**

- **AI** — the tool-less LLM assigns priority, judges excess-privilege /
  asset-criticality, and writes the rationale summary.
- **Tool** — the deterministic orchestrator / collector runs Prowler, enriches
  CVEs, applies the priority floor, signs evidence, posts, and keeps the ledger.
- **You** — the setup, the read-only IAM role, and final responsibility for acting on
  a finding.

**"Human check?"** is flagged **Yes** when a failure is hard to undo (an
already-public post) OR output quality varies (triage / summary errors).

| Step (what a human would do) | Who | Human check? | Why |
|---|:--:|:--:|---|
| **A.** Choose scan scope + provision a read-only IAM role (`aws`/`prowler` config) | You | — | Your call; scope and the read-only role are the safety boundary. |
| **B.** Scan the account (Prowler, read-only) | Tool | No | Deterministic; a failed scan self-recovers next run — nothing is marked. |
| **C.** Enrich CVEs (KEV / EPSS / NVD) | Tool | No | Deterministic; degrades gracefully if a feed is down. |
| **D.** Track what's already been handled | Tool | No | Idempotent — marked only after a post succeeds. |
| **E.** Assign priority to each finding | AI | **Yes** | The core judgement — quality varies; a floor backs it up but review still matters. |
| **F.** Judge excess-privilege / asset-criticality + write the *why* | AI | **Yes** | Varies, can mis-judge or hallucinate — verify before acting. |
| **G.** Floor the priority with KEV/EPSS/exposure facts | Tool | No | Deterministic; the LLM cannot lower a floored priority. |
| **H.** Sign each verdict into the evidence log | Tool | No | Append-only hash chain; signed if a key is configured. |
| **I.** Post the digest to Discord | Tool | No\* | Built from trusted collector metadata, never LLM output. \*See note. |
| **J.** Confirm the post & retry next run | Tool | No | Only successful posts are marked; failures retry — never a silent loss. |

> **\*Note on step I — there is no human-in-the-loop before posting.** The posting
> *mechanism* is safe (message built from trusted metadata, not LLM output), but the
> *content* depends on the AI's steps E–F. Discord posts are effectively
> irreversible, so today the human check on E–F is a **post-hoc review** (read the
> channel, the priority floor and evidence log back you up) — not an approval gate.
> If you need to catch triage errors *before* they go public, add a staging step
> before I (post drafts to a staging channel, publish after review). The harness is
> read-only regardless, so the worst a bad post does is misrank — it can never change
> your account.

Two things are intentionally **not** automated: **scan scope + the read-only role**
(step A) and **acting on a finding** (v1 executes no remediation at all). The security
model above is what makes the rest safe to run unattended.

## Prerequisites

> **First time setting up the host?** Do the one-time, host-wide bootstrap first
> (model provider + credentials, Discord bot + channel, operator scope):
> [../../docs/HOST-SETUP.md](../../docs/HOST-SETUP.md). The steps below assume it's done.

- OpenClaw installed, with a running gateway.
- A text model configured (defaults assume a Bedrock/Claude-class model; any OpenClaw
  text model works).
- A Discord bot in your server + the target channel id
  (enable Discord Developer Mode → right-click channel → Copy Channel ID).
- **Prowler installed** on the host and on `PATH` (or point `PROWLER_BIN` at it). The
  collector pins the major version — see `[prowler].version` in `config.toml` (default
  `"5."`). Install per Prowler's docs (e.g. `pipx install prowler`). For an unattended
  cron deployment, prefer a **dedicated venv at a stable path** (one that survives
  shell/tmp cleanup, e.g. `~/.local/share/aisec-vulntriage/prowler-venv`) and point
  `PROWLER_BIN` at its `prowler` binary — `pipx`/`PATH` also work, but a pinned venv
  keeps the scheduled run from breaking if `PATH` or a scratch install changes.
- **A read-only AWS role/credentials** the host can assume, granting **`SecurityAudit`
  + `ViewOnlyAccess`** and **nothing that mutates**. This is the harness's outer
  safety guarantee — do **not** give it write permissions. Supply it via the host
  credential chain or a named profile (`VULNTRIAGE_AWS_PROFILE`). A copy-paste
  provisioning runbook (trust policy, the extra Prowler read permissions those two
  managed policies miss, and the profile wiring) is in the
  [Appendix — provisioning the read-only role](#appendix--provisioning-the-read-only-role).
- Python 3.11+ on the host (stdlib only for the harness; `tomllib` is used). Optional:
  the `cryptography` package if you want ECDSA-signed evidence (see *Evidence log*
  below) — without it the log is still hash-chained and tamper-evident.

## Setup

### 1. Place the workspace

Clone this repo (or copy this directory) somewhere stable, e.g.
`~/openclaw-workspaces/aisec-vulntriage`.

### 2. Register the agent

```bash
openclaw agents add aisec-vulntriage --workspace /path/to/aisec-vulntriage \
  --model amazon-bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0
```

Do **not** bind this agent to inbound channels — it only posts on a schedule.

### 3. Lock the agent to the `minimal` tool profile (REQUIRED)

```bash
# find the agent's index in agents.list, then:
openclaw config set 'agents.list[<index>].tools' '{"profile":"minimal"}'
openclaw gateway restart
```

Scanning, enriching, and posting are done by the orchestrator, not the agent, so
`minimal` removes attack surface without removing functionality. **This is the core of
the security model — skipping it would hand the triage LLM real tools.**

### 4. Provide secrets in OpenClaw / the host (not here)

- **AWS read-only credentials** via the host credential chain or a named profile — the
  role MUST be read-only (`SecurityAudit` + `ViewOnlyAccess`).
- **Discord bot token** + allow the bot to post in your target channel.
- **Model credentials** via your provider (e.g. the AWS credential chain for Bedrock).

None of these belong in this directory.

### 5. Set your parameters

Two files, split by what they're for:

**`config.toml`** — shippable defaults you commit (no secrets, no per-deployment
state):
- `aws.regions` — regions Prowler scans (default `["us-east-1"]`).
- `prowler.version` — pinned major series the collector refuses to run below.
- `prowler.services` / `compliance` / `statuses` / `severities` — scan scope + the
  coarse pre-filter before triage.
- `enrich.kev` / `epss` / `nvd` — which free intel feeds to attach (NVD off by
  default; its rate limit is low).
- `triage.kev_forces_at_least` / `epss_high_threshold` / `exposure_forces_at_least` —
  the deterministic priority-floor thresholds.
- `output.language` — rationale language (`ja`, `en`, ...).
- `output.llm_batch_size` — findings per LLM triage call (chunked into separate,
  stateless calls). There is no post cap — every triaged finding is posted.

**`.env`** (git-ignored) — the deployment-specific values. Copy the template and fill
it in:

```bash
cp .env.example .env   # then edit
```

| Variable | Purpose | Default |
|---|---|---|
| `VULNTRIAGE_CHANNEL_ID` | target Discord channel id | **required to post** |
| `VULNTRIAGE_AGENT_ID` | the agent the orchestrator invokes | `aisec-vulntriage` |
| `VULNTRIAGE_AWS_PROFILE` | AWS named profile (read-only role) | host default chain |
| `OPENCLAW_BIN` | the `openclaw` CLI path | `openclaw` (on PATH) |
| `PROWLER_BIN` | the `prowler` CLI path | `prowler` (on PATH) |

The target channel is set **only** here (`VULNTRIAGE_CHANNEL_ID`) — not in
`config.toml`, so the committed config carries no deployment state. An exported shell
variable wins over `.env`. **Only non-secret values go in `.env`** — AWS credentials
and the Discord token stay in OpenClaw / the host chain.

### 6. Schedule it

Cron runs the orchestrator as a command. `--no-deliver` stops cron from trying to
deliver the script's stdout (run.py posts on its own).

```bash
openclaw cron add --name aisec-vulntriage-daily \
  --cron '0 9 * * *' --tz Asia/Tokyo \
  --command 'python3 /path/to/aisec-vulntriage/skills/aisec-vulntriage/run.py' \
  --command-cwd /path/to/aisec-vulntriage \
  --no-deliver
```

(`0 9 * * *` = daily 09:00 in `--tz`. Use `--every 12h` for interval runs. Managing
cron jobs requires an operator token with the `operator.admin` scope.)

### 7. Test before relying on it

**Read-only dry run — no AWS calls, no posting.** Capture Prowler's OCSF output once,
then feed it to the collector (this is also how you validate the parser against your
real Prowler version):

```bash
prowler aws --output-formats json-ocsf --output-directory /tmp/prowler-out
python3 skills/aisec-vulntriage/collect.py collect \
  --prowler-output /tmp/prowler-out | head
```

`--prowler-output` reads that captured output (you can pass the directory or the
`*.ocsf.json` file directly) instead of invoking Prowler, so it makes **no AWS calls**
and does **not** post. Omit it to run a live read-only Prowler scan.

**Live scan, no posting** (runs Prowler read-only, prints the collected JSON):
```bash
python3 skills/aisec-vulntriage/collect.py collect | head
```

**Full run (this DOES post to Discord):**
```bash
python3 skills/aisec-vulntriage/run.py        # direct, or:
openclaw cron run <job-id>                     # via cron (debug)
```

**Verify the evidence log** (re-checks the hash chain end-to-end, and signatures if a
key is configured):
```bash
python3 skills/aisec-vulntriage/evidence.py verify state/evidence.log
```

## Run on a schedule, or by hand

The cron job and the orchestrator are independent — switch freely. First find the job
id with `openclaw cron list` (the `ID` column), then:

| What you want | Command |
|---|---|
| **Run once, now** (leave the schedule as-is) | `openclaw cron run <job-id>` |
| **Pause the daily schedule** (keep the job) | `openclaw cron disable <job-id>` |
| **Resume the daily schedule** | `openclaw cron enable <job-id>` |
| **Change the schedule** (time, interval) | `openclaw cron edit <job-id>` |
| **Run without cron at all** | `python3 skills/aisec-vulntriage/run.py` |
| **Dry run** (read-only, no posting) | `python3 skills/aisec-vulntriage/collect.py collect --prowler-output <file>` |
| **Check the graph facts** (Stage 2, read-only) | `python3 skills/aisec-vulntriage/collect.py graph-check` |
| **Verify the audit trail** | `python3 skills/aisec-vulntriage/evidence.py verify state/evidence.log` |

> **Note for laptop / WSL2 hosts:** a scheduled run only fires while the host is
> awake. If the machine is asleep at the scheduled time, OpenClaw runs the job once it
> wakes (so it may run late), and a day the host never comes up is skipped entirely.
> If that's unreliable for you, prefer manual operation: `disable` the schedule and
> trigger runs by hand with `openclaw cron run <job-id>`.

## Evidence log (VAT)

Every triage verdict is appended to `state/evidence.log` (git-ignored, JSON Lines) as
*which inputs (by digest) → what priority → what rationale*, chained with SHA-256 so
any edit breaks the chain (tamper-evident). The signature is **pluggable**:

- **ECDSA P-256** — used when the `cryptography` package is importable **and**
  `VULNTRIAGE_EVIDENCE_EC_KEY` points to a PEM EC private key. This is the
  third-party-verifiable (asymmetric) mode the design targets.
- **HMAC-SHA256** — stdlib fallback when `VULNTRIAGE_EVIDENCE_KEY` (a shared secret)
  is set but ECDSA is unavailable. Tamper-evident to anyone holding the key; **not**
  third-party verifiable. Labelled honestly in each entry's `sig_alg`.
- **none** — chain-only when no key is set. The hash chain still makes the log
  tamper-evident; it is just unsigned (a one-time warning is emitted).

Two distinct properties, so you know what you're getting:

- **Tamper-evidence** comes from the **hash chain** and is always on, with no key and
  no dependencies — any edit to a committed entry breaks the chain and `evidence.py
  verify` catches it.
- **Non-repudiation** (a third party can prove a verdict came from this harness and
  wasn't altered) needs the **ECDSA** mode — only an asymmetric signature gives it.
  HMAC is integrity-only (the verifier holds the same secret that signs, so it can't
  prove authorship to anyone else); the chain alone stops edits but not a full-log
  rewrite by someone who can recompute every hash.

**Signing key management (v1): local PEM.** To turn on ECDSA, generate a P-256 key and
point `VULNTRIAGE_EVIDENCE_EC_KEY` at it (install `cryptography` first):

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ~/.secrets/vulntriage-evidence.pem
chmod 600 ~/.secrets/vulntriage-evidence.pem
export VULNTRIAGE_EVIDENCE_EC_KEY=~/.secrets/vulntriage-evidence.pem
```

Keep the key with your **host's other secrets — never in this directory** (convention
#3). Verifiers use the corresponding public key (`openssl ec -in <key> -pubout`).

> **⚠ Limit of the local-PEM path — do not over-trust it.** A key on this host means
> **host compromise ⇒ signature forgery**: an attacker who steals the key can rewrite
> the log and re-sign it, and the signature then proves nothing *against that
> attacker*. So v1 signing raises the bar for outsiders and gives honest operators
> tamper-evidence — but it is **not** non-repudiation against a host-level breach.
> True non-repudiation requires an off-host signing authority (**AWS KMS**, or
> **Sigstore keyless + a Rekor** transparency log) — the **roadmap stage-3** target,
> not shipped in v1. See `DESIGN.md` §3.5 / §8.

## How it stays idempotent

`state/seen.json` records finding ids. The orchestrator marks a finding handled only
after its post succeeds (plus findings the agent deliberately dropped), so a failed
post retries next run — never a silent loss. It ships empty and fills at runtime
(git-ignored). Unlike the monitors there is **no time window**: a finding stays open
until fixed, so re-posting is suppressed by the ledger alone. (Trade-off: a finding
that is fixed and later recurs under the same id is suppressed by the ledger — an
accepted v1 limitation; see `DESIGN.md` §5 notes.)

## What's tunable vs fixed

- **Tune:** `config.toml` (AWS/Prowler scope, enrich feeds, triage floor thresholds,
  language, batch size) and `.env` (deployment-specific: channel, agent, AWS profile,
  CLI paths).
- **Adjust if you change the routine:** `skills/aisec-vulntriage/run.py`
  (`build_prompt` = what the agent triages; `floor_priority` = the deterministic
  floor; `build_rationale` = fact/LLM merge; `format_post` = the post layout),
  `collect.py` (Prowler invocation + enrichment), `evidence.py` (the signed chain).
- **Persona:** `AGENTS.md`, `SOUL.md`, `IDENTITY.md`.

## Scope & roadmap (v1 = read-only walking skeleton)

v1 is Phase 1–3 + 7: **collect → enrich → triage → report/evidence**, read-only.
**Stage 2 graph context (Cartography + Neo4j) is now available as an opt-in add-on** —
it turns v1's keyword exposure *guess* into a graph-derived *fact*, grounds
excess-privilege in real IAM blast-radius, and floors a graph-confirmed toxic
combination (exposure + over-privilege + KEV/high-EPSS) to Critical. It is **off by
default** and still read-only + B2-preserving; see
[Appendix — enabling Stage 2 graph context](#appendix--enabling-stage-2-graph-context-cartography--neo4j).
Still deliberately deferred (documented, not built): Trivy image/snapshot CVEs,
DefectDojo system of record, Sigstore Rekor transparency, and — the hard line —
**Phase 4–6 execution** (decide → apply → verify), which is where the architecture
escalates beyond tool-less B2 to gated agentic tool-calling. Full design, rationale,
and roadmap: **`DESIGN.md`**.

## Appendix — provisioning the read-only role

The harness's outer safety guarantee is IAM: the credentials it runs under must be
**read-only**, so a fully-compromised LLM still cannot mutate the account. `SecurityAudit`
+ `ViewOnlyAccess` cover almost everything Prowler reads, but Prowler needs a **handful of
extra read actions** those two managed policies miss (e.g. `ec2:GetEbsEncryptionByDefault`,
`s3:GetAccountPublicAccessBlock`, `lambda:GetFunction*`) — without them some checks return
`AccessDenied` and are silently skipped. This runbook creates a dedicated role assumable by
your existing admin principal (no new long-lived keys). Replace `<ACCOUNT_ID>` and the admin
principal ARN with yours; region is passed by the collector (`aws.regions`) so the profile
region is only for auxiliary calls.

```bash
mkdir -p ~/aisec-vulntriage-iam && cd ~/aisec-vulntriage-iam

# 1) trust policy — who may assume the role (your admin user/role)
cat > trust-policy.json <<'JSON'
{ "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_ID>:user/<your-admin-principal>" },
    "Action": "sts:AssumeRole" }] }
JSON

# 2) the extra read actions Prowler needs beyond SecurityAudit + ViewOnlyAccess
#    (Prowler's published "prowler-additions" set; trim to your scanned services if you like)
cat > prowler-additions.json <<'JSON'
{ "Version": "2012-10-17",
  "Statement": [{ "Sid": "AllowMoreReadForProwler", "Effect": "Allow", "Resource": "*",
    "Action": [
      "account:Get*", "appstream:Describe*", "appstream:List*", "backup:List*",
      "cloudtrail:GetInsightSelectors", "codeartifact:List*", "codebuild:BatchGet*",
      "cognito-idp:GetUserPoolMfaConfig", "dlm:Get*", "drs:Describe*",
      "ds:Get*", "ds:Describe*", "ds:List*", "dynamodb:GetResourcePolicy",
      "ec2:GetEbsEncryptionByDefault", "ec2:GetSnapshotBlockPublicAccessState",
      "ec2:GetInstanceMetadataDefaults", "ecr:Describe*",
      "ecr:GetRegistryScanningConfiguration", "elasticfilesystem:DescribeBackupPolicy",
      "glue:GetConnections", "glue:GetSecurityConfiguration*", "glue:SearchTables",
      "lambda:GetFunction*", "logs:FilterLogEvents", "macie2:GetMacieSession",
      "s3:GetAccountPublicAccessBlock", "shield:DescribeProtection",
      "shield:GetSubscriptionState", "servicecatalog:Describe*", "servicecatalog:List*",
      "ssm-incidents:List*", "support:Describe*", "tag:GetTagKeys",
      "wellarchitected:List*" ] }] }
JSON

# 3) create the role + attach the two managed policies + the additions
ROLE=aisec-vulntriage-readonly
aws iam create-role --role-name "$ROLE" \
  --assume-role-policy-document file://trust-policy.json \
  --description "Read-only role for aisec-vulntriage (Prowler CSPM scan)"
aws iam attach-role-policy --role-name "$ROLE" \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-role-policy --role-name "$ROLE" \
  --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
POLICY_ARN=$(aws iam create-policy --policy-name prowler-additions \
  --policy-document file://prowler-additions.json --query 'Policy.Arn' --output text)
aws iam attach-role-policy --role-name "$ROLE" --policy-arn "$POLICY_ARN"
```

Wire it up as a named profile in `~/.aws/config` (point `source_profile` at whatever
profile holds your admin creds; use `credential_source = Environment` if they come from
env vars):

```ini
[profile vulntriage-readonly]
role_arn = arn:aws:iam::<ACCOUNT_ID>:role/aisec-vulntriage-readonly
source_profile = default
region = us-east-1
```

Verify before wiring it into `.env` (`VULNTRIAGE_AWS_PROFILE=vulntriage-readonly`):

```bash
# assumed-role identity resolves (IAM is eventually consistent — retry if it 403s)
aws sts get-caller-identity --profile vulntriage-readonly
# read-only dry run: no AccessDenied in the log = permissions sufficient
VULNTRIAGE_AWS_PROFILE=vulntriage-readonly \
  python3 skills/aisec-vulntriage/collect.py --state /tmp/vt-role-test.json collect
```

## Appendix — enabling Stage 2 graph context (Cartography + Neo4j)

**Optional and off by default.** Stage 2 adds *asset-graph* context: instead of guessing
internet exposure from a keyword heuristic, the collector reads deterministic
`exposure_path` and `blast_radius` facts from a **Cartography**-populated **Neo4j** graph
of your account. The graph-derived exposure overrides the keyword flag, blast-radius
grounds excess-privilege in real IAM wildcard reach, and a graph-confirmed **toxic
combination** (internet exposure ∧ over-privilege ∧ KEV/high-EPSS on one finding) floors
that finding to **Critical**. It changes **nothing** about the security model: Cartography
reads AWS with the **same read-only role**, the harness only issues **read** Cypher over
Neo4j's HTTP endpoint, and the graph facts join the *trusted* collector metadata — no tool
is added to the LLM. Full design and the empirical validation are in `DESIGN.md` §12.

The harness **only queries** an already-populated Neo4j; it does **not** run Cartography
for you. Standing up Neo4j and keeping the graph synced are operator steps (below), the
same way you install and run Prowler.

**Prerequisites (beyond the base ones):**
- **Docker** (or Podman) to run Neo4j locally — and optionally to run Cartography.
- **Cartography** (Apache-2.0) installed in an isolated venv, or run from a container.
- The **same read-only AWS role** from the previous appendix — Cartography's default AWS
  sync needs no IAM beyond `SecurityAudit` + `ViewOnlyAccess` (validated in `DESIGN.md`
  §12.2 — the only `AccessDenied` is the optional `inspector2` module, which it skips).

### 1. Start Neo4j (5.x, localhost-only)

```bash
docker run -d --name aisec-neo4j \
  -p 127.0.0.1:7474:7474 -p 127.0.0.1:7687:7687 \
  -e NEO4J_AUTH=neo4j/<choose-a-strong-password> \
  neo4j:5.26-community
```

Neo4j **must be 5.x** — Cartography 0.138's Cypher uses Neo4j-5 syntax and errors on 4.4.
**Bind to `127.0.0.1` only** (as above): the graph is a sensitive map of your asset
topology and must never be network-exposed (`DESIGN.md` §12.3). `7474` is the HTTP Cypher
port the harness queries; `7687` is bolt, which Cartography writes over.

### 2. Give the harness the Neo4j password (a secret, via the environment)

```bash
export VULNTRIAGE_NEO4J_PASSWORD=<the-password-you-set-above>
```

This is a **secret** — it lives in the host environment / credential chain, **not** in
`.env` (which is non-secret only, convention #3) and never in the repo. Export it in the
same shell/service environment the cron job runs under.

### 3. Populate the graph with Cartography (read-only)

Using the read-only profile, so the sync reads AWS with zero mutate permissions:

```bash
AWS_PROFILE=vulntriage-readonly cartography \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j --neo4j-password-env-var VULNTRIAGE_NEO4J_PASSWORD
```

> **If your host Python can't install Cartography**, run it from a `python:3.12`
> container. (Cartography depends on `oci`, which pins `crc32c==2.7.1`; that has no wheel
> for Python 3.14 and needs a compiler to build from source — so a host venv can fail on a
> very new interpreter.) Put Neo4j and the Cartography container on a shared Docker network
> and mount your AWS config read-only:
>
> ```bash
> docker network create cartonet
> docker network connect cartonet aisec-neo4j
> docker run --rm --network cartonet \
>   -v ~/.aws:/root/.aws:ro -e AWS_PROFILE=vulntriage-readonly \
>   -e NEO4J_PW="$VULNTRIAGE_NEO4J_PASSWORD" python:3.12-slim bash -c \
>   "pip install cartography && cartography --neo4j-uri bolt://aisec-neo4j:7687 \
>      --neo4j-user neo4j --neo4j-password-env-var NEO4J_PW"
> ```

The graph is **derived and ephemeral** — fully re-syncable from the account, nothing to
back up. **Re-run this sync before each triage run** (or on its own schedule) so the graph
reflects current topology; a stale graph only yields stale *facts*, never a wrong action
(the harness is read-only regardless).

### 4. Turn the graph on

In `config.toml`:

```toml
[graph]
enabled = true
```

The `neo4j_http_endpoint` / `neo4j_user` / `neo4j_database` defaults
(`http://localhost:7474`, `neo4j`, `neo4j`) already match the container above — override
them in `[graph]` only if you changed them.

Prefer **not** editing the shipped `enabled = false` if you keep this harness in a git
working tree that tracks upstream: set the non-secret env var **`VULNTRIAGE_GRAPH_ENABLED=true`**
in your deployment `.env` instead. It overrides the config default, so the committed file
stays `false` (nothing to reconcile on `git pull`) — the same "deployment values live in
`.env`" pattern as the channel id. Either way, the Neo4j **password** stays in the host
environment (`VULNTRIAGE_NEO4J_PASSWORD`), never in `.env` or config.

### 5. Verify (read-only, no posting, no ledger writes)

```bash
python3 skills/aisec-vulntriage/collect.py graph-check
```

It prints how many findings joined to the graph and their `exposure_path` /
`blast_radius` facts. If the graph is unreachable, the password is wrong, or a finding
doesn't join, that finding **degrades gracefully** to v1's keyword exposure flag — the run
never crashes and never blocks (same graceful-degrade contract as a down intel feed). When
it looks right, your scheduled `run.py` picks up the graph facts automatically.

## Layout

```
aisec-vulntriage/
├── README.md                  ← this file
├── DESIGN.md                  ← full v1 design, security model, roadmap
├── config.toml                ← shippable defaults (AWS/Prowler scope, feeds, thresholds)
├── .env.example               ← copy to .env for per-deployment overrides
├── AGENTS.md / SOUL.md / IDENTITY.md
├── skills/aisec-vulntriage/
│   ├── SKILL.md               ← architecture + three-layer threat model
│   ├── collect.py             ← Prowler + KEV/EPSS/NVD collect + enrich + ledger (stdlib)
│   ├── evidence.py            ← append-only hash-chained + signed evidence log (stdlib core)
│   └── run.py                 ← orchestrator: collect → triage → floor → sign → post → mark
└── state/                     ← runtime ledger + evidence log live here (git-ignored)
```
