#!/usr/bin/env python3
# Copyright (C) 2026 Isao Takaesu
# SPDX-License-Identifier: AGPL-3.0-or-later
"""aisec-vulntriage collector — Phase 1-2 (collect + enrich), read-only.

Stdlib only (requires Python 3.11+ for tomllib) plus the pinned Prowler CLI and,
optionally, the pinned Trivy CLI (stage 3, off by default). No third-party Python
deps, no secrets.

WHAT IT DOES (DESIGN.md §4 steps 1-2):
  1. Runs Prowler (read-only CSPM) over the configured AWS scope and reads its
     JSON-OCSF output. When [trivy].enabled (stage 3, DESIGN §13), also runs Trivy
     over the configured images and merges its CVE findings. When
     [defectdojo].enabled (stage 3, DESIGN §14), also IMPORTS open findings from a
     DefectDojo instance over its REST API — a system-of-record aggregating many
     scanners — read-only, honoring DefectDojo's own human triage state.
  2. Normalizes each finding to a common schema, de-duplicates against the ledger,
     extracts any referenced CVE ids, and enriches them from free public intel
     feeds (CISA KEV membership, FIRST EPSS score, optionally NVD CVSS).
  3. Emits the NEW (unseen) findings as JSON on stdout for the orchestrator, which
     hands them to the tool-less triage LLM.

SECURITY (DESIGN.md §3):
  - Everything here is deterministic tier-1 (read-only) work. No LLM is called; no
    account state is mutated. Prowler runs under a read-only IAM role.
  - The findings this emits (resource names, CVE text, remediation prose) are
    UNTRUSTED input — they can carry indirect prompt injection — and are marked as
    such for the orchestrator, which fences them as DATA before the tool-less LLM
    ever sees them. This collector does not interpret finding text as instructions.

Subcommands:
  collect                 Print JSON {generated_at, new_count, total_count,
                          include_seen, items:[...]} of NEW (unseen) findings. Runs
                          Prowler unless --prowler-output is given (then it reads that
                          captured OCSF file instead — a read-only dry run with no AWS
                          calls). With --include-seen it emits EVERY currently-open
                          finding (each tagged "seen") for the weekly full re-digest;
                          this changes only what is EMITTED, never the ledger.
  mark <id> [<id>...]     Record finding ids as handled (call AFTER a successful
                          post, per the post-then-mark ledger contract).
  seen-count              Print how many finding ids are currently recorded as seen.

Layout assumption (workspace-local skill):
  <workspace>/config.toml
  <workspace>/state/seen.json
  <workspace>/skills/aisec-vulntriage/collect.py   <- this file

Override paths with --config and --state if needed.
"""
import os
import re
import sys
import json
import time
import base64
import random
import shutil
import argparse
import tempfile
import tomllib
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone

USER_AGENT = "aisec-vulntriage/1.0 (+https://github.com/AgenticSecurity-ai)"

# Free public intel feeds. All read-only, unauthenticated, public.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"                       # ?cve=CVE-...,CVE-...
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"          # ?cveId=CVE-...

# Politeness / batching for the intel feeds.
EPSS_BATCH = 100          # EPSS API accepts a comma list; keep the query string sane
NVD_SLEEP_SECONDS = 6.5   # NVD unauthenticated limit is 5 req / 30s -> ~1 per 6s

# HTTP resilience for the intel feeds (transient rate-limit / server blips). Same
# shape as the monitors' fetch.py: bounded retry, exponential backoff + jitter,
# honoring Retry-After. Exhausted retries raise (the caller degrades gracefully).
HTTP_TIMEOUT_SECONDS = 60
MAX_RETRIES = 4                  # total attempts = MAX_RETRIES + 1
BACKOFF_BASE_SECONDS = 2.0
MAX_BACKOFF_SECONDS = 60.0
JITTER_SECONDS = 1.0
RETRYABLE_STATUS = {429, 500, 502, 503, 504}

# How long Prowler may run before we give up (a full-account scan can be slow;
# scope it down in config.toml to stay well under this).
PROWLER_TIMEOUT_SECONDS = 1800

# How long a single Trivy image scan (pull + analyze) may run before we give up.
TRIVY_TIMEOUT_SECONDS = 600

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Heuristic internet-exposure signal derived from a Prowler check id / title. This
# is a coarse flag, NOT a real reachability proof — path-based exposure ("toxic
# combination") is a roadmap stage-2 feature (Cartography). See DESIGN §10.
EXPOSURE_HINTS = (
    "public", "internet", "0.0.0.0", "exposed", "unrestricted",
    "world", "anonymous", "publicly",
)

VALID_SEVERITIES = ("critical", "high", "medium", "low", "informational")

# workspace = two levels up from this file's dir (skills/aisec-vulntriage/ -> workspace)
SKILL_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.abspath(os.path.join(SKILL_DIR, "..", ".."))


# --------------------------------------------------------------------------- #
# config + dedup ledger                                                        #
# --------------------------------------------------------------------------- #
def load_config(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def load_seen(path):
    if not os.path.exists(path):
        return set()
    try:
        with open(path) as f:
            data = json.load(f)
        return set(data.get("seen", []))
    except (json.JSONDecodeError, OSError):
        return set()


def save_seen(path, seen):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"seen": sorted(seen)}, f, indent=2)
    os.replace(tmp, path)


def _log(msg):
    """Progress to stderr (flushed); stdout is reserved for the JSON result so the
    orchestrator can parse it. Lets a manual or cron run show what's happening."""
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# HTTP helper (intel feeds)                                                    #
# --------------------------------------------------------------------------- #
def _retry_delay(attempt, exc=None):
    """Backoff for retry `attempt` (0-based). Honors Retry-After on 429/503 when
    given as integer seconds; otherwise exponential backoff with jitter, capped."""
    delay = min(MAX_BACKOFF_SECONDS, BACKOFF_BASE_SECONDS * (2 ** attempt))
    if isinstance(exc, urllib.error.HTTPError):
        retry_after = exc.headers.get("Retry-After")
        if retry_after:
            try:
                delay = max(delay, float(int(retry_after)))
            except ValueError:
                pass
    return min(MAX_BACKOFF_SECONDS, delay) + random.uniform(0, JITTER_SECONDS)


def http_get_json(url):
    """GET a URL and parse JSON, with bounded retry on transient failures. Raises
    on exhausted retries or a non-retryable status (the caller degrades)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as r:
                return json.loads(r.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code in RETRYABLE_STATUS and attempt < MAX_RETRIES:
                delay = _retry_delay(attempt, e)
                _log(f"[warn] intel HTTP {e.code}; retry "
                     f"{attempt + 1}/{MAX_RETRIES} in {delay:.1f}s")
                time.sleep(delay)
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < MAX_RETRIES:
                delay = _retry_delay(attempt)
                _log(f"[warn] intel {type(e).__name__} ({e}); retry "
                     f"{attempt + 1}/{MAX_RETRIES} in {delay:.1f}s")
                time.sleep(delay)
                continue
            raise


# --------------------------------------------------------------------------- #
# Neo4j / Cartography graph context (stage 2, DESIGN §12)                      #
#                                                                              #
# The asset graph lives in Neo4j, populated by Cartography (an external CLI, in #
# the same "external tool" category as Prowler — see DESIGN §12.3). We query it #
# over Neo4j's HTTP transactional Cypher endpoint using pure-stdlib urllib +    #
# basic-auth, deliberately NOT the third-party `neo4j` bolt driver, to keep the #
# harness stdlib-only. This is orchestrator work: the returned facts are        #
# collector-authoritative (never LLM-authored), exactly like KEV/EPSS.         #
# --------------------------------------------------------------------------- #
class Neo4jError(RuntimeError):
    """Neo4j returned a Cypher/statement error, or the endpoint was unreachable
    after retries. Callers degrade gracefully (graph facts become unavailable and
    findings fall back to the v1 keyword exposure flag — DESIGN §12.4)."""


def neo4j_cypher(endpoint, user, password, statement, params=None,
                 database="neo4j"):
    """Run one Cypher statement over Neo4j's HTTP transactional endpoint and return
    its rows as a list of dicts (column name -> value). Bounded retry on transient
    HTTP failures (same backoff as the intel feeds); raises Neo4jError on a Cypher
    error or exhausted retries so the caller can degrade."""
    url = f"{endpoint.rstrip('/')}/db/{database}/tx/commit"
    body = json.dumps({"statements": [
        {"statement": statement, "parameters": params or {}}]}).encode("utf-8")
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Basic {token}",
        "User-Agent": USER_AGENT,
    })
    for attempt in range(MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as r:
                doc = json.loads(r.read().decode("utf-8", errors="replace"))
            break
        except urllib.error.HTTPError as e:
            # 401/403 (bad creds) and other 4xx are not retried — fail fast.
            if e.code in RETRYABLE_STATUS and attempt < MAX_RETRIES:
                delay = _retry_delay(attempt, e)
                _log(f"[warn] neo4j HTTP {e.code}; retry "
                     f"{attempt + 1}/{MAX_RETRIES} in {delay:.1f}s")
                time.sleep(delay)
                continue
            raise Neo4jError(f"neo4j HTTP {e.code} at {url}: {e.reason}")
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < MAX_RETRIES:
                delay = _retry_delay(attempt)
                _log(f"[warn] neo4j {type(e).__name__} ({e}); retry "
                     f"{attempt + 1}/{MAX_RETRIES} in {delay:.1f}s")
                time.sleep(delay)
                continue
            raise Neo4jError(f"neo4j unreachable at {url}: {e}")
    else:  # pragma: no cover - loop always breaks or raises above
        raise Neo4jError(f"neo4j request to {url} exhausted retries")

    if doc.get("errors"):
        first = doc["errors"][0]
        raise Neo4jError(f"cypher error {first.get('code')}: {first.get('message')}")
    result = (doc.get("results") or [{}])[0]
    cols = result.get("columns", [])
    return [dict(zip(cols, row.get("row", []))) for row in result.get("data", [])]


# --------------------------------------------------------------------------- #
# DefectDojo REST API (stage 3, DESIGN §14) — authenticated read-only GET       #
#                                                                              #
# DefectDojo is a vulnerability system of record (it aggregates MANY scanners), #
# reached over its REST API with an `Authorization: Token <key>` header, NOT a   #
# subprocess. The token is a SECRET (host env VULNTRIAGE_DEFECTDOJO_TOKEN,       #
# convention #3) and the operator provisions a READ-ONLY (view-only) token, so   #
# the read-only guarantee holds by construction (§14.3). Same trust posture as   #
# every other collector: imported text is UNTRUSTED DATA for the tool-less LLM.  #
# --------------------------------------------------------------------------- #
class DefectDojoError(RuntimeError):
    """DefectDojo's REST API returned an auth/other 4xx error, or was unreachable
    after retries. Raised so a bad/expired token or a down instance surfaces LOUDLY
    rather than silently degrading to an empty finding set (which would read as
    "0 findings = clean"). The caller catches it, logs the degrade explicitly, and
    continues with the other collectors — mirrors neo4j_cypher's 401/403 fail-fast
    (DESIGN §14.3)."""


def defectdojo_get(url, token):
    """GET a DefectDojo REST URL with an `Authorization: Token` header and parse
    JSON. Bounded retry on transient failures (same backoff as the intel feeds);
    401/403 and any other non-retryable status fail fast as DefectDojoError (a bad
    token must not be retried or silently swallowed). Twin of http_get_json with an
    auth header and a typed error for fail-fast handling."""
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Authorization": f"Token {token}",
        "Accept": "application/json",
    })
    for attempt in range(MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as r:
                return json.loads(r.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code in RETRYABLE_STATUS and attempt < MAX_RETRIES:
                delay = _retry_delay(attempt, e)
                _log(f"[warn] defectdojo HTTP {e.code}; retry "
                     f"{attempt + 1}/{MAX_RETRIES} in {delay:.1f}s")
                time.sleep(delay)
                continue
            # 401/403 (bad/expired token) and other 4xx: do not retry — fail fast.
            raise DefectDojoError(f"DefectDojo HTTP {e.code} at {url}: {e.reason}")
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < MAX_RETRIES:
                delay = _retry_delay(attempt)
                _log(f"[warn] defectdojo {type(e).__name__} ({e}); retry "
                     f"{attempt + 1}/{MAX_RETRIES} in {delay:.1f}s")
                time.sleep(delay)
                continue
            raise DefectDojoError(f"DefectDojo unreachable at {url}: {e}")


# --------------------------------------------------------------------------- #
# Prowler                                                                      #
# --------------------------------------------------------------------------- #
def _verify_prowler_version(prowler_bin, pinned):
    """Refuse to run if the installed Prowler doesn't match the pinned version
    prefix (supply-chain hygiene). Empty `pinned` skips the check. Returns the
    reported version string for logging."""
    try:
        out = subprocess.run([prowler_bin, "--version"], capture_output=True,
                             text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError(f"cannot run '{prowler_bin} --version': {e}. "
                           "Is Prowler installed and on PATH (or set PROWLER_BIN)?")
    reported = (out.stdout + out.stderr).strip()
    # Extract the first version-looking token (e.g. "Prowler 5.5.0" -> "5.5.0").
    m = re.search(r"\d+\.\d+\.\d+", reported)
    version = m.group(0) if m else reported
    if pinned and not version.startswith(pinned):
        raise RuntimeError(
            f"Prowler version mismatch: installed '{version}' does not match "
            f"pinned '{pinned}' in config.toml [prowler].version. Install the "
            "pinned version or update the pin deliberately.")
    return version


def run_prowler(cfg, prowler_bin, aws_profile):
    """Run Prowler read-only over the configured scope and return the parsed
    JSON-OCSF finding list. Writes output to a temp dir that is cleaned up."""
    prow = cfg.get("prowler", {})
    aws = cfg.get("aws", {})
    _verify_prowler_version(prowler_bin, str(prow.get("version", "")).strip())

    outdir = tempfile.mkdtemp(prefix="prowler-vulntriage-")
    try:
        cmd = [prowler_bin, "aws",
               "--output-formats", "json-ocsf",
               "--output-directory", outdir,
               "--output-filename", "scan"]
        regions = aws.get("regions") or []
        if regions:
            cmd += ["--region", *regions]
        if aws_profile:
            cmd += ["--profile", aws_profile]
        services = prow.get("services") or []
        if services:
            cmd += ["--service", *services]
        compliance = prow.get("compliance") or []
        if compliance:
            cmd += ["--compliance", *compliance]

        _log(f"[prowler] running: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=PROWLER_TIMEOUT_SECONDS)
        # Prowler exits non-zero when it FINDS failing checks (exit 3), which is the
        # normal case here — so we do NOT treat a non-zero exit as an error. We only
        # fail if no output file was produced (a real invocation error).
        if proc.returncode not in (0, 3):
            _log(f"[prowler] exit {proc.returncode}; stderr tail: "
                 f"{proc.stderr[-500:]}")
        raw = _read_ocsf(outdir)
        _log(f"[prowler] parsed {len(raw)} finding record(s) from output")
        return raw
    finally:
        shutil.rmtree(outdir, ignore_errors=True)


def _read_ocsf(path):
    """Read the OCSF JSON Prowler wrote. `path` is a file or a directory; if a
    directory, pick the first *.ocsf.json / *.json inside it."""
    if os.path.isdir(path):
        cands = [f for f in os.listdir(path) if f.endswith((".ocsf.json", ".json"))]
        if not cands:
            raise RuntimeError(f"no JSON-OCSF output found in {path}")
        path = os.path.join(path, sorted(cands)[0])
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    # OCSF output is a JSON array of finding objects.
    return data if isinstance(data, list) else data.get("findings", [])


# --------------------------------------------------------------------------- #
# Trivy (stage 3, DESIGN §13) — image/package CVEs. Same trust posture as       #
# Prowler/Cartography: an external, pinned, deterministic subprocess whose JSON  #
# output is normalized to the common finding schema. Every Trivy finding IS a    #
# CVE, so these light up the KEV/EPSS/NVD enrichment that CSPM-only Prowler       #
# findings rarely trigger. Read-only and B2-preserving (§13.5).                  #
# --------------------------------------------------------------------------- #
def _verify_trivy_version(trivy_bin, pinned):
    """Refuse to run if the installed Trivy doesn't match the pinned version prefix
    (supply-chain hygiene — a surprise upgrade can change output shape). Empty
    `pinned` skips the check. Returns the reported version string. Twin of
    _verify_prowler_version."""
    try:
        out = subprocess.run([trivy_bin, "--version"], capture_output=True,
                             text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError(f"cannot run '{trivy_bin} --version': {e}. "
                           "Is Trivy installed and on PATH (or set TRIVY_BIN)?")
    reported = (out.stdout + out.stderr).strip()
    m = re.search(r"\d+\.\d+\.\d+", reported)
    version = m.group(0) if m else reported
    if pinned and not version.startswith(pinned):
        raise RuntimeError(
            f"Trivy version mismatch: installed '{version}' does not match pinned "
            f"'{pinned}' in config.toml [trivy].version. Install the pinned version "
            "or update the pin deliberately.")
    return version


def run_trivy_image(trivy_bin, image_ref):
    """Scan one image ref with Trivy and return the parsed JSON report (a dict with
    Results[]). Writes to a temp file that is cleaned up. We do NOT pass --exit-code,
    so a clean exit is expected even when vulnerabilities are found; a non-zero exit
    signals a real invocation/pull error, which we surface but only fail on if no
    output was produced (mirrors run_prowler's exit handling)."""
    outdir = tempfile.mkdtemp(prefix="trivy-vulntriage-")
    outfile = os.path.join(outdir, "scan.json")
    try:
        cmd = [trivy_bin, "image", "--quiet", "--format", "json",
               "--output", outfile, image_ref]
        _log(f"[trivy] running: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=TRIVY_TIMEOUT_SECONDS)
        if proc.returncode != 0:
            _log(f"[trivy] exit {proc.returncode} scanning {image_ref}; stderr tail: "
                 f"{proc.stderr[-500:]}")
        if not os.path.exists(outfile):
            raise RuntimeError(
                f"Trivy produced no output for {image_ref} (exit {proc.returncode})")
        return _read_trivy_json(outfile)
    finally:
        shutil.rmtree(outdir, ignore_errors=True)


def _read_trivy_json(path):
    """Read a Trivy JSON report file. Returns the parsed object (dict, or a list of
    reports if the captured file holds several). An empty or truncated file (Trivy
    killed mid-write, or a hand-edited capture) and invalid JSON are both raised as
    RuntimeError — NOT the bare json.JSONDecodeError (a ValueError). That distinction
    matters: collect_trivy's degrade-to-Prowler guard catches (RuntimeError, OSError)
    but deliberately not ValueError (which the ecr_discovery abort uses), so a bad
    report file must surface as RuntimeError to degrade cleanly instead of aborting
    the whole run with a JSON traceback."""
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    if not raw.strip():
        raise RuntimeError(f"Trivy output file {path} is empty (no scan result)")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Trivy output file {path} is not valid JSON: {e}")


# --------------------------------------------------------------------------- #
# common finding schema — the ONE shape every collector emits and every         #
# downstream step (enrich / sort / floor / graph / digest / evidence / ledger)  #
# consumes. Both normalizers (normalize_trivy below, normalize for Prowler)      #
# build it through make_finding so the field set + the stable intel/graph slots  #
# live in one place; each normalizer keeps only its source-specific extraction   #
# (id, cve ids, exposure heuristic) and passes the results here.                 #
# --------------------------------------------------------------------------- #
def make_finding(*, fid, source, check_id, title, severity, status,
                 account="", region="", resource="", resource_type="",
                 resource_name="", description="", risk="", remediation="",
                 internet_exposed=False, cve_ids=None):
    """Build one common-schema finding dict. Centralizes the field set and the
    intel/graph slots (kev/epss/nvd/graph always start as {}, filled in later by
    enrich()/graph_enrich()) so a schema change is made HERE, not duplicated per
    collector. The free-text fields (title/description/risk/remediation) carry
    UNTRUSTED publisher/environment text — DATA for the tool-less LLM only, fenced
    by the orchestrator, never interpreted as a command — and are whitespace-
    collapsed exactly as each normalizer did inline."""
    def _ws(s):
        return " ".join(str(s).split())
    return {
        "id": fid,
        "source": source,
        "check_id": check_id,
        "title": _ws(title),
        "severity": severity,
        "status": status,
        "account": account,
        "region": region,
        "resource": resource,
        "resource_type": resource_type,
        "resource_name": resource_name,
        "description": _ws(description),
        "risk": _ws(risk),
        "remediation": _ws(remediation),
        "internet_exposed": internet_exposed,
        "cve_ids": cve_ids or [],
        "kev": {},
        "epss": {},
        "nvd": {},
        "graph": {},
    }


def normalize_trivy(vuln, image_ref, target):
    """Map one Trivy vulnerability (Results[].Vulnerabilities[]) to the SAME common
    finding schema normalize() produces for Prowler, so every downstream step
    (enrich / sort / floor / graph / digest / evidence / ledger) consumes Trivy
    findings unchanged. Defensive .get chains: a shape drift degrades a field rather
    than crashing the run. Returns None for a record with no usable id."""
    vid = str(vuln.get("VulnerabilityID", "")).strip()
    pkg = str(vuln.get("PkgName", "")).strip()
    if not vid:
        return None
    # Stable dedup key: the CONFIGURED image ref (a floating tag like `app:latest` or a
    # digest-pinned ref) + target + package + id. We deliberately DO NOT key on the
    # image *digest* (Metadata.ImageID): a `:latest` rebuild mints a new digest even
    # when the same package still carries the same CVE, which would re-mint the id and
    # re-post an unchanged finding every rebuild — a violation of the idempotent-ledger
    # invariant (CLAUDE.md #5). Keying on the ref collapses those to one finding. The
    # trade-off (a CVE that is fixed then re-introduced under the same ref is not re-
    # notified on a daily run) mirrors Prowler's resolved→recurred constraint and is
    # covered by the weekly full re-digest (S1.7), which re-surfaces still-open findings.
    # The exact scanned digest is not lost — it is logged for provenance in collect_trivy.
    fid = f"trivy|{image_ref}|{target}|{pkg}|{vid}"

    severity = str(vuln.get("Severity", "")).strip().lower()
    if severity not in VALID_SEVERITIES:
        # Trivy emits UNKNOWN for unscored advisories; keep as '' (not dropped), like
        # normalize() does for an unrecognized Prowler severity.
        severity = ""

    # Only CVE-shaped ids reach the intel feeds. Trivy also emits GHSA / DLA / etc.;
    # those stay in the title (context for the LLM) but never go to KEV/EPSS/NVD.
    cve_ids = sorted({m.group(0).upper() for m in CVE_RE.finditer(vid)})

    installed = str(vuln.get("InstalledVersion", "")).strip()
    fixed = str(vuln.get("FixedVersion", "")).strip()
    title_txt = str(vuln.get("Title", "")).strip()
    title = f"{pkg} {vid} — {title_txt}" if title_txt else f"{pkg} {vid}"
    desc = str(vuln.get("Description", "")).strip()
    primary = str(vuln.get("PrimaryURL", "")).strip()
    refs = vuln.get("References") or []
    risk = primary or (str(refs[0]) if refs else "")
    remediation = (f"upgrade {pkg} {installed} → {fixed}" if fixed
                   else f"no fixed version available for {pkg} {installed}".strip())

    return make_finding(
        fid=fid,
        source="trivy",
        check_id=vid,
        title=title,
        severity=severity,
        # Every Trivy vulnerability is an open finding; there is no PASS/FAIL axis.
        status="FAIL",
        resource=image_ref,
        resource_type="container_image",
        resource_name=image_ref,
        description=desc,
        risk=risk,
        remediation=remediation,
        # The image itself has no network path; exposure/blast belong to the asset
        # RUNNING the image (a stage-2 graph join deferred for Trivy — DESIGN §13.4).
        internet_exposed=False,
        cve_ids=cve_ids,
    )


def _trivy_enabled(trivy_cfg):
    """Whether Stage-3 Trivy collection is on. A deployment flips it with the
    non-secret VULNTRIAGE_TRIVY_ENABLED env var (like the Discord channel id / the
    graph toggle, convention #3) WITHOUT editing the shipped default, which stays
    `[trivy].enabled=false` so self-hosters are unaffected. Env, when set non-empty,
    wins; otherwise fall back to [trivy].enabled. Twin of _graph_enabled."""
    env = os.environ.get("VULNTRIAGE_TRIVY_ENABLED")
    if env is not None and env.strip() != "":
        return env.strip().lower() in ("1", "true", "yes", "on")
    return bool(trivy_cfg.get("enabled", False))


def _coerce_reports(rep):
    """Coerce a parsed Trivy report into a list of dict reports. A Trivy JSON file can
    hold a single report (dict) or several (a top-level list); a hand-edited capture
    can also carry non-object junk. Return only the dict elements, logging and dropping
    anything else, so a shape drift degrades a field rather than crashing the scan loop
    with AttributeError on `rep.get(...)` (which would escape the degrade-to-Prowler
    guard and sink the whole run). Used by BOTH the live-scan and captured paths so the
    list case is handled symmetrically."""
    candidates = rep if isinstance(rep, list) else [rep]
    reports = []
    for r in candidates:
        if isinstance(r, dict):
            reports.append(r)
        else:
            _log(f"[trivy] skipping non-object report element "
                 f"(type {type(r).__name__})")
    return reports


def _trivy_reports(cfg, trivy_bin, trivy_output):
    """Yield (report_dict, image_ref) for each Trivy scan — from a captured file
    (--trivy-output, a read-only dry run with no scan) or by scanning each configured
    target image. Per-image scan failures are logged and skipped, never sinking the
    run (a bad pull leaves that image unmarked to retry, like a failed post)."""
    if trivy_output:
        _log(f"[trivy] reading captured Trivy output {trivy_output} "
             "(dry run; no scan)")
        for r in _coerce_reports(_read_trivy_json(trivy_output)):
            yield r, str(r.get("ArtifactName", "") or "captured-image")
        return

    tcfg = cfg.get("trivy", {})
    targets = tcfg.get("targets") or []
    if not targets:
        _log("[trivy] no [trivy].targets configured; nothing to scan")
        return
    version = _verify_trivy_version(trivy_bin, str(tcfg.get("version", "")).strip())
    _log(f"[trivy] Trivy {version}; scanning {len(targets)} target image(s)")
    for ref in targets:
        try:
            rep = run_trivy_image(trivy_bin, ref)
        except Exception as e:
            _log(f"[trivy] scan of {ref} failed, skipping: {e}")
            continue
        for r in _coerce_reports(rep):
            yield r, ref


def collect_trivy(cfg, trivy_bin, trivy_output=None):
    """Return normalized Trivy findings (common schema), coarse-filtered by
    [trivy].severities like the Prowler path. Empty list when Trivy is disabled and
    no captured output was given. These findings all carry a CVE, so cmd_collect
    merges them into the item list BEFORE enrich() to feed KEV/EPSS/NVD."""
    tcfg = cfg.get("trivy", {})
    if not (trivy_output or _trivy_enabled(tcfg)):
        return []
    # ecr_discovery is an unimplemented opt-in (DESIGN §13.3): S3.1 only scans the
    # explicit [trivy].targets, so ECR repos are never enumerated. Fail LOUD rather than
    # silently scanning nothing — a deployer who flips it believes their registry is being
    # covered, and letting the run proceed would let an unscanned ECR masquerade as
    # "0 findings = clean". This is an operator config mistake, not a transient setup
    # failure, so it is raised BEFORE the degrade-to-Prowler guard below and propagates up
    # to abort the run (ValueError, which that guard's RuntimeError/OSError does not catch;
    # main() turns it into a clean [error] line). A --trivy-output dry run reads a captured
    # report and never enumerates, so the check is skipped there.
    if not trivy_output and tcfg.get("ecr_discovery", False):
        raise ValueError(
            "[trivy].ecr_discovery=true is not implemented (DESIGN §13.3): no ECR "
            "repositories are enumerated, so the run would scan nothing and could hide an "
            "unscanned registry as clean. Set explicit [trivy].targets and unset "
            "ecr_discovery, or disable it.")
    # Coarse severity pre-filter. An explicit [trivy].severities wins; when it is
    # unset/empty we inherit [prowler].severities so Trivy isn't silently unfiltered
    # while Prowler is filtered (the two collectors' coarse gate stays symmetric). If
    # both are empty, keep everything (the `if wanted` guard below).
    sev = tcfg.get("severities") or cfg.get("prowler", {}).get("severities", [])
    wanted = [s.lower() for s in sev]
    items = []
    # A Trivy SETUP failure (binary missing / version-pin mismatch, raised by
    # _verify_trivy_version) must degrade to Prowler-only, not sink the whole run —
    # Trivy is an off-by-default add-on with the same graceful-degrade contract as a
    # down intel feed or an unreachable graph. (Per-image scan failures are already
    # caught inside _trivy_reports; this catches the one-time setup error before the
    # loop yields anything.)
    try:
        for rep, ref in _trivy_reports(cfg, trivy_bin, trivy_output):
            meta = rep.get("Metadata") or {}
            # Provenance only — the exact build assessed. NOT part of the dedup key
            # (see normalize_trivy): keying on the digest would re-post every unchanged
            # CVE on each `:latest` rebuild. Logged so the audit trail records which
            # image build produced these findings.
            digest = meta.get("ImageID") or meta.get("RepoDigests") or ""
            if isinstance(digest, list):
                digest = digest[0] if digest else ""
            _log(f"[trivy] scanned {ref} (digest {digest or 'unknown'})")
            for result in rep.get("Results") or []:
                if not isinstance(result, dict):
                    continue
                target = str(result.get("Target", ""))
                for vuln in result.get("Vulnerabilities") or []:
                    if not isinstance(vuln, dict):
                        continue
                    it = normalize_trivy(vuln, ref, target)
                    if it is None:
                        continue
                    # Keep unknown ('') severity rather than silently dropping it.
                    if wanted and it["severity"] and it["severity"] not in wanted:
                        continue
                    items.append(it)
    except (RuntimeError, OSError) as e:
        _log(f"[trivy] setup failed ({e}); degrading to Prowler-only "
             "(no Trivy findings this run)")
        return []
    _log(f"[trivy] {len(items)} finding(s) after severity filter")
    return items


# --------------------------------------------------------------------------- #
# DefectDojo (stage 3, DESIGN §14) — import from a system of record. Unlike      #
# Prowler/Trivy this is NOT a scanner the harness runs: it reads already-        #
# aggregated findings (from N upstream scanners) over the REST API. Every         #
# DefectDojo finding may carry a CVE, so — like Trivy — these light up the        #
# KEV/EPSS/NVD enrichment with no new floor logic. The one obligation the         #
# scanners don't have: DefectDojo carries HUMAN TRIAGE STATE, which the harness   #
# must respect (import only genuinely-open findings, never re-surface a finding   #
# a human already marked false-positive / risk-accepted — §14.4). Read-only and   #
# B2-preserving: imported free-text is the MOST untrusted source (§14.5).         #
# --------------------------------------------------------------------------- #

# DefectDojo intel numbers (its own epss_score/percentile) are DELIBERATELY
# ignored: the harness re-derives KEV/EPSS via enrich() so a single authoritative
# intel source governs the floor across ALL collectors (§14.4). CVEs come only
# from vulnerability_ids[] (+ the legacy `cve` field), filtered by CVE_RE.
MAX_DEFECTDOJO_PAGES = 200   # pagination safety cap (200 * page_size findings)
DEFECTDOJO_PAGE_SIZE = 100


def _defectdojo_open(f):
    """Whether a DefectDojo finding is genuinely OPEN and un-triaged, so importing
    it does not fight the org's own triage (DESIGN §14.4 — a HARD requirement). The
    live query already filters server-side; this re-checks defensively on both the
    live and captured (--defectdojo-output) paths. active must be true AND none of
    the disposition flags set."""
    return (bool(f.get("active"))
            and not bool(f.get("false_p"))
            and not bool(f.get("duplicate"))
            and not bool(f.get("is_mitigated"))
            and not bool(f.get("out_of_scope"))
            and not bool(f.get("risk_accepted")))


def normalize_defectdojo(finding, product_name=""):
    """Map one DefectDojo `/api/v2/findings/` result to the SAME common finding
    schema (via make_finding) every downstream step consumes. Returns None for a
    record with no usable id or one that is not genuinely open (defensive re-check of
    the triage state — §14.4). Defensive .get chains: a shape drift degrades a field
    rather than crashing the run."""
    fid_id = finding.get("id")
    if fid_id is None or str(fid_id).strip() == "":
        return None
    if not _defectdojo_open(finding):
        return None

    # Dedup key: DefectDojo's own integer finding id, namespaced. It is stable and
    # already deduplicated by DefectDojo's engine, making it the most robust key of
    # the three collectors (§14.4). Trade-off: wiping/rebuilding the instance resets
    # ids and re-notifies every still-open finding ONCE — same as a wiped seen.json.
    fid = f"defectdojo|{fid_id}"

    # CVEs from vulnerability_ids[] (+ legacy `cve`), CVE-shaped only. GHSA/CWE/other
    # advisory ids stay in the title/description for the LLM but never reach the feeds.
    raw_ids = []
    for v in finding.get("vulnerability_ids") or []:
        raw_ids.append(str(v.get("vulnerability_id", "")) if isinstance(v, dict)
                       else str(v))
    if finding.get("cve"):
        raw_ids.append(str(finding.get("cve")))
    cve_ids = sorted({m.group(0).upper()
                      for s in raw_ids for m in CVE_RE.finditer(s)})

    severity = str(finding.get("severity", "")).strip().lower()
    if severity in ("info", "informational"):
        severity = "informational"
    if severity not in VALID_SEVERITIES:
        severity = ""

    # check_id: the first vulnerability id if present (consistent with Trivy's vid),
    # else which scanner reported it (found_by provenance), else the namespaced id.
    found_by = finding.get("found_by") or []
    scanner = (", ".join(str(x) for x in found_by) if isinstance(found_by, list)
               else str(found_by)).strip()
    check_id = (raw_ids[0] if raw_ids else "") or scanner or f"DD-{fid_id}"

    comp_name = str(finding.get("component_name", "")).strip()
    comp_ver = str(finding.get("component_version", "")).strip()
    component = f"{comp_name} {comp_ver}".strip()

    return make_finding(
        fid=fid,
        source="defectdojo",
        check_id=check_id,
        title=str(finding.get("title", "")).strip() or check_id,
        severity=severity,
        # Only open findings reach here (filtered above); there is no PASS axis.
        status="FAIL",
        resource=component,
        resource_type="component",
        resource_name=product_name or comp_name or component,
        description=str(finding.get("description", "")).strip(),
        # impact, else references, as the risk narrative (both untrusted DATA).
        risk=str(finding.get("impact") or finding.get("references") or "").strip(),
        remediation=str(finding.get("mitigation", "")).strip(),
        # A DefectDojo finding is a component/CVE fact, not an asset-graph node; an
        # endpoints→exposure join is conceivable but deferred (§14.4), same posture
        # as Trivy's image-has-no-network-path.
        internet_exposed=False,
        cve_ids=cve_ids,
    )


def _defectdojo_enabled(dd_cfg):
    """Whether Stage-3 DefectDojo import is on. A deployment flips it with the
    non-secret VULNTRIAGE_DEFECTDOJO_ENABLED env var (like the graph / Trivy toggles,
    convention #3) WITHOUT editing the shipped default, which stays
    `[defectdojo].enabled=false` so self-hosters are unaffected. Env, when set non-
    empty, wins; otherwise fall back to [defectdojo].enabled. Twin of _trivy_enabled.
    (The API token is a SECRET and stays in the host env, never in config/.env — see
    VULNTRIAGE_DEFECTDOJO_TOKEN.)"""
    env = os.environ.get("VULNTRIAGE_DEFECTDOJO_ENABLED")
    if env is not None and env.strip() != "":
        return env.strip().lower() in ("1", "true", "yes", "on")
    return bool(dd_cfg.get("enabled", False))


def _read_defectdojo_json(path):
    """Read a captured DefectDojo findings JSON (a single `/api/v2/findings/` envelope
    or a list of them, from --defectdojo-output). An empty/invalid file raises
    DefectDojoError so collect_defectdojo degrades cleanly with a loud log rather than
    aborting the run with a JSON traceback (twin of _read_trivy_json's contract)."""
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    if not raw.strip():
        raise DefectDojoError(f"DefectDojo output file {path} is empty")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise DefectDojoError(f"DefectDojo output file {path} is not valid JSON: {e}")


def _defectdojo_query_params(dcfg):
    """Server-side filter for GET /api/v2/findings/: the triage-state gate (§14.4) plus
    optional scope. Client-side severity filtering + the defensive _defectdojo_open
    re-check still apply; these params just avoid pulling obviously-triaged findings."""
    params = {
        "active": "true", "false_p": "false", "duplicate": "false",
        "is_mitigated": "false", "out_of_scope": "false", "risk_accepted": "false",
        "limit": str(DEFECTDOJO_PAGE_SIZE),
    }
    if dcfg.get("verified_only"):
        params["verified"] = "true"
    # Optional scope filters (nested DRF lookups); ignored by DefectDojo if unset.
    if dcfg.get("product_id"):
        params["test__engagement__product"] = str(dcfg["product_id"])
    if dcfg.get("engagement_id"):
        params["test__engagement"] = str(dcfg["engagement_id"])
    tags = dcfg.get("tags") or []
    if tags:
        params["tags"] = ",".join(str(t) for t in tags)
    return params


def _defectdojo_findings(dcfg, output):
    """Return the raw list of DefectDojo finding dicts — from a captured envelope
    (--defectdojo-output; dry run, no network, no token) or by paging the live REST
    API via the `next` link until exhausted. Raises DefectDojoError on a bad file, a
    missing base_url/token, or an API failure (the caller degrades with a loud log)."""
    if output:
        _log(f"[defectdojo] reading captured findings envelope {output} "
             "(dry run; no network, no token)")
        raw = _read_defectdojo_json(output)
        envelopes = raw if isinstance(raw, list) else [raw]
        findings = []
        for env in envelopes:
            if isinstance(env, dict):
                findings.extend(env.get("results") or [])
        return findings

    base_url = str(dcfg.get("base_url", "")).strip().rstrip("/")
    if not base_url:
        raise DefectDojoError("[defectdojo].base_url is not set")
    token = os.environ.get("VULNTRIAGE_DEFECTDOJO_TOKEN", "")
    if not token:
        raise DefectDojoError(
            "VULNTRIAGE_DEFECTDOJO_TOKEN is unset — a read-only DefectDojo API token "
            "is required (host env, never config/.env; DESIGN §14.3)")
    query = urllib.parse.urlencode(_defectdojo_query_params(dcfg))
    url = f"{base_url}/api/v2/findings/?{query}"
    findings, pages = [], 0
    while url and pages < MAX_DEFECTDOJO_PAGES:
        doc = defectdojo_get(url, token)
        findings.extend(doc.get("results") or [])
        url = doc.get("next")
        pages += 1
    if url:
        _log(f"[defectdojo] stopped at {MAX_DEFECTDOJO_PAGES}-page safety cap; some "
             "findings not fetched — narrow scope in [defectdojo] (product/tags)")
    _log(f"[defectdojo] fetched {len(findings)} finding(s) across {pages} page(s)")
    return findings


def collect_defectdojo(cfg, output=None):
    """Return normalized DefectDojo findings (common schema), filtered to genuinely-
    open findings (§14.4) and coarse-filtered by [defectdojo].severities (inheriting
    [prowler].severities when unset — the §13.7-⑤ pattern). Empty list when disabled
    and no captured output was given. Like Trivy, these carry CVEs, so cmd_collect
    merges them BEFORE enrich(). A fetch failure degrades to the other collectors with
    a LOUD log — NOT a silent empty (which would read as "0 findings = clean")."""
    dcfg = cfg.get("defectdojo", {})
    if not (output or _defectdojo_enabled(dcfg)):
        return []
    sev = dcfg.get("severities") or cfg.get("prowler", {}).get("severities", [])
    wanted = [s.lower() for s in sev]
    try:
        raw_findings = _defectdojo_findings(dcfg, output)
    except (DefectDojoError, OSError) as e:
        _log(f"[defectdojo] fetch failed ({e}); DefectDojo findings absent this run "
             "(degrading to the other collectors — this is NOT '0 findings = clean'). "
             "Check VULNTRIAGE_DEFECTDOJO_TOKEN / [defectdojo].base_url / connectivity.")
        return []

    items, dropped_triaged = [], 0
    for f in raw_findings:
        if not isinstance(f, dict):
            continue
        if not _defectdojo_open(f):
            dropped_triaged += 1
            continue
        it = normalize_defectdojo(f, str(f.get("product_name", "")).strip())
        if it is None:
            continue
        # Keep unknown ('') severity rather than silently dropping it.
        if wanted and it["severity"] and it["severity"] not in wanted:
            continue
        items.append(it)
    _log(f"[defectdojo] {len(items)} open finding(s) after triage-state + severity "
         f"filter ({dropped_triaged} dropped as already-triaged/closed)")
    return items


# --------------------------------------------------------------------------- #
# normalization (OCSF -> common finding schema)                               #
# --------------------------------------------------------------------------- #
def _first_resource(rec):
    res = rec.get("resources") or []
    return res[0] if res else {}


def normalize(rec):
    """Map one Prowler JSON-OCSF record to the common finding schema. Defensive
    (.get chains + fallbacks) so a shape drift degrades a field rather than
    crashing the run. Returns None for records we can't identify."""
    finfo = rec.get("finding_info") or {}
    meta = rec.get("metadata") or {}
    cloud = rec.get("cloud") or {}
    account = (cloud.get("account") or {}).get("uid", "")
    res = _first_resource(rec)
    remediation = rec.get("remediation") or {}

    check_id = (meta.get("event_code")
                or (rec.get("unmapped") or {}).get("check_id")
                or finfo.get("uid", ""))
    # Stable dedup key: prefer Prowler's finding uid (stable across runs for the
    # same check+resource); fall back to a composite so we never lose an id.
    fid = (finfo.get("uid")
           or f"{check_id}|{account}|{res.get('region','')}|{res.get('uid','')}")
    if not fid:
        return None

    severity = str(rec.get("severity", "")).strip().lower()
    if severity not in VALID_SEVERITIES:
        severity = ""

    title = finfo.get("title") or check_id
    desc = finfo.get("desc") or rec.get("status_detail") or ""
    risk = rec.get("risk_details") or ""
    remediation_text = remediation.get("desc") or ""

    # CVE ids referenced anywhere in the finding's untrusted text.
    haystack = " ".join([str(title), str(desc), str(risk), str(remediation_text),
                         str(res.get("uid", "")), str(res.get("name", ""))])
    cve_ids = sorted({m.group(0).upper() for m in CVE_RE.finditer(haystack)})

    exposure_probe = f"{check_id} {title}".lower()
    internet_exposed = any(h in exposure_probe for h in EXPOSURE_HINTS)

    return make_finding(
        fid=fid,
        source="prowler",
        check_id=check_id,
        title=title,
        severity=severity,
        status=rec.get("status_code", ""),
        account=account,
        region=res.get("region") or cloud.get("region", ""),
        resource=res.get("uid", ""),
        resource_type=res.get("type", ""),
        resource_name=res.get("name", ""),
        description=desc,
        risk=risk,
        remediation=remediation_text,
        internet_exposed=internet_exposed,
        cve_ids=cve_ids,
    )


# --------------------------------------------------------------------------- #
# intel enrichment (KEV / EPSS / NVD)                                          #
# --------------------------------------------------------------------------- #
def fetch_kev():
    """Return the set of CVE ids in the CISA Known Exploited Vulnerabilities
    catalog. Single fetch. Returns an empty set on failure (enrichment degrades;
    the run still produces triage input)."""
    try:
        data = http_get_json(KEV_URL)
    except Exception as e:
        _log(f"[warn] KEV fetch failed, skipping KEV enrichment: {e}")
        return set()
    vulns = data.get("vulnerabilities") or []
    kev = {v.get("cveID", "").upper() for v in vulns if v.get("cveID")}
    _log(f"[enrich] KEV catalog: {len(kev)} CVEs")
    return kev


def fetch_epss(cve_ids):
    """Return {CVE: epss_score(float)} for the given ids via the FIRST EPSS API,
    batched. Missing/failed lookups are simply absent from the map."""
    out = {}
    ids = sorted(cve_ids)
    for i in range(0, len(ids), EPSS_BATCH):
        batch = ids[i:i + EPSS_BATCH]
        url = f"{EPSS_URL}?cve={','.join(batch)}"
        try:
            data = http_get_json(url)
        except Exception as e:
            _log(f"[warn] EPSS batch {i // EPSS_BATCH + 1} failed: {e}")
            continue
        for row in data.get("data") or []:
            cve = str(row.get("cve", "")).upper()
            try:
                out[cve] = float(row.get("epss"))
            except (TypeError, ValueError):
                pass
    _log(f"[enrich] EPSS: scored {len(out)}/{len(cve_ids)} CVE(s)")
    return out


def fetch_nvd(cve_ids):
    """Return {CVE: {cvss, severity, vector}} from NVD. One request per CVE, rate-
    limited (unauthenticated limit is 5 req / 30s). Off by default in config —
    only called when [enrich].nvd = true. Failures are skipped per-CVE."""
    out = {}
    ids = sorted(cve_ids)
    for n, cve in enumerate(ids):
        if n > 0:
            time.sleep(NVD_SLEEP_SECONDS)
        try:
            data = http_get_json(f"{NVD_URL}?cveId={cve}")
        except Exception as e:
            _log(f"[warn] NVD lookup {cve} failed: {e}")
            continue
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            continue
        metrics = ((vulns[0].get("cve") or {}).get("metrics") or {})
        # Prefer CVSS v3.1, then v3.0, then v2 — take the first available.
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                cd = entries[0].get("cvssData") or {}
                cvss = {
                    "cvss": cd.get("baseScore"),
                    "severity": (cd.get("baseSeverity")
                                 or entries[0].get("baseSeverity", "")),
                    "vector": cd.get("vectorString", ""),
                }
                break
        if cvss:
            out[cve] = cvss
    _log(f"[enrich] NVD: enriched {len(out)}/{len(cve_ids)} CVE(s)")
    return out


def enrich(items, cfg):
    """Attach KEV / EPSS / NVD intel to the per-finding CVE ids, per [enrich] config.
    Only fetches feeds when at least one finding references a CVE."""
    en = cfg.get("enrich", {})
    all_cves = sorted({c for it in items for c in it["cve_ids"]})
    if not all_cves:
        _log("[enrich] no CVE ids referenced by findings; skipping intel feeds "
             "(expected for CSPM-only v1 — CVE coverage grows with Trivy in stage 3)")
        return items

    _log(f"[enrich] {len(all_cves)} distinct CVE(s) referenced across findings")
    kev = fetch_kev() if en.get("kev", True) else set()
    epss = fetch_epss(all_cves) if en.get("epss", True) else {}
    nvd = fetch_nvd(all_cves) if en.get("nvd", False) else {}

    for it in items:
        for cve in it["cve_ids"]:
            if kev:
                it["kev"][cve] = cve in kev
            if cve in epss:
                it["epss"][cve] = epss[cve]
            if cve in nvd:
                it["nvd"][cve] = nvd[cve]
    return items


# --------------------------------------------------------------------------- #
# graph facts — exposure_path / blast_radius (stage 2, DESIGN §12.1/§12.4)     #
#                                                                              #
# Deterministic Cypher over the Cartography graph turns v1's keyword exposure  #
# GUESS into a graph-derived FACT, and grounds excess-privilege with a real    #
# blast-radius signal. These facts are collector-authoritative (like KEV/EPSS) #
# and — in stage 2.3 — will extend the deterministic priority floor. Stage 2.2 #
# (this code) builds the query capability + Cypher; the `graph-check` command   #
# exercises it. Wiring into the floor/rationale/schema is stage 2.3.           #
# --------------------------------------------------------------------------- #
OPEN_CIDR = "0.0.0.0/0"
# Node labels for which graph_facts() actually computes an exposure path. For a joined
# node of any OTHER type (an IAM principal, an RDS instance, …) the graph has no exposure
# opinion, so exposure_path.exposed stays None and the finding keeps the v1 keyword flag
# rather than being wrongly cleared to False.
EXPOSURE_MODELED_LABELS = {"EC2Instance", "EC2SecurityGroup", "S3Bucket"}


def graph_key(resource_uid):
    """Return (arn, fallback_id) join keys for a Prowler resource uid, per the S2.1
    validation (DESIGN §12.8). The uid is normally the ARN (primary key); the
    fallback id is its last path component (`…/i-abc` -> `i-abc`, `…/sg-abc` ->
    `sg-abc`), which is how Cartography keys EC2 instances/security-groups — they
    carry no `arn` property, so an ARN-only join would silently drop them."""
    uid = resource_uid or ""
    arn = uid if uid.startswith("arn:") else ""
    tail = uid.split("/")[-1] if "/" in uid else uid.split(":")[-1]
    return arn, tail


def _empty_facts():
    return {
        "joined": False, "join_by": None, "node_labels": [],
        "exposure_path": {"exposed": None, "reasons": []},
        "blast_radius": None,
    }


def _blast_from_rows(rows):
    """Aggregate the wildcard-privilege proxy over one or more IAM-principal rows into a
    single blast_radius dict. More than one row occurs when an EC2 instance assumes
    multiple roles (§12.10 bridge); the finding inherits the WORST case — admin_like if
    ANY role is, and the max wildcard-statement counts."""
    return {
        "admin_like": any((r.get("star") or 0) > 0 for r in rows),
        "star_action_stmts": max((r.get("star") or 0) for r in rows),
        "wildcard_service_stmts": max((r.get("wild") or 0) for r in rows),
        "allow_stmt_count": max((r.get("allow") or 0) for r in rows),
    }


def graph_facts(graph_cfg, password, findings):
    """Query the Cartography graph for exposure_path + blast_radius facts for each
    finding's resource, keyed as in graph_key(). Returns {finding_id: facts}. Raises
    Neo4jError if the graph is unreachable (the caller degrades — findings keep the
    v1 keyword exposure flag, DESIGN §12.4). A resource that simply isn't in the
    graph gets `joined=False` and no graph facts — the same graceful degrade."""
    endpoint = graph_cfg.get("neo4j_http_endpoint", "http://localhost:7474")
    user = graph_cfg.get("neo4j_user", "neo4j")
    database = graph_cfg.get("neo4j_database", "neo4j")

    def q(stmt, **params):
        return neo4j_cypher(endpoint, user, password, stmt, params, database)

    arns = sorted({a for f in findings if (a := graph_key(f["resource"])[0])})
    ids = sorted({graph_key(f["resource"])[1] for f in findings
                  if graph_key(f["resource"])[1]})

    # 1) node resolution — which keys actually exist in the graph, and as what.
    arn_labels, id_labels = {}, {}
    for row in q("UNWIND $arns AS a MATCH (n {arn:a}) RETURN a AS key, labels(n) AS l",
                 arns=arns):
        arn_labels.setdefault(row["key"], row["l"])
    for row in q("UNWIND $ids AS i MATCH (n {id:i}) RETURN i AS key, labels(n) AS l",
                 ids=ids):
        id_labels.setdefault(row["key"], row["l"])

    # 2) exposure inputs (bulk).
    open_sgs = {r["key"] for r in q(
        "MATCH (:IpRange {id:$cidr})-[:MEMBER_OF_IP_RULE]->(:IpPermissionInbound)"
        "-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup) "
        "RETURN DISTINCT sg.id AS key", cidr=OPEN_CIDR)}
    ec2 = {r["key"]: r for r in q(
        "UNWIND $ids AS iid MATCH (i:EC2Instance {id:iid}) "
        "OPTIONAL MATCH (i)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)"
        "<-[:MEMBER_OF_EC2_SECURITY_GROUP]-(:IpPermissionInbound)"
        "<-[:MEMBER_OF_IP_RULE]-(:IpRange {id:$cidr}) "
        "RETURN iid AS key, i.publicipaddress AS public_ip, count(DISTINCT sg) AS open_sg",
        ids=ids, cidr=OPEN_CIDR)}
    s3 = {r["key"]: r for r in q(
        "UNWIND $arns AS a MATCH (b:S3Bucket {arn:a}) RETURN a AS key, "
        "coalesce(b.anonymous_access,false) AS anon, "
        "coalesce(b.block_public_acls,false) AS bpa, "
        "coalesce(b.restrict_public_buckets,false) AS rpb", arns=arns)}

    # 3a) EC2 -> role bridge (DESIGN §12.10). An EC2 instance finding's own resource is not
    # an IAM principal, so its over-privilege lives on the role the instance assumes.
    # Cartography's normal sync models both the instance-profile path and a direct
    # assume-role edge, so we resolve each instance's attached role(s) here and inherit
    # their blast radius below. This is what lets the toxic-combination floor fire on an
    # exposed, over-privileged instance PER FINDING (was computed separately before).
    ec2_roles = {r["key"]: r["role_arns"] for r in q(
        "UNWIND $ids AS iid MATCH (i:EC2Instance {id:iid}) "
        "OPTIONAL MATCH (i)-[:INSTANCE_PROFILE]->(:AWSInstanceProfile)"
        "-[:ASSOCIATED_WITH]->(r1:AWSRole) "
        "OPTIONAL MATCH (i)-[:STS_ASSUMEROLE_ALLOW]->(r2:AWSRole) "
        "WITH iid, collect(DISTINCT r1.arn) + collect(DISTINCT r2.arn) AS ras "
        "RETURN iid AS key, [x IN ras WHERE x IS NOT NULL] AS role_arns", ids=ids)}

    # 3b) blast radius — for resources that ARE an IAM principal (role/user). Without
    # the opt-in permission_relationships mapping the graph has no CAN_ACCESS edges to
    # specific resources, so we use the strongest available proxy: wildcard-privilege
    # policy statements attached to the principal (DESIGN §12.8 records this limit). The
    # keyed arn set spans both finding-owned principals AND EC2-attached roles (3a).
    role_arns = {ra for lst in ec2_roles.values() for ra in lst}
    blast_arns = sorted(set(arns) | role_arns)
    blast = {r["key"]: r for r in q(
        "UNWIND $arns AS a MATCH (pr) WHERE pr.arn=a AND (pr:AWSRole OR pr:AWSUser) "
        "OPTIONAL MATCH (pr)-[:POLICY]->(:AWSPolicy)-[:STATEMENT]->"
        "(s:AWSPolicyStatement {effect:'Allow'}) "
        "WITH a, collect(s) AS ss RETURN a AS key, "
        "size([x IN ss WHERE any(act IN x.action WHERE act='*')]) AS star, "
        "size([x IN ss WHERE any(act IN x.action WHERE act ENDS WITH ':*')]) AS wild, "
        "size(ss) AS allow", arns=blast_arns)}

    out = {}
    for f in findings:
        arn, fid_key = graph_key(f["resource"])
        facts = _empty_facts()
        if arn and arn in arn_labels:
            facts["joined"], facts["join_by"], facts["node_labels"] = True, "arn", arn_labels[arn]
        elif fid_key and fid_key in id_labels:
            facts["joined"], facts["join_by"], facts["node_labels"] = True, "id", id_labels[fid_key]

        reasons = []
        # exposure: EC2 instance (public IP and/or open ingress), open SG, public S3.
        if fid_key in ec2:
            row = ec2[fid_key]
            if row.get("public_ip"):
                reasons.append(f"public_ip:{row['public_ip']}")
            if (row.get("open_sg") or 0) > 0:
                reasons.append("open_ingress_sg")
        if fid_key in open_sgs:
            reasons.append("open_ingress_sg")
        if arn in s3:
            row = s3[arn]
            if row.get("anon"):
                reasons.append("s3_anonymous_access")
            if not (row.get("bpa") and row.get("rpb")):
                reasons.append("s3_public_access_block_incomplete")
        if facts["joined"]:
            facts["exposure_path"]["reasons"] = reasons
            # Definite True/False only for the node types we model exposure for; None
            # ("no graph opinion") for everything else, so the caller keeps the keyword flag.
            modeled = any(l in EXPOSURE_MODELED_LABELS for l in facts["node_labels"])
            facts["exposure_path"]["exposed"] = bool(reasons) if modeled else None

        if arn in blast:
            facts["blast_radius"] = _blast_from_rows([blast[arn]])
        elif fid_key in ec2_roles and ec2_roles[fid_key]:
            # EC2 instance finding: inherit the blast radius of the role(s) it assumes via
            # the instance-profile / assume-role bridge (§12.10). `via_instance_role` keeps
            # the provenance honest in the signed evidence log — this privilege is the
            # instance's transitively, not its own.
            rows = [blast[ra] for ra in ec2_roles[fid_key] if ra in blast]
            if rows:
                facts["blast_radius"] = _blast_from_rows(rows)
                facts["blast_radius"]["via_instance_role"] = ec2_roles[fid_key]
        out[f["id"]] = facts
    return out


def _graph_enabled(graph_cfg):
    """Whether Stage-2 graph enrichment is on. A deployment can flip it with the
    VULNTRIAGE_GRAPH_ENABLED env var — a NON-SECRET deployment value, like the Discord
    channel id (convention #3) — WITHOUT editing the shipped config default, which stays
    `[graph].enabled=false` so self-hosters are unaffected and never need a live Neo4j.
    Env, when set to a non-empty value, wins; otherwise fall back to [graph].enabled.
    (The Neo4j password is a SECRET and stays in the host environment, never in config
    or .env — see VULNTRIAGE_NEO4J_PASSWORD.)"""
    env = os.environ.get("VULNTRIAGE_GRAPH_ENABLED")
    if env is not None and env.strip() != "":
        return env.strip().lower() in ("1", "true", "yes", "on")
    return bool(graph_cfg.get("enabled", False))


def graph_enrich(items, cfg):
    """Stage 2.3: when graph enrichment is enabled, attach Cartography graph facts to each
    and let the graph-derived exposure_path OVERRIDE the v1 keyword `internet_exposed`
    flag for the node types the graph models (EC2 instance / security group / S3 bucket).
    A joined node of any other type, an unjoined resource, a missing password, a disabled
    toggle, or an unreachable graph all degrade to the keyword flag — a graph outage never
    blocks or crashes a run (DESIGN §12.4).

    Graph facts are collector-authoritative, exactly like KEV/EPSS: the tool-less triage
    LLM never sets them and the deterministic priority floor (run.py) reads them, so a
    compromised LLM cannot talk a graph-confirmed toxic combination down."""
    gcfg = cfg.get("graph", {})
    if not _graph_enabled(gcfg):
        return items
    password = os.environ.get("VULNTRIAGE_NEO4J_PASSWORD", "")
    if not password:
        _log("[graph] [graph].enabled but VULNTRIAGE_NEO4J_PASSWORD is unset; "
             "degrading to the keyword exposure flag (DESIGN §12.4)")
        return items
    try:
        facts = graph_facts(gcfg, password, items)
    except Neo4jError as e:
        _log(f"[graph] graph unavailable ({e}); degrading to the keyword exposure flag")
        return items

    joined = overridden = exposed = admin = 0
    for it in items:
        gf = facts.get(it["id"])
        if not gf:
            continue
        it["graph"] = gf
        if not gf["joined"]:
            continue
        joined += 1
        exp = gf["exposure_path"]["exposed"]
        if exp is not None:  # graph modeled this node type -> it is authoritative
            if bool(exp) != bool(it["internet_exposed"]):
                overridden += 1
            it["internet_exposed"] = bool(exp)
            if exp:
                exposed += 1
        br = gf.get("blast_radius")
        if br and br.get("admin_like"):
            admin += 1
    _log(f"[graph] {joined}/{len(items)} finding(s) joined; exposure override on "
         f"{overridden} (graph exposed={exposed}); admin-like blast on {admin}")
    return items


# --------------------------------------------------------------------------- #
# commands                                                                     #
# --------------------------------------------------------------------------- #
def _severity_allowed(item, cfg):
    wanted = [s.lower() for s in cfg.get("prowler", {}).get("severities", [])]
    if not wanted:
        return True
    # Keep items whose severity is unknown ('') rather than silently dropping them.
    return item["severity"] == "" or item["severity"] in wanted


def _status_allowed(rec, cfg):
    wanted = cfg.get("prowler", {}).get("statuses", ["FAIL"])
    if not wanted:
        return True
    return rec.get("status_code", "") in wanted


def cmd_collect(cfg, seen_path, prowler_bin, aws_profile, prowler_output,
                include_seen=False, trivy_bin="trivy", trivy_output=None,
                defectdojo_output=None):
    seen = load_seen(seen_path)

    if prowler_output:
        _log(f"[collect] reading captured Prowler output {prowler_output} "
             "(dry run; no AWS calls)")
        raw = _read_ocsf(prowler_output)
        _log(f"[collect] parsed {len(raw)} finding record(s)")
    else:
        raw = run_prowler(cfg, prowler_bin, aws_profile)

    # Filter by status, normalize, filter by severity, de-dup by finding id.
    items, by_id = [], {}
    for rec in raw:
        if not _status_allowed(rec, cfg):
            continue
        item = normalize(rec)
        if item is None or not _severity_allowed(item, cfg):
            continue
        by_id.setdefault(item["id"], item)  # first record wins on dup id
    # Stage 3 (DESIGN §13): merge Trivy CVE findings into the same item list BEFORE
    # enrich(), so their CVEs feed KEV/EPSS/NVD. No-op when Trivy is disabled. Trivy
    # ids are namespaced ("trivy|…") so they never collide with Prowler finding uids.
    # A `--prowler-output` replay is a documented OFFLINE dry run ("no AWS calls"), so
    # it must NOT trigger live Trivy image pulls either — only include Trivy findings
    # from a captured `--trivy-output`. Otherwise (live Prowler run) collect Trivy live.
    if not (prowler_output and not trivy_output):
        for item in collect_trivy(cfg, trivy_bin, trivy_output):
            by_id.setdefault(item["id"], item)
    # Stage 3 (DESIGN §14): merge DefectDojo imported findings the same way, BEFORE
    # enrich(), ids namespaced ("defectdojo|…") so they never collide. Same offline-
    # replay guard as Trivy: a --prowler-output replay ("no AWS calls") must not trigger
    # a live DefectDojo fetch either — only include DefectDojo findings from a captured
    # --defectdojo-output. Otherwise (live run) import DefectDojo live.
    if not (prowler_output and not defectdojo_output):
        for item in collect_defectdojo(cfg, defectdojo_output):
            by_id.setdefault(item["id"], item)
    items = list(by_id.values())
    _log(f"[collect] {len(items)} finding(s) after status/severity filter "
         f"(ledger has {len(seen)} seen)")

    fresh = [it for it in items if it["id"] not in seen]
    _log(f"[collect] {len(fresh)} NEW finding(s) after dedup ledger")

    # Normally emit only the NEW findings. On a weekly full re-digest run (--include-seen)
    # emit EVERY currently-open finding so the orchestrator can re-surface still-open
    # findings the ledger would otherwise keep hidden forever. This changes only what is
    # EMITTED — the ledger is not touched here; mark is still driven by post-then-mark.
    emit = items if include_seen else fresh
    for it in emit:
        it["seen"] = it["id"] in seen
    if include_seen:
        _log(f"[collect] --include-seen: emitting all {len(emit)} open finding(s) "
             f"({len(fresh)} new, {len(emit) - len(fresh)} already-seen) for full re-digest")

    emit = enrich(emit, cfg)
    # Graph context (stage 2.3): overrides the keyword exposure flag with a graph-derived
    # exposure_path and attaches blast_radius, when [graph].enabled. No-op / graceful
    # degrade otherwise, so the sort + downstream floor keep working on the keyword flag.
    emit = graph_enrich(emit, cfg)

    # Sort so the most urgent surface first: KEV-listed, then higher EPSS, then
    # internet-exposed, then Prowler severity. (Deterministic ordering only — the
    # actual priority is the LLM's job.)
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0, "": 0}
    def _key(it):
        return (
            1 if any(it["kev"].get(c) for c in it["cve_ids"]) else 0,
            max([it["epss"].get(c, 0.0) for c in it["cve_ids"]] or [0.0]),
            1 if it["internet_exposed"] else 0,
            sev_rank.get(it["severity"], 0),
        )
    emit.sort(key=_key, reverse=True)

    print(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "new_count": len(fresh),
        "total_count": len(items),
        "include_seen": include_seen,
        "items": emit,
    }, ensure_ascii=False, indent=2))


def cmd_mark(ids, seen_path):
    seen = load_seen(seen_path)
    before = len(seen)
    seen.update(ids)
    save_seen(seen_path, seen)
    print(f"marked {len(seen) - before} new id(s); total seen={len(seen)}")


def cmd_seen_count(seen_path):
    print(len(load_seen(seen_path)))


def _findings_from_raw(raw, cfg):
    """Status/severity-filter + normalize + de-dup raw OCSF records into findings
    (the same pipeline cmd_collect uses, minus the ledger)."""
    by_id = {}
    for rec in raw:
        if not _status_allowed(rec, cfg):
            continue
        item = normalize(rec)
        if item is None or not _severity_allowed(item, cfg):
            continue
        by_id.setdefault(item["id"], item)
    return list(by_id.values())


def cmd_graph_check(cfg, prowler_bin, aws_profile, prowler_output):
    """Stage-2.2 validation tool: resolve each finding to its Cartography node and
    print the graph-derived exposure_path / blast_radius facts. Read-only; does NOT
    touch the ledger, post, or change triage — that wiring is stage 2.3."""
    graph_cfg = cfg.get("graph", {})
    password = os.environ.get("VULNTRIAGE_NEO4J_PASSWORD", "")
    if prowler_output:
        _log(f"[graph-check] reading captured Prowler output {prowler_output}")
        raw = _read_ocsf(prowler_output)
    else:
        raw = run_prowler(cfg, prowler_bin, aws_profile)
    findings = _findings_from_raw(raw, cfg)
    _log(f"[graph-check] {len(findings)} finding(s) after status/severity filter")

    try:
        facts = graph_facts(graph_cfg, password, findings)
    except Neo4jError as e:
        _log(f"[graph-check] graph unavailable ({e}); findings would degrade to the "
             "v1 keyword exposure flag (DESIGN §12.4)")
        return 1

    joined = exposed = admin = 0
    rows = []
    for f in findings:
        gf = facts.get(f["id"], _empty_facts())
        if gf["joined"]:
            joined += 1
        exp = gf["exposure_path"]["exposed"]
        if exp:
            exposed += 1
        br = gf["blast_radius"]
        if br and br["admin_like"]:
            admin += 1
        rows.append((f, gf, exp, br))

    print(f"graph-check: {len(findings)} findings | joined to graph: {joined} "
          f"| exposure_path=true: {exposed} | admin-like blast: {admin}")
    print("-" * 100)
    for f, gf, exp, br in rows:
        jb = gf["join_by"] or "-"
        label = (gf["node_labels"] or ["(unjoined)"])[0]
        exp_s = {True: "EXPOSED", False: "no", None: "?"}[exp]
        reasons = ",".join(gf["exposure_path"]["reasons"]) or "-"
        blast_s = "-"
        if br:
            blast_s = (f"admin={br['admin_like']} star={br['star_action_stmts']} "
                       f"wild={br['wildcard_service_stmts']} allow={br['allow_stmt_count']}")
        print(f"[{f['resource_type']:22s}] join={jb:3s} {label:20s} "
              f"exposure={exp_s:7s} ({reasons}) blast[{blast_s}]")
        print(f"    {f['resource'][:96]}")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="aisec-vulntriage collector (Prowler + KEV/EPSS/NVD, read-only)")
    ap.add_argument("--config", default=os.path.join(WORKSPACE, "config.toml"))
    ap.add_argument("--state", default=os.path.join(WORKSPACE, "state", "seen.json"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_collect = sub.add_parser("collect")
    p_collect.add_argument(
        "--prowler-output", default=None,
        help="Read this captured Prowler JSON-OCSF file/dir instead of running "
             "Prowler (read-only dry run; no AWS calls).")
    p_collect.add_argument(
        "--include-seen", action="store_true",
        help="Emit EVERY currently-open finding (each tagged \"seen\"), not just "
             "unseen ones, for the weekly full re-digest. Does not touch the ledger.")
    p_collect.add_argument(
        "--trivy-output", default=None,
        help="Read this captured Trivy JSON report file instead of scanning images "
             "(read-only dry run; no pull, no AWS). Merges its CVE findings alongside "
             "Prowler's. See DESIGN §13.")
    p_collect.add_argument(
        "--defectdojo-output", default=None,
        help="Read this captured DefectDojo /api/v2/findings/ JSON envelope instead of "
             "querying a live instance (read-only dry run; no network, no token). Merges "
             "its imported findings alongside the others. See DESIGN §14.")
    p_mark = sub.add_parser("mark")
    p_mark.add_argument("ids", nargs="+")
    sub.add_parser("seen-count")
    p_graph = sub.add_parser(
        "graph-check",
        help="Stage-2.2 validation: print graph-derived exposure_path / blast_radius "
             "facts per finding (read-only; needs a Cartography-populated Neo4j and "
             "VULNTRIAGE_NEO4J_PASSWORD). Does not post or touch the ledger.")
    p_graph.add_argument(
        "--prowler-output", default=None,
        help="Read this captured Prowler JSON-OCSF file/dir instead of running Prowler.")
    args = ap.parse_args()

    if args.cmd == "collect":
        cfg = load_config(args.config)
        prowler_bin = os.environ.get("PROWLER_BIN", "prowler")
        trivy_bin = os.environ.get("TRIVY_BIN", "trivy")
        aws_profile = (os.environ.get("VULNTRIAGE_AWS_PROFILE")
                       or cfg.get("aws", {}).get("profile", "") or "")
        try:
            cmd_collect(cfg, args.state, prowler_bin, aws_profile, args.prowler_output,
                        include_seen=args.include_seen, trivy_bin=trivy_bin,
                        trivy_output=args.trivy_output,
                        defectdojo_output=args.defectdojo_output)
        except ValueError as exc:
            # A collector config error (e.g. the ecr_discovery fail-loud) — abort with a
            # clean operator-facing message and a non-zero exit so run.py stops the run,
            # instead of dumping a traceback.
            sys.exit(f"[error] {exc}")
    elif args.cmd == "mark":
        cmd_mark(args.ids, args.state)
    elif args.cmd == "seen-count":
        cmd_seen_count(args.state)
    elif args.cmd == "graph-check":
        cfg = load_config(args.config)
        prowler_bin = os.environ.get("PROWLER_BIN", "prowler")
        aws_profile = (os.environ.get("VULNTRIAGE_AWS_PROFILE")
                       or cfg.get("aws", {}).get("profile", "") or "")
        sys.exit(cmd_graph_check(cfg, prowler_bin, aws_profile, args.prowler_output))


if __name__ == "__main__":
    main()
