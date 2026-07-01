#!/usr/bin/env python3
# Copyright (C) 2026 Isao Takaesu
# SPDX-License-Identifier: AGPL-3.0-or-later
"""aisec-vulntriage collector — Phase 1-2 (collect + enrich), read-only.

Stdlib only (requires Python 3.11+ for tomllib) plus the pinned Prowler CLI. No
third-party Python deps, no secrets.

WHAT IT DOES (DESIGN.md §4 steps 1-2):
  1. Runs Prowler (read-only CSPM) over the configured AWS scope and reads its
     JSON-OCSF output.
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
  collect                 Print JSON {generated_at, new_count, items:[...]} of NEW
                          (unseen) findings. Runs Prowler unless --prowler-output
                          is given (then it reads that captured OCSF file instead —
                          a read-only dry run with no AWS calls).
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
import random
import shutil
import argparse
import tempfile
import tomllib
import subprocess
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

    return {
        "id": fid,
        "source": "prowler",
        "check_id": check_id,
        "title": " ".join(str(title).split()),
        "severity": severity,
        "status": rec.get("status_code", ""),
        "account": account,
        "region": res.get("region") or cloud.get("region", ""),
        "resource": res.get("uid", ""),
        "resource_type": res.get("type", ""),
        "resource_name": res.get("name", ""),
        # Untrusted publisher/environment text — for the tool-less LLM only, fenced
        # as DATA by the orchestrator. Never interpreted as a command here.
        "description": " ".join(str(desc).split()),
        "risk": " ".join(str(risk).split()),
        "remediation": " ".join(str(remediation_text).split()),
        "internet_exposed": internet_exposed,
        "cve_ids": cve_ids,
        # Intel enrichment filled in by enrich(); defaults keep the schema stable
        # even when a finding carries no CVE.
        "kev": {},
        "epss": {},
        "nvd": {},
    }


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


def cmd_collect(cfg, seen_path, prowler_bin, aws_profile, prowler_output):
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
    items = list(by_id.values())
    _log(f"[collect] {len(items)} finding(s) after status/severity filter "
         f"(ledger has {len(seen)} seen)")

    fresh = [it for it in items if it["id"] not in seen]
    _log(f"[collect] {len(fresh)} NEW finding(s) after dedup ledger")

    fresh = enrich(fresh, cfg)

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
    fresh.sort(key=_key, reverse=True)

    print(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "new_count": len(fresh),
        "items": fresh,
    }, ensure_ascii=False, indent=2))


def cmd_mark(ids, seen_path):
    seen = load_seen(seen_path)
    before = len(seen)
    seen.update(ids)
    save_seen(seen_path, seen)
    print(f"marked {len(seen) - before} new id(s); total seen={len(seen)}")


def cmd_seen_count(seen_path):
    print(len(load_seen(seen_path)))


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
    p_mark = sub.add_parser("mark")
    p_mark.add_argument("ids", nargs="+")
    sub.add_parser("seen-count")
    args = ap.parse_args()

    if args.cmd == "collect":
        cfg = load_config(args.config)
        prowler_bin = os.environ.get("PROWLER_BIN", "prowler")
        aws_profile = (os.environ.get("VULNTRIAGE_AWS_PROFILE")
                       or cfg.get("aws", {}).get("profile", "") or "")
        cmd_collect(cfg, args.state, prowler_bin, aws_profile, args.prowler_output)
    elif args.cmd == "mark":
        cmd_mark(args.ids, args.state)
    elif args.cmd == "seen-count":
        cmd_seen_count(args.state)


if __name__ == "__main__":
    main()
