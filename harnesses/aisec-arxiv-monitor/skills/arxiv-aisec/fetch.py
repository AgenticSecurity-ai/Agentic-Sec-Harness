#!/usr/bin/env python3
# Copyright (C) 2026 Isao Takaesu
# SPDX-License-Identifier: AGPL-3.0-or-later
"""arXiv AI-security monitor fetcher.

Stdlib only (requires Python 3.11+ for tomllib). No third-party deps, no secrets.

Subcommands:
  fetch                 Print JSON {generated_at, items:[...]} of NEW (unseen) papers.
  mark <id> [<id>...]   Record arXiv ids as seen (call AFTER successful posting).
  seen-count            Print how many ids are currently recorded as seen.

Layout assumption (workspace-local skill):
  <workspace>/config.toml
  <workspace>/state/seen.json
  <workspace>/skills/arxiv-aisec/fetch.py   <- this file

Override paths with --config and --state if needed.
"""
import sys
import os
import json
import time
import random
import argparse
import tomllib
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta

ATOM = "{http://www.w3.org/2005/Atom}"
ARXIV_NS = "{http://arxiv.org/schemas/atom}"
API = "https://export.arxiv.org/api/query"  # https direct; http 301-redirects under load
RATE_LIMIT_SECONDS = 3.0  # arXiv ToU: no more than 1 request / 3 sec

# Resilience to transient arXiv export API degradation (429 / 5xx / read timeout).
# The export API intermittently rate-limits or returns 503/timeout for heavy
# queries under load; a single cron run that hits a blip would otherwise skip the
# whole day (recovered next run via the dedup ledger, but stale). Bounded retry
# with exponential backoff + jitter lets a run ride out a transient blip and fetch
# same-day. It does NOT mask a real outage — once retries exhaust, the query fails
# and that query's items stay unmarked for the next run, exactly as before.
HTTP_TIMEOUT_SECONDS = 60        # was 30; heavy OR-queries are slow under load
MAX_RETRIES = 4                  # total attempts = MAX_RETRIES + 1
BACKOFF_BASE_SECONDS = 2.0       # delay ≈ BASE * 2**attempt (+ jitter), capped
MAX_BACKOFF_SECONDS = 60.0
JITTER_SECONDS = 1.0
RETRYABLE_STATUS = {429, 500, 502, 503, 504}

# workspace = two levels up from this file's dir (skills/arxiv-aisec/ -> workspace)
SKILL_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.abspath(os.path.join(SKILL_DIR, "..", ".."))


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


def base_id(raw_id):
    # http://arxiv.org/abs/2401.12345v2 -> 2401.12345
    tail = raw_id.rstrip("/").split("/")[-1]
    if "v" in tail:
        head, _, ver = tail.rpartition("v")
        if ver.isdigit():
            return head
    return tail


def parse_entries(xml_text):
    root = ET.fromstring(xml_text)
    out = []
    for e in root.findall(f"{ATOM}entry"):
        raw_id = (e.findtext(f"{ATOM}id") or "").strip()
        if not raw_id:
            continue
        aid = base_id(raw_id)
        title = " ".join((e.findtext(f"{ATOM}title") or "").split())
        summary = " ".join((e.findtext(f"{ATOM}summary") or "").split())
        published = (e.findtext(f"{ATOM}published") or "").strip()
        updated = (e.findtext(f"{ATOM}updated") or "").strip()
        authors = [
            (a.findtext(f"{ATOM}name") or "").strip()
            for a in e.findall(f"{ATOM}author")
        ]
        cats = [
            c.attrib.get("term", "")
            for c in e.findall(f"{ATOM}category")
        ]
        abs_link = ""
        pdf_link = ""
        for l in e.findall(f"{ATOM}link"):
            if l.attrib.get("rel") == "alternate":
                abs_link = l.attrib.get("href", "")
            if l.attrib.get("title") == "pdf":
                pdf_link = l.attrib.get("href", "")
        out.append({
            "id": aid,
            "title": title,
            "authors": authors,
            "summary": summary,
            "published": published,
            "updated": updated,
            "categories": cats,
            "abs_url": abs_link or f"https://arxiv.org/abs/{aid}",
            "pdf_url": pdf_link,
        })
    return out


def _log(msg):
    """Progress to stderr (flushed); stdout is reserved for the JSON result so the
    orchestrator can parse it. Lets a manual or cron run show what's happening."""
    print(msg, file=sys.stderr, flush=True)


def _retry_delay(attempt, exc=None):
    """Backoff for retry `attempt` (0-based). Honors Retry-After on HTTP 429/503
    when given as integer seconds; otherwise exponential backoff. Adds jitter and
    caps the total to avoid runaway waits."""
    delay = min(MAX_BACKOFF_SECONDS, BACKOFF_BASE_SECONDS * (2 ** attempt))
    if isinstance(exc, urllib.error.HTTPError):
        retry_after = exc.headers.get("Retry-After")
        if retry_after:
            try:  # Retry-After may be int seconds or an HTTP-date; only honor seconds
                delay = max(delay, float(int(retry_after)))
            except ValueError:
                pass
    return min(MAX_BACKOFF_SECONDS, delay) + random.uniform(0, JITTER_SECONDS)


def query_arxiv(query, max_results):
    url = API + "?" + urllib.parse.urlencode({
        "search_query": query,
        "sortBy": "submittedDate",
        "sortOrder": "descending",
        "max_results": max_results,
    })
    req = urllib.request.Request(url, headers={"User-Agent": "aisec-arxiv-monitor/1.0"})
    for attempt in range(MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as r:
                return r.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            # HTTPError subclasses URLError, so catch it first. Retry only transient
            # statuses (rate-limit / server errors); 4xx like 400 are query bugs -> raise.
            if e.code in RETRYABLE_STATUS and attempt < MAX_RETRIES:
                delay = _retry_delay(attempt, e)
                print(f"[warn] arXiv HTTP {e.code}; retry "
                      f"{attempt + 1}/{MAX_RETRIES} in {delay:.1f}s", file=sys.stderr)
                time.sleep(delay)
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            # Read timeout / connection reset: transient, retry until exhausted.
            if attempt < MAX_RETRIES:
                delay = _retry_delay(attempt)
                print(f"[warn] arXiv {type(e).__name__} ({e}); retry "
                      f"{attempt + 1}/{MAX_RETRIES} in {delay:.1f}s", file=sys.stderr)
                time.sleep(delay)
                continue
            raise


def cmd_fetch(cfg, seen_path):
    arx = cfg.get("arxiv", {})
    queries = arx.get("queries", [])
    max_results = int(arx.get("max_results", 30))
    lookback_days = int(arx.get("lookback_days", 7))

    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    seen = load_seen(seen_path)

    n = len(queries)
    _log(f"[fetch] {n} quer{'y' if n == 1 else 'ies'} | max_results={max_results} "
         f"| lookback={lookback_days}d | seen-ledger={len(seen)}")

    merged = {}
    failures = 0
    for i, q in enumerate(queries):
        if i > 0:
            _log(f"[fetch] rate-limit pause {RATE_LIMIT_SECONDS:.0f}s (arXiv ToU)")
            time.sleep(RATE_LIMIT_SECONDS)  # arXiv ToU: 1 request / 3 sec
        _log(f"[fetch] query {i + 1}/{n}: requesting newest {max_results} ...")
        try:
            xml_text = query_arxiv(q, max_results)
        except Exception as exc:  # network/parse resilience: report, keep going
            failures += 1
            print(f"[warn] query {i + 1}/{n} failed after retries: {exc}", file=sys.stderr)
            continue
        got = parse_entries(xml_text)
        for item in got:
            merged[item["id"]] = item  # dedupe across queries
        _log(f"[fetch] query {i + 1}/{n}: {len(got)} returned "
             f"| {len(merged)} unique so far")

    fresh = []
    for item in merged.values():
        if item["id"] in seen:
            continue
        try:
            pub = datetime.fromisoformat(item["published"].replace("Z", "+00:00"))
            if pub < cutoff:
                continue
        except ValueError:
            pass
        fresh.append(item)

    fresh.sort(key=lambda x: x["published"], reverse=True)

    _log(f"[fetch] done: {len(merged)} unique -> {len(fresh)} new "
         f"(after seen + {lookback_days}d-window filter)"
         + (f" | WARNING {failures}/{n} queries failed" if failures else ""))

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
    ap = argparse.ArgumentParser(description="arXiv AI-security monitor fetcher")
    ap.add_argument("--config", default=os.path.join(WORKSPACE, "config.toml"))
    ap.add_argument("--state", default=os.path.join(WORKSPACE, "state", "seen.json"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fetch")
    p_mark = sub.add_parser("mark")
    p_mark.add_argument("ids", nargs="+")
    sub.add_parser("seen-count")
    args = ap.parse_args()

    if args.cmd == "fetch":
        cmd_fetch(load_config(args.config), args.state)
    elif args.cmd == "mark":
        cmd_mark(args.ids, args.state)
    elif args.cmd == "seen-count":
        cmd_seen_count(args.state)


if __name__ == "__main__":
    main()
