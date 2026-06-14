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
import argparse
import tomllib
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta

ATOM = "{http://www.w3.org/2005/Atom}"
ARXIV_NS = "{http://arxiv.org/schemas/atom}"
API = "http://export.arxiv.org/api/query"
RATE_LIMIT_SECONDS = 3.0  # arXiv ToU: no more than 1 request / 3 sec

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


def query_arxiv(query, max_results):
    url = API + "?" + urllib.parse.urlencode({
        "search_query": query,
        "sortBy": "submittedDate",
        "sortOrder": "descending",
        "max_results": max_results,
    })
    req = urllib.request.Request(url, headers={"User-Agent": "aisec-arxiv-monitor/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8")


def cmd_fetch(cfg, seen_path):
    arx = cfg.get("arxiv", {})
    queries = arx.get("queries", [])
    max_results = int(arx.get("max_results", 30))
    lookback_days = int(arx.get("lookback_days", 7))
    cap = int(cfg.get("output", {}).get("max_posts_per_run", 10))

    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    seen = load_seen(seen_path)

    merged = {}
    for i, q in enumerate(queries):
        if i > 0:
            time.sleep(RATE_LIMIT_SECONDS)  # arXiv ToU: 1 request / 3 sec
        try:
            xml_text = query_arxiv(q, max_results)
        except Exception as exc:  # network/parse resilience: report, keep going
            print(f"[warn] query failed: {q!r}: {exc}", file=sys.stderr)
            continue
        for item in parse_entries(xml_text):
            merged[item["id"]] = item  # dedupe across queries

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
    fresh = fresh[:cap]

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
