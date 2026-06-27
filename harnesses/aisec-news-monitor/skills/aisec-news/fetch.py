#!/usr/bin/env python3
# Copyright (C) 2026 Isao Takaesu
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security-news (RSS/Atom) AI-security monitor fetcher.

Stdlib only (requires Python 3.11+ for tomllib). No third-party deps, no secrets.

This is a feed-reader-style consumer: it reads each publisher's officially-provided
RSS or Atom feed (same purpose as Feedly), normalizes every item to a common schema,
and hands the result to the orchestrator. It does NOT crawl or scrape article pages.

Subcommands:
  fetch                 Print JSON {generated_at, items:[...]} of NEW (unseen) articles.
  mark <id> [<id>...]   Record article ids as seen (call AFTER successful posting).
  seen-count            Print how many ids are currently recorded as seen.

Layout assumption (workspace-local skill):
  <workspace>/config.toml
  <workspace>/state/seen.json
  <workspace>/skills/aisec-news/fetch.py   <- this file

Override paths with --config and --state if needed.
"""
import sys
import os
import re
import json
import time
import html
import random
import argparse
import tomllib
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone, timedelta

# The Hacker News default feed (RSS 2.0). The site's native /feeds/posts/default
# 301-redirects here, so we target FeedBurner directly to avoid the extra hop.
DEFAULT_FEED = "https://feeds.feedburner.com/TheHackersNews"
USER_AGENT = "aisec-news-monitor/1.0 (feed reader; +https://github.com/AgenticSecurity-ai)"
RATE_LIMIT_SECONDS = 3.0  # polite spacing when more than one feed is configured

# Resilience to transient feed-host degradation (429 / 5xx / read timeout). A single
# cron run that hits a blip would otherwise skip the day (recovered next run via the
# dedup ledger, but stale). Bounded retry with exponential backoff + jitter lets a
# run ride out a transient blip. It does NOT mask a real outage — once retries
# exhaust, the feed fails and its items stay unmarked for the next run.
HTTP_TIMEOUT_SECONDS = 60
MAX_RETRIES = 4                  # total attempts = MAX_RETRIES + 1
BACKOFF_BASE_SECONDS = 2.0       # delay ≈ BASE * 2**attempt (+ jitter), capped
MAX_BACKOFF_SECONDS = 60.0
JITTER_SECONDS = 1.0
RETRYABLE_STATUS = {429, 500, 502, 503, 504}

# Namespaces we may encounter. dc:creator is an author fallback; content:encoded is
# a full-text body some RSS feeds use; the Atom namespace covers feeds served as Atom
# (e.g. Schneier on Security) rather than RSS 2.0.
DC_NS = "{http://purl.org/dc/elements/1.1/}"
CONTENT_NS = "{http://purl.org/rss/1.0/modules/content/}"
ATOM_NS = "{http://www.w3.org/2005/Atom}"

# Cap the excerpt handed to the LLM. Relevance judging + a <=140-char summary never
# need a full article, and several feeds (Krebs, The Register, IEEE Spectrum) ship the
# whole body in the feed — clipping keeps the per-article judging token cost roughly
# flat across short- and full-text feeds. It also reinforces the copyright posture: we
# only ever pass a short excerpt to the model, never the full piece.
EXCERPT_MAX_CHARS = 600

# workspace = two levels up from this file's dir (skills/aisec-news/ -> workspace)
SKILL_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.abspath(os.path.join(SKILL_DIR, "..", ".."))

_TAG_RE = re.compile(r"<[^>]+>")


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


def excerpt(text):
    """Collapse an HTML feed snippet to plain text and clip it to EXCERPT_MAX_CHARS.
    The feed body is the publisher's editorial excerpt / article text (their
    copyrighted expression); we only use it as UNTRUSTED input for the tool-less
    summarizer to judge + rewrite — it is never reposted verbatim (see run.py /
    README copyright notes), and we hand the model only a short, clipped excerpt."""
    text = _TAG_RE.sub(" ", text or "")
    text = " ".join(html.unescape(text).split())
    if len(text) > EXCERPT_MAX_CHARS:
        text = text[:EXCERPT_MAX_CHARS].rstrip() + "…"
    return text


def to_iso(datestr):
    """Normalize a feed date to UTC ISO 8601. Handles both RSS pubDate (RFC 822, e.g.
    'Sat, 27 Jun 2026 01:08:29 +0530') and Atom published/updated (ISO 8601, e.g.
    '2026-06-27T01:08:29Z'). Returns '' if unparseable so the caller keeps the item
    rather than silently dropping it."""
    if not datestr:
        return ""
    datestr = datestr.strip()
    dt = None
    try:
        dt = parsedate_to_datetime(datestr)              # RFC 822 (RSS)
    except (TypeError, ValueError):
        dt = None
    if dt is None:
        try:
            dt = datetime.fromisoformat(datestr.replace("Z", "+00:00"))  # ISO (Atom)
        except ValueError:
            return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _parse_rss(root):
    channel = root.find("channel")
    if channel is None:
        return []
    out = []
    for it in channel.findall("item"):
        link = (it.findtext("link") or "").strip()
        guid = (it.findtext("guid") or "").strip()
        # guid is the stable dedup key (isPermaLink=false on THN, but its value is
        # the canonical article URL); fall back to link if a feed omits guid.
        aid = guid or link
        if not aid:
            continue
        title = " ".join((it.findtext("title") or "").split())
        author = (it.findtext("author") or it.findtext(f"{DC_NS}creator") or "").strip()
        pubdate = (it.findtext("pubDate") or "").strip()
        # Prefer content:encoded (full body) when present, else description; either
        # way excerpt() clips it to EXCERPT_MAX_CHARS.
        body = it.findtext(f"{CONTENT_NS}encoded") or it.findtext("description") or ""
        out.append({
            "id": aid,
            "title": title,
            "author": author,
            "summary": excerpt(body),      # untrusted, clipped excerpt — for the LLM only
            "published": to_iso(pubdate),  # UTC ISO
            "pubdate_raw": pubdate,
            "url": link or aid,
        })
    return out


def _parse_atom(root):
    out = []
    for e in root.findall(f"{ATOM_NS}entry"):
        # Prefer the rel="alternate" link (the human article URL); a link with no rel
        # attribute defaults to "alternate".
        link = ""
        for l in e.findall(f"{ATOM_NS}link"):
            if l.attrib.get("rel", "alternate") == "alternate":
                link = l.attrib.get("href", "").strip()
                break
        eid = (e.findtext(f"{ATOM_NS}id") or "").strip()
        aid = eid or link  # Atom <id> is the stable dedup key; fall back to the link
        if not aid:
            continue
        title = " ".join((e.findtext(f"{ATOM_NS}title") or "").split())
        author = (e.findtext(f"{ATOM_NS}author/{ATOM_NS}name") or "").strip()
        published = (e.findtext(f"{ATOM_NS}published")
                     or e.findtext(f"{ATOM_NS}updated") or "").strip()
        body = e.findtext(f"{ATOM_NS}content") or e.findtext(f"{ATOM_NS}summary") or ""
        out.append({
            "id": aid,
            "title": title,
            "author": author,
            "summary": excerpt(body),
            "published": to_iso(published),
            "pubdate_raw": published,
            "url": link or aid,
        })
    return out


def parse_items(xml_text):
    """Parse either RSS 2.0 or Atom into the common item schema. The format is
    detected from the root element, so one fetcher handles both (most sources are
    RSS; Schneier on Security is Atom)."""
    root = ET.fromstring(xml_text)
    if root.tag.endswith("feed"):   # Atom root: {http://www.w3.org/2005/Atom}feed
        return _parse_atom(root)
    return _parse_rss(root)         # RSS 2.0 (or unknown → try channel/item)


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


def fetch_feed(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as r:
                return r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            # HTTPError subclasses URLError, so catch it first. Retry only transient
            # statuses (rate-limit / server errors); 4xx like 404 are config bugs -> raise.
            if e.code in RETRYABLE_STATUS and attempt < MAX_RETRIES:
                delay = _retry_delay(attempt, e)
                print(f"[warn] feed HTTP {e.code}; retry "
                      f"{attempt + 1}/{MAX_RETRIES} in {delay:.1f}s", file=sys.stderr)
                time.sleep(delay)
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            # Read timeout / connection reset: transient, retry until exhausted.
            if attempt < MAX_RETRIES:
                delay = _retry_delay(attempt)
                print(f"[warn] feed {type(e).__name__} ({e}); retry "
                      f"{attempt + 1}/{MAX_RETRIES} in {delay:.1f}s", file=sys.stderr)
                time.sleep(delay)
                continue
            raise


def cmd_fetch(cfg, seen_path):
    news = cfg.get("news", {})
    feeds = news.get("feeds") or [DEFAULT_FEED]
    lookback_days = int(news.get("lookback_days", 7))

    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    seen = load_seen(seen_path)

    n = len(feeds)
    _log(f"[fetch] {n} feed{'' if n == 1 else 's'} | lookback={lookback_days}d "
         f"| seen-ledger={len(seen)}")

    merged = {}
    failures = 0
    for i, feed in enumerate(feeds):
        if i > 0:
            _log(f"[fetch] rate-limit pause {RATE_LIMIT_SECONDS:.0f}s")
            time.sleep(RATE_LIMIT_SECONDS)
        _log(f"[fetch] feed {i + 1}/{n}: requesting {feed} ...")
        try:
            xml_text = fetch_feed(feed)
        except Exception as exc:  # network/parse resilience: report, keep going
            failures += 1
            print(f"[warn] feed {i + 1}/{n} failed after retries: {exc}", file=sys.stderr)
            continue
        got = parse_items(xml_text)
        for item in got:
            merged.setdefault(item["id"], item)  # first feed wins on dup id
        _log(f"[fetch] feed {i + 1}/{n}: {len(got)} item(s) "
             f"| {len(merged)} unique so far")

    fresh = []
    for item in merged.values():
        if item["id"] in seen:
            continue
        if item["published"]:
            try:
                pub = datetime.fromisoformat(item["published"])
                if pub < cutoff:
                    continue
            except ValueError:
                pass  # keep undated/odd items rather than silently dropping them
        fresh.append(item)

    fresh.sort(key=lambda x: x["published"], reverse=True)

    _log(f"[fetch] done: {len(merged)} unique -> {len(fresh)} new "
         f"(after seen + {lookback_days}d-window filter)"
         + (f" | WARNING {failures}/{n} feeds failed" if failures else ""))

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
    ap = argparse.ArgumentParser(description="The Hacker News AI-security monitor fetcher")
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
