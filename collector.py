#!/usr/bin/env python3

import argparse
import feedparser
import hashlib
import json
import logging
import re
import sqlite3
import sys
import time
import urllib.request
from datetime import datetime, timezone
from html import unescape
from pathlib import Path

import weigh # importing weight.py

import yaml

import filter as gate  # filter.py: load_profile, score_item

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
INBOX = DATA / "inbox"
OUTPUT = DATA /"output"
REJECTED = DATA / "staging" / "rejected"
STATE = DATA / "state"

#CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
#HTML_RE = re.compile(r"<[^>]+>\s*")

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
HTML_RE = re.compile(r"<[^>]+>\s*")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("collector")


def strip_html(s: str) -> str:
    return unescape(HTML_RE.sub(" ", s or "")).strip()


def parse_date(entry) -> str:
    for attr in ("published_parsed", "updated_parsed"):
        t = getattr(entry, attr, None)
        if t:
            return datetime(*t[:6], tzinfo=timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()


def load_kev(url: str) -> set[str]:
    """Fetch the KEV catalog once per day; cache to a file."""
    cache = STATE / "kev_cache.json"
    today = datetime.now(timezone.utc).date().isoformat()
    if cache.exists():
        data = json.loads(cache.read_text())
        if data.get("date") == today:
            return set(data["cves"])
    log.info("fetching KEV catalog")
    with urllib.request.urlopen(url, timeout=30) as r:
        catalog = json.load(r)
    cves = {v["cveID"] for v in catalog.get("vulnerabilities", [])}
    STATE.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"date": today, "cves": sorted(cves)}))
    return cves


def build_item(entry, source: str, kev: set[str]) -> dict:
    title = strip_html(entry.get("title", ""))
    body = strip_html(entry.get("summary", ""))
    link = entry.get("link", "")
    cves = sorted(set(m.upper() for m in CVE_RE.findall(title + " " + body)))
    return {
        "id": hashlib.sha256(link.encode()).hexdigest()[:16],
        "title": title,
        "url": link,
        "summary": body[:2000],
        "source": source,
        "published": parse_date(entry),
        "cves": cves,
        "in_kev": any(c in kev for c in cves),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


def dedupe_db() -> sqlite3.Connection:
    STATE.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(STATE / "collector.db")
    db.execute("CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY, url TEXT, first_seen TEXT)")
    db.commit()
    return db


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--date", default=datetime.now(timezone.utc).date().isoformat())
    ap.add_argument("--profile", default="linux-cve")
    ap.add_argument("--explain", action="store_true")
    args = ap.parse_args()

    cfg = yaml.safe_load((BASE / "feeds.yaml").read_text())
    profile = gate.load_profile(args.profile)
    kev = load_kev(cfg["kev_catalog"]) if cfg.get("kev_catalog") else set()
    db = dedupe_db()

    day_dir = INBOXCVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
    rej_dir = REJECTED / args.date
    accepted = rejected = dupes = 0

    for feed in cfg["feeds"]:
        log.info("fetching %s", feed["name"])
        try:
            parsed = feedparser.parse(feed["url"])
        except Exception as e:
            log.warning("%s fetch failed: %s", feed["name"], e)
            continue

        for entry in parsed.entries:
            item = build_item(entry, feed["name"], kev)
            if not item["title"] or not item["url"]:
                continue

            # 1. FILTER (filter.py owns judgment)
            passed, score, reasons = gate.score_item(item, profile)
            if not passed:
                rejected += 1
                rej_dir.mkdir(parents=True, exist_ok=True)
                (rej_dir / f"{item['id']}.json").write_text(
                    json.dumps(item, indent=2, ensure_ascii=False))
                if args.explain:
                    print(f"[FAIL] {item['title'][:70]}  ::  {reasons[0] if reasons else 'score'}")
                continue

            # 2. DEDUPE (only items worth keeping get tracked)
            try:
                db.execute("INSERT INTO seen VALUES (?, ?, ?)",
                           (item["id"], item["url"], item["fetched_at"]))
                db.commit()
            except sqlite3.IntegrityError:
                dupes += 1
                continue

            # 3. STORE
            day_dir.mkdir(parents=True, exist_ok=True)
            item["profile"], item["filter_score"] = args.profile, score
            item["filter_reasons"] = reasons
            tmp = day_dir / f"{item['id']}.json.tmp"
            tmp.write_text(json.dumps(item, indent=2, ensure_ascii=False))
            tmp.rename(day_dir / f"{item['id']}.json")
            accepted += 1
            if args.explain:
                print(f"[PASS] {score:5.1f}  {item['title'][:70]}")

        time.sleep(1)  # be polite to feed servers

    log.info("profile=%s: %d accepted, %d rejected, %d dupes -> %s",
             args.profile, accepted, rejected, dupes, day_dir)

    weigh.rank_and_select(INBOX, OUTPUT, top_n=2)


if __name__ == "__main__":
    sys.exit(main())