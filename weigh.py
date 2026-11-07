# weigh.py
from datetime import datetime, timezone
from pathlib import Path
import json
import math
import shutil
import argparse

TOP_N_PER_CATEGORY = 2          # your current setting
CATEGORY_ORDER = ["linux-cve"]  # extend as profiles multiply
KEV_BONUS = 10.0
RECENCY_HALFLIFE_HOURS = 24.0   # weight halves every 24h

def score_item(item, now):
    """
    Scalar importance score. Higher = more important.
    Inputs deliberately limited to what's actually available today.
    """
    score = 0.0

    # Severity: KEV presence is the only ground-truth signal we have now.
    if item.get("in_kev"):
        score += KEV_BONUS

    # CVSS / EPSS / source-count: wired in now, dormant until enrichment runs.
    cvss = item.get("cvss")
    if cvss:
        score += float(cvss) * 2.0
    epss = item.get("epss")
    if epss:
        score += float(epss) * 20.0
    sources = item.get("sources") or []
    score += min(len(sources), 4) * 2.0

    # Recency: exponential decay, half-life 24h. Missing/unparseable date = 0 recency points.
    age_h = age_hours(item.get("published"), now)
    if age_h is not None:
        score += 10.0 * math.exp(-age_h * math.log(2) / RECENCY_HALFLIFE_HOURS)

    return round(score, 3)


def age_hours(published, now):
    if not published:
        return None
    try:
        dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0.0, (now - dt).total_seconds() / 3600.0)



def rank_and_select(inbox_dir: Path, out_dir: Path, now=None, top_n=TOP_N_PER_CATEGORY):
    now = now or datetime.now(timezone.utc)

    items = []
    for f in sorted(inbox_dir.glob("*.json")):
        try:
            item = json.loads(f.read_text())
        except json.JSONDecodeError:
            print(f"[weigh] skipping unparseable {f.name}")
            continue
        item["_file"] = f.name
        item["_score"] = score_item(item, now)
        items.append(item)

    # Bucket by category. Collector/filter must set item["category"];
    # fall back to "uncategorized" so nothing silently vanishes.
    buckets = {}
    for it in items:
        buckets.setdefault(it.get("category") or "uncategorized", []).append(it)

    shortlist = []
    for cat in CATEGORY_ORDER:
        pool = buckets.get(cat, [])
        pool.sort(key=lambda i: i["_score"], reverse=True)
        chosen = pool[:top_n]
        shortlist.extend(chosen)
        print(f"[weigh] {cat}: {len(pool)} candidates → picked {len(chosen)}")

    # Write shortlist as a single file the summarizer reads.
    out_dir.mkdir(parents=True, exist_ok=True)
    shortlist_path = out_dir / "shortlist.json"
    shortlist_path.write_text(json.dumps(
        {"generated": now.isoformat(), "items": shortlist},
        indent=2,
    ))
    print(f"[weigh] wrote {len(shortlist)} items → {shortlist_path}")
    return shortlist



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--date", default=datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    ap.add_argument("--data-root", type=Path, default=Path("data"))
    ap.add_argument("--top-n", type=int, default=TOP_N_PER_CATEGORY)
    args = ap.parse_args()

    inbox = args.data_root / "inbox" / args.date
    if not inbox.exists():
        print(f"[weigh] no inbox for {args.date} at {inbox}; nothing to do")
        return 1

    rank_and_select(inbox, args.data_root / "out" / args.date, top_n=args.top_n)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())