#!/usr/bin/env python3
"""
filter.py — judgment layer. Imported by collector.py (score_item, load_profile).
Also runnable standalone to re-score a stored day or tune profiles:

    python filter.py --explain                 # re-score today's rejects with reasons
"""

import argparse
import json
import re
from pathlib import Path

import yaml

BASE = Path(__file__).resolve().parent
PROFILES = BASE / "profiles"


def load_profile(name: str) -> dict:
    p = yaml.safe_load((PROFILES / f"{name}.yaml").read_text())
    p.setdefault("min_score", 3)
    p.setdefault("negative", {})
    p.setdefault("kev_bonus", 2)
    return p



# def score_item(item: dict, profile: dict) -> tuple[bool, float, list[str]]:
#     text = f"{item.get('title','')} {item.get('summary','')}".lower()

#     text = (item["title"] + "\n" + item.get("summary", "")).lower()

#     for pat in profile.get("reject_if", []):
#         if re.search(pat, text, re.I):
#             return 0.0, [f"REJECT: matched anti-pattern '{pat}'"]

#     req = profile.get("require_any")
#     if req:
#         hit = [p for p in req if re.search(p, text, re.I)]
#         if not hit:
#             return 0.0, ["REJECT: no required term matched"]
#         reasons = [f"+gate '{hit[0]}'"]

#     score, reasons = 0.0, []
#     for term, w in profile.get("scoring", {}).items():
#         if term.lower() in text:
#             score += w
#             reasons.append(f"+{w} '{term}'")
#     for term, w in profile.get("negative", {}).items():
#         if term.lower() in text:
#             score += w
#             reasons.append(f"{w} '{term}'")
#     if item.get("in_kev"):
#         score += profile["kev_bonus"]
#         reasons.append(f"+{profile['kev_bonus']} KEV-listed")

#     return score >= profile["min_score"], score, reasons


def score_item(item, profile):
    text = (item["title"] + "\n" + item.get("summary", "")).lower()

    # 1. Hard reject
    for pat in profile.get("reject_if", []):
        if re.search(pat, text, re.I):
            return False, 0.0, [f"REJECT: anti-pattern '{pat}'"]

    # 2. Hard gate
    req = profile.get("require_any") or []
    if req:
        hit = next((p for p in req if re.search(p, text, re.I)), None)
        if hit is None:
            return False, 0.0, ["REJECT: no required term matched"]
        reasons = [f"+gate '{hit}'"]
    else:
        reasons = []

    # 3. Weighted keyword scoring
    score = 0.0
    for pattern, w in profile.get("keywords", {}).items():
        if re.search(pattern, text, re.I):
            score += w
            reasons.append(f"+{w} '{pattern}'")

    # 4. Threshold
    min_score = profile.get("min_score", 0)
    passed = score >= min_score
    if not passed:
        reasons.append(f"BELOW min_score ({score} < {min_score})")

    return passed, score, reasons

def main():  # standalone: explain passes/fails for a day's stored items
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(BASE / "data" / "staging" / "rejected"))
    ap.add_argument("--profile", default="linux-cve")
    args = ap.parse_args()

    profile = load_profile(args.profile)
    for f in sorted(Path(args.dir).rglob("*.json")):
        item = json.loads(f.read_text())
        passed, score, reasons = score_item(item, profile)
        print(f"[{'PASS' if passed else 'FAIL'}] {score:5.1f}  {item['title'][:70]}")
        print(f"        {'; '.join(reasons) if reasons else '(no matches)'}")


if __name__ == "__main__":
    main()