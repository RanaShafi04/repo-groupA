#!/usr/bin/env python3
"""
build_nodes_standardized.py

Unifies MITRE, CWE, and NIST parsed JSONL files into the
LLM-ready unified schema:

{
  "id": "...",
  "source": "MITRE|CWE|NIST",
  "title": "...",
  "description": "...",
  "summary_512": "...",
  "categories": [...],
  "keywords": [...],
  "rev_date": "...",
  "url": "..."
}
"""

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INTERIM = REPO / "data/interim"
PROCESSED = REPO / "data/processed"
PROCESSED.mkdir(exist_ok=True)

MITRE_FILE = INTERIM / "mitre_parsed.jsonl"
CWE_FILE = INTERIM / "cwe_parsed.jsonl"
NIST_FILE = INTERIM / "nist_parsed.jsonl"

OUT_FILE = PROCESSED / "nodes_standardized.jsonl"

def load_jsonl(path):
    nodes = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                nodes.append(json.loads(line))
    return nodes

def ensure_list(v):
    if not v:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        return [v]
    return list(v)

print("[+] Loading interim data...")
mitre = load_jsonl(MITRE_FILE)
cwe   = load_jsonl(CWE_FILE)
nist  = load_jsonl(NIST_FILE)

standardized = []

print("[+] Standardizing MITRE...")
for n in mitre:
    out = {
        "id": n["id"],
        "source": "MITRE",
        "title": n.get("title", ""),
        "description": n.get("description", ""),

        "summary_512": n.get("summary_512") or n.get("description","")[:512],

        "categories": ensure_list(n.get("categories")),
        "keywords": ensure_list(n.get("keywords")) + ensure_list(n.get("tactics")),

        "rev_date": n.get("rev_date"),
        "url": n.get("url")
    }

    standardized.append(out)

print("[+] Standardizing CWE...")
for n in cwe:
    out = {
        "id": n["id"],
        "source": "CWE",
        "title": n.get("title") or n.get("name",""),
        "description": n.get("description",""),

        "summary_512": (n.get("description") or "")[:512],

        "categories": ensure_list(n.get("categories")),
        "keywords": ensure_list(n.get("keywords")),

        "rev_date": n.get("rev_date"),
        "url": n.get("url")
    }
    standardized.append(out)

print("[+] Standardizing NIST...")
for n in nist:
    out = {
        "id": n["id"],
        "source": "NIST",
        "title": n.get("title",""),
        "description": n.get("description",""),

        "summary_512": (n.get("description") or "")[:512],

        "categories": ensure_list(n.get("categories")),
        "keywords": ensure_list(n.get("keywords")),

        "rev_date": n.get("rev_date"),
        "url": n.get("url")
    }
    standardized.append(out)

print(f"[+] Total standardized nodes: {len(standardized)}")

with open(OUT_FILE, "w", encoding="utf-8") as f:
    for n in standardized:
        f.write(json.dumps(n) + "\n")

print("[✓] Saved:", OUT_FILE)
