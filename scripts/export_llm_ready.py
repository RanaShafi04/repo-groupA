#!/usr/bin/env python3
import json
import jsonlines
from pathlib import Path
import re

MITRE_PATH = Path("data/interim/mitre_parsed.jsonl")
CWE_PATH   = Path("data/interim/cwe_parsed.jsonl")
NIST_PATH  = Path("data/interim/nist_parsed.jsonl")

OUT_PATH   = Path("data/processed/nodes_standardized.jsonl")

OUT_PATH.parent.mkdir(parents=True, exist_ok=True)


# ---------------------------
# Helper functions
# ---------------------------

def clean_text(t):
    if not t:
        return ""
    return re.sub(r"\s+", " ", t).strip()

def extract_keywords(text):
    if not text:
        return []
    # Simple keyword extraction: lowercase + split on non-letters
    words = re.findall(r"[a-zA-Z0-9]+", text.lower())
    # remove trivial words
    stop = {"the","and","or","to","in","of","for","a","an","is","as","by","with","on","this","that"}
    return sorted(set([w for w in words if w not in stop and len(w) > 2]))


# ---------------------------
# Canonical URL generators
# ---------------------------

def mitre_url(att_id):
    # Example: T1059.001 → https://attack.mitre.org/techniques/T1059/001
    if "." in att_id:
        base, sub = att_id.split(".")
        return f"https://attack.mitre.org/techniques/{base}/{sub}"
    else:
        return f"https://attack.mitre.org/techniques/{att_id}/"

def cwe_url(cwe_id):
    # Example: CWE-79 → https://cwe.mitre.org/data/definitions/79.html
    num = cwe_id.replace("CWE-", "")
    return f"https://cwe.mitre.org/data/definitions/{num}.html"

def nist_url(control_id):
    # Generic NIST SP 800-53 Rev.5 link
    return "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"


# ---------------------------
# Load parsed data
# ---------------------------

def load_jsonl(path):
    items = []
    with jsonlines.open(path) as reader:
        for obj in reader:
            items.append(obj)
    return items


mitre_items = load_jsonl(MITRE_PATH)
cwe_items   = load_jsonl(CWE_PATH)
nist_items  = load_jsonl(NIST_PATH)


# ---------------------------
# Convert to unified nodes
# ---------------------------

unified = []

# --- MITRE ---
for item in mitre_items:
    uid = item.get("id")
    title = item.get("name") or item.get("title")
    desc = clean_text(item.get("description", ""))

    unified.append({
        "id": uid,
        "source": "MITRE",
        "title": title,
        "summary_512": "",        # to be filled later
        "description": desc,
        "categories": item.get("tactics", []),
        "keywords": extract_keywords(desc),
        "rev_date": None,
        "url": mitre_url(uid)
    })


# --- CWE ---
for item in cwe_items:
    uid = item["id"]
    title = item["name"]
    desc = clean_text(item.get("description",""))
    
    unified.append({
        "id": uid,
        "source": "CWE",
        "title": title,
        "summary_512": "",
        "description": desc,
        "categories": [item.get("weakness_abstraction","")],
        "keywords": extract_keywords(desc),
        "rev_date": None,
        "url": cwe_url(uid)
    })


# --- NIST ---
for item in nist_items:
    control_id = item["id"]
    title = item["title"]
    statement = clean_text(item.get("text",""))
    supp = clean_text(item.get("supplemental_guidance",""))

    desc = (statement + " " + supp).strip()

    unified.append({
        "id": control_id,
        "source": "NIST",
        "title": title,
        "summary_512": "",
        "description": desc,
        "categories": [item.get("family","")],
        "keywords": extract_keywords(desc),
        "rev_date": None,
        "url": nist_url(control_id)
    })


# ---------------------------
# Write output
# ---------------------------

with jsonlines.open(OUT_PATH, mode="w") as writer:
    writer.write_all(unified)

print(f"[✓] Successfully created unified node file → {OUT_PATH}")
print(f"[✓] Total nodes: {len(unified)}")
