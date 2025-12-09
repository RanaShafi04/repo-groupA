#!/usr/bin/env python3
"""
parse_nist.py
Reads NIST SP800-53 Excel and outputs data/interim/nist_parsed.jsonl
Produces consistent fields:
{
  "id": "AC-04(02)",
  "source": "NIST",
  "title": "...",
  "description": "...",     # merged statement + discussion
  "summary_512": null,
  "categories": ["AC"],
  "keywords": [...],
  "rev_date": null,
  "url": null
}
"""
import pandas as pd
import json
from pathlib import Path
import re

SRC = Path("data/source/nist_sp800-53_controls.xlsx")
OUT = Path("data/interim/nist_parsed.jsonl")
OUT.parent.mkdir(parents=True, exist_ok=True)

print("[+] Loading NIST Excel:", SRC)
df = pd.read_excel(SRC, dtype=str)

# Normalize column names (trim)
df.columns = df.columns.str.strip()

# Adapt these column names if your sheet uses slightly different headings:
col_family    = "Control Family"
col_id        = "Control (or Control Enhancement) Identifier"
col_name      = "Control (or Control Enhancement) Name"
col_statement = "Control Statement"
col_supp      = "Discussion"  # your Excel used "Discussion" earlier

# Forward-fill merged family cells (common in NIST XLSX)
df[col_family] = df[col_family].ffill()

records = []
def extract_keywords(text, top_n=12):
    if not text or pd.isna(text):
        return []
    text = str(text).lower()
    tokens = re.findall(r"[a-z0-9\-]{3,}", text)
    stop = {"the","and","for","use","useful","organization","organization-defined","shall"}
    tokens = [t for t in tokens if t not in stop]
    freq = {}
    for t in tokens:
        freq[t] = freq.get(t, 0) + 1
    keys = sorted(freq.keys(), key=lambda k: (-freq[k], -len(k)))
    return keys[:top_n]

print("[+] Iterating rows...")
for _, row in df.iterrows():
    cid = str(row.get(col_id, "")).strip()
    if not cid or cid.lower() == "nan":
        continue

    family = str(row.get(col_family, "")).strip()
    title = str(row.get(col_name, "")).strip()
    statement = str(row.get(col_statement, "")).strip() if not pd.isna(row.get(col_statement, "")) else ""
    supp = str(row.get(col_supp, "")).strip() if not pd.isna(row.get(col_supp, "")) else ""

    # Merge statement + discussion into a single description
    desc_parts = []
    if statement:
        desc_parts.append(statement)
    if supp:
        desc_parts.append(supp)
    description = " ".join(desc_parts).strip()

    # categories: family may contain multiple families separated by comma; normalize to list
    cats = [c.strip() for c in re.split(r"[;/,]", family) if c.strip()]

    # keywords: from title + description heuristics
    keywords = extract_keywords(title + " " + description)

    node = {
        "id": cid,
        "source": "NIST",
        "title": title,
        "description": description,
        "summary_512": None,
        "categories": cats,
        "keywords": keywords,
        "rev_date": None,
        "url": None
    }
    records.append(node)

print(f"[+] Extracted {len(records)} NIST controls")

# Write JSONL
with open(OUT, "w", encoding="utf-8") as f:
    for r in records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

print("[+] Saved:", OUT)
