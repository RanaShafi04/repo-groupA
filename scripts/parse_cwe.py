#!/usr/bin/env python3
"""
parse_cwe.py
Robust CWE XML -> data/interim/cwe_parsed.jsonl parser.

Outputs nodes that match the unified schema:
{
  "id": "CWE-79",
  "source": "CWE",
  "title": "...",
  "description": "...",        # concatenated, cleaned text
  "summary_512": null,
  "categories": [...],         # list
  "keywords": [...],           # list
  "rev_date": "...",
  "url": "...",
  "weakness_abstraction": "...",
  "structure": "...",
  "status": "...",
  "relationships": [...]
}
"""
import xml.etree.ElementTree as ET
from pathlib import Path
import json
import html
import re

SRC = Path("data/source/cwe.xml")
OUT = Path("data/interim/cwe_parsed.jsonl")
OUT.parent.mkdir(parents=True, exist_ok=True)

NS = {"ns": "http://cwe.mitre.org/cwe-7", "xhtml": "http://www.w3.org/1999/xhtml"}

def text_of(elem):
    """Get visible text inside an element (handles nested tags)."""
    if elem is None:
        return ""
    # join text from element and subelements
    parts = []
    if elem.text:
        parts.append(elem.text)
    for child in elem:
        if child.text:
            parts.append(child.text)
        if child.tail:
            parts.append(child.tail)
    # fallback to tostring if empty
    if not parts:
        return (ET.tostring(elem, encoding="unicode", method="text") or "").strip()
    return " ".join(p for p in parts if p).strip()

def clean_html(s):
    if not s:
        return ""
    s = html.unescape(s)
    # remove remaining tags if any
    s = re.sub(r"<[^>]+>", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def keywords_from_text(s, top_n=12):
    """Heuristic keyword extractor: simple tokenization + frequency filter."""
    if not s:
        return []
    s = s.lower()
    # remove code-like tokens, keep words/digits
    tokens = re.findall(r"[a-z0-9\-]{2,}", s)
    # basic stopwords (extend as needed)
    stop = {
        "the","and","for","with","that","this","such","may","often","also","use","used",
        "useful","application","system","function","functions","functionality"
    }
    filtered = [t for t in tokens if t not in stop]
    # frequency
    freq = {}
    for t in filtered:
        freq[t] = freq.get(t, 0) + 1
    # sort by freq then length
    keys = sorted(freq.keys(), key=lambda k: (-freq[k], -len(k)))
    return keys[:top_n]

print("[+] Parsing CWE XML:", SRC)
tree = ET.parse(SRC)
root = tree.getroot()

records = []
count = 0
for w in root.findall(".//ns:Weakness", NS):
    count += 1
    wid = w.attrib.get("ID") or ""
    name = w.attrib.get("Name") or ""
    abstraction = w.attrib.get("Abstraction")
    structure = w.attrib.get("Structure")
    status = w.attrib.get("Status")

    # Description: prefer <Description> then any <Description_...> child content
    desc_elem = w.find("ns:Description", NS)
    description = clean_html(text_of(desc_elem)) if desc_elem is not None else ""

    # Collect other text fields (Potential_Mitigation, Observation, Extended_Description, etc.)
    extras = []
    for tag in ("Potential_Mitigation", "Potential_Mitigation_Notes", "Notes",
                "Extended_Description", "Relationships", "Observation"):
        e = w.find(f"ns:{tag}", NS)
        if e is not None:
            extras.append(clean_html(text_of(e)))

    # Collect references (optional)
    url = None
    for ref in w.findall("ns:Reference", NS):
        href = ref.attrib.get("URI") or ref.attrib.get("URL")
        if href:
            url = href
            break

    # Related weaknesses
    relationships = []
    for rel in w.findall(".//ns:Related_Weakness", NS):
        rid = rel.attrib.get("CWE_ID")
        rtype = rel.attrib.get("Nature") or rel.attrib.get("Relationship_Type")
        if rid:
            relationships.append({"related_id": f"CWE-{rid}", "type": rtype})

    # categories: combine abstraction, structure, status (if present)
    categories = []
    for v in (abstraction, structure, status):
        if v:
            categories.append(v)

    # build full description: main + extras
    full_text = " ".join([description] + extras)
    full_text = clean_html(full_text)

    # keywords
    kw_from_name = re.findall(r"[A-Za-z0-9\-]{2,}", name.lower())
    kw_from_text = keywords_from_text(full_text)
    keywords = list(dict.fromkeys([k for k in (kw_from_name + kw_from_text) if k]))  # preserve order

    node = {
        "id": f"CWE-{wid}" if wid else "",
        "source": "CWE",
        "title": name,
        "description": full_text,
        "summary_512": None,
        "categories": categories,
        "keywords": keywords,
        "rev_date": w.attrib.get("Date") or None,
        "url": url,
        "weakness_abstraction": abstraction,
        "structure": structure,
        "status": status,
        "relationships": relationships
    }
    records.append(node)

print(f"[+] Extracted {len(records)} CWE entries (iterated {count} <Weakness> tags)")

# Write JSONL
with open(OUT, "w", encoding="utf-8") as f:
    for r in records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

print("[+] Saved:", OUT)
