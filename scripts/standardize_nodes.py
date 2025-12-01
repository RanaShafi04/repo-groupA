import json
import re
from datetime import datetime
from bs4 import BeautifulSoup
from pathlib import Path

# -----------------------------------------------------------------------
# Helper Functions (Normalization Rules)
# -----------------------------------------------------------------------

def canonicalize_id(raw_id, source):
    if not raw_id:
        return None

    raw_id = raw_id.strip()

    if source == "CWE":
        num = raw_id.replace("CWE-", "").lstrip("0")
        return f"CWE-{num}"

    if source == "MITRE":
        # ATT&CK IDs are usually correct; just uppercase and trim spaces
        return raw_id.upper()

    if source == "NIST":
        return raw_id  # Usually already canonical (AC-2, AC-2(1), etc.)

    return raw_id


def clean_text(text):
    if text is None:
        return ""
    # Remove HTML
    text = BeautifulSoup(text, "html.parser").text
    # Normalize whitespace
    text = re.sub(r"\s+", " ", text)
    text = text.strip()
    return text


def normalize_keywords(keyword_list):
    if not keyword_list:
        return []
    return [k.lower().strip() for k in keyword_list if k]


def normalize_date(raw_date):
    if not raw_date:
        return None
    try:
        raw_date = raw_date.replace("Z", "")
        base = raw_date.split("T")[0]
        dt = datetime.fromisoformat(base)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return None


# -----------------------------------------------------------------------
# Standardization Logic
# -----------------------------------------------------------------------

def standardize_node(obj):
    """
    Takes a raw parsed node from interim JSONL and returns a unified schema node.
    Handles MITRE, CWE, and NIST inputs.
    """
    raw_id = obj.get("id")
    source = obj.get("source")

    # ------------------------------
    # Detect source if missing
    # ------------------------------
    if source is None:
        if raw_id.startswith("T"):
            source = "MITRE"
        elif raw_id.startswith("CWE"):
            source = "CWE"
        else:
            source = "NIST"

    node = {}
    
    # NR1: canonical ID
    node["id"] = canonicalize_id(raw_id, source)
    node["source"] = source

    # ------------------------------
    # MITRE extraction
    # ------------------------------
    if source == "MITRE":
        node["title"] = clean_text(obj.get("name"))
        node["description"] = clean_text(obj.get("description"))

        # categories = tactics
        node["categories"] = obj.get("tactics", [])

        # keywords = title tokens (lowercase) + tactics
        title_kw = node["title"].lower().split()
        tactic_kw = [t.lower().replace("-", " ") for t in obj.get("tactics", [])]
        node["keywords"] = normalize_keywords(title_kw + tactic_kw)

        # extract MITRE URL
        url = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                url = ref.get("url")
                break
        node["url"] = url

        # rev_date: MITRE STIX sometimes includes "modified"
        node["rev_date"] = normalize_date(obj.get("modified"))

    # ------------------------------
    # CWE extraction
    # ------------------------------
    elif source == "CWE":
        node["title"] = clean_text(obj.get("name"))
        node["description"] = clean_text(obj.get("description"))
        node["categories"] = obj.get("weakness_abstraction", [])
        node["keywords"] = normalize_keywords(obj.get("keywords", []))
        node["rev_date"] = normalize_date(obj.get("rev_date"))
        node["url"] = obj.get("url")

    # ------------------------------
    # NIST extraction
    # ------------------------------
    elif source == "NIST":
        node["title"] = clean_text(obj.get("title"))
        node["description"] = clean_text(obj.get("text"))
        node["categories"] = [obj.get("family")] if obj.get("family") else []
        node["keywords"] = normalize_keywords(node["title"].split())
        node["rev_date"] = None    # NIST often lacks dates
        node["url"] = None

    # Summary placeholder
    node["summary_512"] = None

    return node



# -----------------------------------------------------------------------
# Main Pipeline
# -----------------------------------------------------------------------

def main():
    INPUT_DIR = Path("data/interim")
    OUTPUT_DIR = Path("processed")
    OUTPUT_DIR.mkdir(exist_ok=True)

    output_file = OUTPUT_DIR / "nodes_standardized.jsonl"

    seen = set()
    count = 0

    with output_file.open("w", encoding="utf-8") as out:

        # Process all parsed data files
        for file_name in ["mitre_parsed.jsonl", "cwe_parsed.jsonl", "nist_parsed.jsonl"]:
            input_path = INPUT_DIR / file_name

            if not input_path.exists():
                print(f"[WARN] Missing file: {input_path}")
                continue

            with input_path.open("r", encoding="utf-8") as f:
                for line in f:
                    obj = json.loads(line)

                    node = standardize_node(obj)

                    # NR5 — Deduplication key
                    key = (node["id"], node["source"])
                    if key in seen:
                        continue

                    seen.add(key)
                    out.write(json.dumps(node, ensure_ascii=False) + "\n")
                    count += 1

    print(f"[OK] Standardized nodes written: {count}")
    print(f"File created: {output_file}")


if __name__ == "__main__":
    main()
