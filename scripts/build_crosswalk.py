import json
import pandas as pd
import re
from pathlib import Path
from difflib import SequenceMatcher


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------
DATA_DIR = Path("data/processed")
OUTPUT_DIR = Path("mapping")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

NODES_FILE = DATA_DIR / "nodes_standardized.jsonl"
RELATIONS_FILE = DATA_DIR / "relations_standardized.jsonl"
CROSSWALK_FILE = OUTPUT_DIR / "attck_cwe_nist_crosswalk.csv"


# ---------------------------------------------------------
# Load standardized nodes
# ---------------------------------------------------------
def load_nodes():
    nodes = []
    with open(NODES_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                nodes.append(json.loads(line))
    return nodes


nodes = load_nodes()
attack_nodes = [n for n in nodes if n["source"] == "MITRE"]
cwe_nodes = [n for n in nodes if n["source"] == "CWE"]
nist_nodes = [n for n in nodes if n["source"] == "NIST"]


# ---------------------------------------------------------
# FAST similarity helpers (no sklearn)
# ---------------------------------------------------------
def norm_text(t):
    if not t:
        return ""
    t = t.lower()
    t = re.sub(r"[^a-z0-9 ]+", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def token_overlap(a, b):
    a = set(norm_text(a).split())
    b = set(norm_text(b).split())
    if not a or not b:
        return 0
    return len(a & b) / len(a | b)


def string_similarity(a, b):
    a = norm_text(a)
    b = norm_text(b)
    return SequenceMatcher(None, a, b).ratio()


def compute_confidence(a, b):
    """
    Final score = 40% title match + 40% description match + 20% keyword overlap
    """
    title_sim = string_similarity(a.get("title", ""), b.get("title", ""))
    desc_sim = string_similarity(a.get("description", ""), b.get("description", ""))
    kw_sim = token_overlap(" ".join(a.get("keywords", [])), " ".join(b.get("keywords", [])))

    score = 0.4 * title_sim + 0.4 * desc_sim + 0.2 * kw_sim
    return round(score, 4)


# ---------------------------------------------------------
# Mapping functions
# ---------------------------------------------------------
def map_attack_to_cwe():
    mappings = []
    for att in attack_nodes:
        for cwe in cwe_nodes:
            score = compute_confidence(att, cwe)
            if score >= 0.60:
                mappings.append({
                    "src_id": att["id"],
                    "dst_id": cwe["id"],
                    "relation_type": "maps_to",
                    "confidence": score,
                    "evidence": f"similarity={score}"
                })
    return mappings


def map_cwe_to_nist():
    mappings = []
    for cwe in cwe_nodes:
        for nist in nist_nodes:
            score = compute_confidence(cwe, nist)
            if score >= 0.60:
                mappings.append({
                    "src_id": cwe["id"],
                    "dst_id": nist["id"],
                    "relation_type": "mitigated_by",
                    "confidence": score,
                    "evidence": f"similarity={score}"
                })
    return mappings


# ---------------------------------------------------------
# Build the crosswalk
# ---------------------------------------------------------
attack_cwe = map_attack_to_cwe()
cwe_nist = map_cwe_to_nist()

all_relations = attack_cwe + cwe_nist

# Save relations_standardized.jsonl
with open(RELATIONS_FILE, "w", encoding="utf-8") as f:
    for r in all_relations:
        f.write(json.dumps(r) + "\n")

# Build final CSV (wide format)
df_attack_cwe = pd.DataFrame(attack_cwe)
df_cwe_nist = pd.DataFrame(cwe_nist)

df1 = df_attack_cwe.rename(columns={"dst_id": "CWE_ID", "confidence": "ATT_CWE_confidence"})
df2 = df_cwe_nist.rename(columns={"src_id": "CWE_ID", "confidence": "CWE_NIST_confidence"})

crosswalk = df1.merge(df2, on="CWE_ID", how="inner")

crosswalk = crosswalk[[
    "src_id",
    "CWE_ID",
    "dst_id",
    "ATT_CWE_confidence",
    "CWE_NIST_confidence"
]]

crosswalk.rename(columns={"src_id": "ATT_ID", "dst_id": "NIST_ID"}, inplace=True)

crosswalk.to_csv(CROSSWALK_FILE, index=False)

print("✓ Crosswalk generation completed.")
print("✓ Saved:", CROSSWALK_FILE)
print("✓ Relations saved:", RELATIONS_FILE)
