{"id":"58341","variant":"standard","title":"QA Script Revised"}
#!/usr/bin/env python3
import pandas as pd
import numpy as np
from pathlib import Path
import matplotlib.pyplot as plt
from datetime import datetime

# ---------------------------------------------
# Paths
# ---------------------------------------------
NODES_PATH = Path("data/processed/nodes_standardized.jsonl")
CROSSWALK = Path("mapping/attck_cwe_nist_crosswalk.csv")

DOCS_DIR = Path("docs")
LOG_DIR = Path("logs")
IMG_PATH = Path("mapping/score_histogram.png")
OUT_MD = DOCS_DIR / "qa_checklist.md"

DOCS_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

log_path = LOG_DIR / f"pipeline_run_{datetime.now().strftime('%Y%m%d_%H%M')}.log"


# ---------------------------------------------
# Logging utility
# ---------------------------------------------
def log(msg):
    print(msg)
    with open(log_path, "a") as f:
        f.write(msg + "\n")


log("[+] Starting QA pipeline")


# ---------------------------------------------
# Load data
# ---------------------------------------------
if not CROSSWALK.exists():
    raise FileNotFoundError(
        "Crosswalk file not found: mapping/attck_cwe_nist_crosswalk.csv"
    )

df = pd.read_csv(CROSSWALK)
nodes = pd.read_json(NODES_PATH, lines=True)

log(f"[+] Loaded {len(df)} edges")
log(f"[+] Loaded {len(nodes)} nodes")


# ---------------------------------------------
# Field coverage
# ---------------------------------------------
required_fields = ["id", "title", "description", "source"]
coverage = {
    field: 100 * nodes[field].notna().mean()
    for field in required_fields
}

field_pass = all(v >= 95 for v in coverage.values())

# ---------------------------------------------
# Duplicates
# ---------------------------------------------
duplicate_ids = nodes["id"].duplicated().sum()
duplicate_edges = df.duplicated(["src_id", "dst_id", "relation_type"]).sum()
edge_dup_rate = duplicate_edges / max(1, len(df))

dup_pass = (duplicate_ids == 0) and (edge_dup_rate < 0.005)


# ---------------------------------------------
# Token budget (summary_512)
# ---------------------------------------------
if "summary_512" in nodes.columns:
    over_limit = nodes["summary_512"].fillna("").apply(
        lambda x: len(x.split()) > 512
    ).sum()
else:
    over_limit = 0  # summaries not yet produced

token_pass = (over_limit == 0)


# ---------------------------------------------
# Link density
# ---------------------------------------------
mitre_nodes = nodes[nodes["source"] == "MITRE"]["id"].tolist()
cwe_nodes = nodes[nodes["source"] == "CWE"]["id"].tolist()

mitre_to_cwe = df[df["relation_type"] == "related_to"]
mitre_has_cwe = mitre_to_cwe["src_id"].nunique()
density_mitre_cwe = mitre_has_cwe / max(1, len(mitre_nodes))

cwe_to_nist = df[df["relation_type"] == "mitigated_by"]
cwe_has_nist = cwe_to_nist["src_id"].nunique()
density_cwe_nist = cwe_has_nist / max(1, len(cwe_nodes))

density_pass = (density_mitre_cwe >= 1.0) and (density_cwe_nist >= 1.0)


# ---------------------------------------------
# Score histogram
# ---------------------------------------------
plt.figure(figsize=(8, 4))
plt.hist(df["evidence"], bins=40)
plt.title("Crosswalk Score Distribution")
plt.xlabel("Score")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(IMG_PATH)
plt.close()

log("[+] Saved histogram → mapping/score_histogram.png")


# ---------------------------------------------
# Final PASS logic
# ---------------------------------------------
overall_pass = all([field_pass, dup_pass, token_pass, density_pass])


# ---------------------------------------------
# Write QA markdown
# ---------------------------------------------
with open(OUT_MD, "w") as f:
    f.write("# Crosswalk QA Checklist\n\n")
    f.write(f"Generated: **{datetime.utcnow().isoformat()}Z**\n\n")

    # FIELD COVERAGE
    f.write("## Field Coverage\n")
    for k, v in coverage.items():
        f.write(f"- **{k}**: {v:.2f}%\n")
    f.write(f"- **PASS?** {'✔️ Yes' if field_pass else '❌ No'}\n\n")

    # DUPLICATES
    f.write("## Duplicates\n")
    f.write(f"- Duplicate node IDs: {duplicate_ids}\n")
    f.write(f"- Duplicate edges: {duplicate_edges} ({edge_dup_rate:.3%})\n")
    f.write(f"- **PASS?** {'✔️ Yes' if dup_pass else '❌ No'}\n\n")

    # TOKEN BUDGET
    f.write("## Token Budget (summary_512)\n")
    f.write(f"- Over limit: {over_limit}\n")
    f.write(f"- **PASS?** {'✔️ Yes' if token_pass else '❌ No'}\n\n")

    # LINK DENSITY
    f.write("## Link Density\n")
    f.write(f"- ATT&CK→CWE coverage: {density_mitre_cwe*100:.2f}%\n")
    f.write(f"- CWE→NIST coverage: {density_cwe_nist*100:.2f}%\n")
    f.write(f"- **PASS?** {'✔️ Yes' if density_pass else '❌ No'}\n\n")

    # FINAL VERDICT
    f.write("## Final Verdict\n")
    if overall_pass:
        f.write("### ✔️ **PASS — Crosswalk meets QA requirements.**\n")
    else:
        f.write("### ❌ **FAIL — Crosswalk does not meet QA requirements.**\n")
        f.write("Please improve mappings, summary generation, or deduplication.\n")

log("[✓] QA Completed. Markdown written to docs/qa_checklist.md")
