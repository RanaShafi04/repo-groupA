# Data Lineage – Group A Dataset

This document explains **where every piece of data originates**, how it is **transformed**, and how it becomes part of the final **Group A Crosswalk Dataset v1.0**.

Generated: **2025-11-26**

---

# 1. Sources

### **MITRE ATT&CK (v14+)**

* Techniques: enterprise-attack.json
* Extracted fields: `id`, `name`, `description`, `tactics`, `external_references`

### **MITRE CWE**

* CWE XML: 4.12+
* Extracted fields: `Weakness ID`, `Name`, `Description`, `Extended Description`, `Potential Mitigations`

### **NIST 800-53 Rev5**

* JSON baseline data
* Extracted fields: `Control ID`, `Title`, `Family`, `Control Text`

All raw files added to:

```
data/raw/
```

---

# 2. ETL Flow (Extract → Transform → Load)

## Step 1 — Parsing

Scripts:

* `scripts/parse_mitre.py`
* `scripts/parse_cwe.py`
* `scripts/parse_nist.py`

Output → `data/interim/*.jsonl`

Actions:

* Strip HTML
* Merge multi-field descriptions
* Normalize whitespace
* Extract keywords (noun chunks + important verbs)
* Canonicalize IDs (e.g., `CWE-79`, `T1059.001`, `AC-3`)

---

## Step 2 — Standardization

Script: `export_llm_ready.py`

Output → `data/processed/nodes_standardized.jsonl`

Actions:

* Lowercase + normalize text
* Replace HTML tags
* Deduplicate keywords
* Generate `summary_512` (<= 512 tokens)
* Validate against `unified_schema.json`

---

## Step 3 — Crosswalk Generation

Script: `build_crosswalk.py`

Output:

* `mapping/attck_cwe_nist_crosswalk.csv`
* `data/processed/relations_standardized.jsonl`

Methodology:

* Embedding similarity (MiniLM)
* Fuzzy title/description matching
* Keyword Jaccard overlap
* Hybrid scoring
* Threshold: 0.60 for auto-accept

Relation types:

* `related_to` (ATT&CK → CWE)
* `mitigated_by` (CWE → NIST)

---

## Step 4 — QA Pipeline

Script: `qa_pipeline.py`

Output:

* `docs/qa_checklist.md`
* `mapping/score_histogram.png`
* Logged events → `docs/decisions_log.md`

Checks:

* Field coverage
* Duplicates
* Token budget
* Link density
* Score distribution

---

## Step 5 — Release Packaging

Script: `package_release.py`

Outputs to `releases/`:

* `groupA_dataset_v1.jsonl`
* `groupA_dataset_v1.csv`
* `checksums.txt`

Included metadata:

* Version
* Timestamp
* Checksums
* Schema reference
* File paths

---

# 3. Summary Diagram

```
RAW → INTERIM → PROCESSED → MAPPING → QA → RELEASE
```

or in detail:

```
ATT&CK JSON ┐
CWE XML     ├── parse_* → interim → export_llm_ready → nodes_standardized
NIST JSON   ┘

nodes_standardized + crosswalk scoring → relations_standardized

QA pipeline → qa_checklist.md, scoreboard, logs

package_release → groupA_dataset_v1.*, checksums
```

---

# 4. Reproducibility

This pipeline is:

* Deterministic (same inputs → same outputs)
* Versioned through `schema/unified_schema.json`
* Logged via `decisions_log.md`
* Checked using `qa_checklist.md`

All transformations are traceable to specific scripts and parameter settings.

---

# 5. Maintainer Notes

* Any schema change requires bumping dataset version.
* All mappings must be justified with audit evidence.
* QA must pass **before** packaging a release.

End of document.
