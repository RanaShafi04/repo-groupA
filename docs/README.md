# Group A – Unified ATT&CK → CWE → NIST Crosswalk

Version: **v1.0**

This repository contains a fully standardized security knowledge graph linking:

* **MITRE ATT&CK Techniques**
* **MITRE CWE Weaknesses**
* **NIST 800-53 Controls**

The project normalizes heterogeneous cybersecurity datasets into a **unified schema**, produces a **high-quality crosswalk**, and runs a **QA pipeline** to ensure data integrity, coverage, and reproducibility.

---

## 📁 Repository Structure

```
schema/
  unified_schema.json
  field_dictionary.md

mapping/
  attck_cwe_nist_crosswalk.csv
  mapping_guide.md

data/
  raw/
  interim/
  processed/
    nodes_standardized.jsonl
    relations_standardized.jsonl

docs/
  README.md
  data_lineage.md
  qa_checklist.md
  decisions_log.md

scripts/
  parse_mitre.py
  parse_cwe.py
  parse_nist.py
  build_crosswalk.py
  export_llm_ready.py
  qa_pipeline.py

releases/
  groupA_dataset_v1.jsonl
  groupA_dataset_v1.csv
  checksums.txt
```

---

## 🚀 How to Run the Pipeline

### 1. Parse and standardize raw sources

```bash
python scripts/parse_mitre.py
python scripts/parse_cwe.py
python scripts/parse_nist.py
```

### 2. Standardize into unified schema

```bash
python scripts/export_llm_ready.py
```

This produces:

* `nodes_standardized.jsonl`
* `relations_standardized.jsonl` (empty until crosswalk is built)

### 3. Build the crosswalk

```bash
python scripts/build_crosswalk.py
```

Outputs:

* `mapping/attck_cwe_nist_crosswalk.csv`
* `data/processed/relations_standardized.jsonl`

### 4. Run QA

```bash
python scripts/qa_pipeline.py
```

Outputs:

* `docs/qa_checklist.md`
* `mapping/score_histogram.png`
* Updated `decisions_log.md`

### 5. Produce Release Bundle

```bash
python scripts/package_release.py
```

Creates:

* `releases/groupA_dataset_v1.jsonl`
* `releases/groupA_dataset_v1.csv`
* `releases/checksums.txt`

---

## 🧱 Unified Schema Overview

Required fields:

| Field         | Type   | Description                      |
| ------------- | ------ | -------------------------------- |
| `id`          | string | Canonical node identifier        |
| `title`       | string | Human-readable name              |
| `description` | string | Cleaned + normalized description |
| `source`      | enum   | `MITRE`, `CWE`, `NIST`           |
| `keywords`    | list   | Extracted semantic keywords      |
| `summary_512` | string | Token-limited summary            |

Full schema: `schema/unified_schema.json`.

---

## 📊 QA Requirements

The dataset must satisfy:

* **≥95% field coverage**
* **0 duplicate node IDs**
* **<0.5% duplicate edges**
* **All summaries ≤512 tokens**
* **≥1 CWE per applicable ATT&CK technique**
* **≥1 NIST control per mapped CWE**

Full checklist in: `docs/qa_checklist.md`.

---

## 📦 Release Bundle Contents

| File                      | Purpose                         |
| ------------------------- | ------------------------------- |
| `groupA_dataset_v1.jsonl` | Metadata + node/edge references |
| `groupA_dataset_v1.csv`   | CSV version                     |
| `checksums.txt`           | SHA256 checksums for integrity  |

---

## 📝 FAQ

**Q: Why do some ATT&CK techniques map to multiple CWEs?**
Because techniques represent behaviors, while CWEs represent structural weaknesses, many-to-many mappings occur naturally.

**Q: How do I contribute?**
Open an issue or submit a pull request. Follow `mapping_guide.md` for crosswalk changes.

**Q: Where is the gold set used for threshold calibration?**
See `docs/decisions_log.md`.

---

## 👤 Maintainers

Group A – Cybersecurity Knowledge Graph
Erasmus Mundus Cohort, 2025
