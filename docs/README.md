# Group A – Unified ATT&CK → CWE → NIST Crosswalk

## Version: v1.0

This repository contains an end-to-end pipeline that builds a standardized cybersecurity knowledge graph linking:

- MITRE ATT&CK techniques
- MITRE CWE weaknesses
- NIST SP 800-53 controls

The system parses heterogeneous upstream datasets, normalizes them into a unified schema, generates a multi-stage crosswalk, and performs a structured QA process to ensure accuracy, coverage, and reproducibility.

## Repository Structure
schema/
  unified_schema.json
  field_dictionary.md

mapping/
  attck_cwe_nist_crosswalk.csv
  crosswalk_rejects.jsonl
  score_histogram.png
  mapping_guide.md

data/
  source/
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
  export_llm_ready.py
  build_crosswalk.py
  qa_crosswalk.py
  package_release.py

releases/
  groupA_dataset_v1.jsonl
  groupA_dataset_v1.csv
  checksums.txt

## Pipeline Overview
1. Parse raw datasets

Each dataset is extracted and normalized:

python scripts/parse_mitre.py
python scripts/parse_cwe.py
python scripts/parse_nist.py


This generates structured JSONL files in data/interim/.

2. Convert to unified schema
python scripts/export_llm_ready.py


### Outputs:

nodes_standardized.jsonl

relations_standardized.jsonl (initially empty)

3. Build the crosswalk (ATT&CK → CWE → NIST)
python scripts/build_crosswalk.py


This script uses:

fuzzy text similarity

keyword overlap

expanded security-concept matching

description overlap

cross-mention scoring

### Outputs:

mapping/attck_cwe_nist_crosswalk.csv (columns: src_id, dst_id, relation_type, evidence)

mapping/crosswalk_rejects.jsonl

data/processed/relations_standardized.jsonl

4. Run QA Validation
python scripts/qa_crosswalk.py


### Produces:

docs/qa_checklist.md

mapping/score_histogram.png

logs in logs/

The QA script validates:

field completeness

duplicate node IDs

duplicate edges (using src_id,dst_id,relation_type)

link density (ATT&CK→CWE and CWE→NIST)

summary token limits

score distribution

5. Build final release bundle
python scripts/package_release.py


### Creates:

releases/groupA_dataset_v1.jsonl

releases/groupA_dataset_v1.csv

releases/checksums.txt

## Unified Schema (Core Fields)
Field	Type	Description
id	string	Canonical node ID (e.g., T1059.003, CWE-79, AC-02)
title	string	Human-readable name
description	string	Cleaned and normalized text
source	enum	One of: MITRE, CWE, NIST
keywords	list	Extracted normalized keywords
categories	list	Control family / weakness abstraction
summary_512	string	LLM-ready ≤512-token summary

Full specification: schema/unified_schema.json

## QA Requirements

The dataset is considered valid when:

≥95% field coverage

0 duplicate node IDs

Duplicate edges <0.5%
(checked using src_id, dst_id, relation_type)

No summary exceeds 512 tokens

Each ATT&CK technique maps to ≥1 CWE (unless conceptually unmappable)

Each CWE maps to ≥1 NIST control

See: docs/qa_checklist.md.

## Release Bundle Contents
File	Purpose
groupA_dataset_v1.jsonl	Unified graph with node + edge metadata
groupA_dataset_v1.csv	Flat CSV export
checksums.txt	Hashes for data integrity
## Maintainers

Group A – CyberMACS Cybersecurity Knowledge Graph Project (2025)