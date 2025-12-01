# Mapping guide (auto-generated summary)

Scoring features and weights:

- title_sim: weight 0.3
- desc_sim: weight 0.3
- kw_tactic_jaccard: weight 0.2
- mitigation_overlap: weight 0.2

Auto-accept threshold: 0.6
Top-K candidates kept per ATT_ID: 3

Heuristics applied: small boosts when CWE mentions technique tokens, penalty for generic CWE buckets, prefer sub-technique matches.

For calibration, provide mapping/gold.csv and call this script; it will search thresholds that satisfy precision >= 0.80 and maximize F1.
