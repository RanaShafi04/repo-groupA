#!/usr/bin/env python3
import json
import csv
import re
from pathlib import Path
from collections import defaultdict
from difflib import SequenceMatcher

# ============================================
# PATHS
# ============================================
REPO = Path(__file__).resolve().parents[1]
PROCESSED = REPO / "data/processed"
MAPPINGS = REPO / "mapping"
PROCESSED.mkdir(exist_ok=True)

NODES_FILE = PROCESSED / "nodes_standardized.jsonl"
OUT_MAPPINGS = PROCESSED / "attck_cwe_nist_crosswalk.csv"

MIN_SCORE_TO_SAVE = 0.0

# ============================================
# UTILS
# ============================================

def load_nodes_by_source(path):
    """Load standardized nodes and separate by source."""
    mitre_nodes = []
    cwe_nodes = []
    nist_nodes = []
    
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                node = json.loads(line)
                source = node.get("source", "")
                
                if source == "MITRE":
                    mitre_nodes.append(node)
                elif source == "CWE":
                    cwe_nodes.append(node)
                elif source == "NIST":
                    nist_nodes.append(node)
    
    return mitre_nodes, cwe_nodes, nist_nodes


def normalize_text(text):
    """Normalize text for comparison."""
    if not text:
        return ""
    text = str(text).lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def get_stems(text):
    """Extract word stems (simple prefix matching)."""
    words = normalize_text(text).split()
    stems = set()
    for word in words:
        if len(word) > 4:
            stems.add(word[:4])  # First 4 chars as stem
        stems.add(word)
    return stems


def fuzzy_similarity(text1, text2):
    """Calculate fuzzy string similarity using SequenceMatcher."""
    if not text1 or not text2:
        return 0.0
    return SequenceMatcher(None, normalize_text(text1), normalize_text(text2)).ratio()


def keyword_overlap_score(kw1, kw2):
    """Calculate Jaccard similarity with stem matching."""
    if not kw1 or not kw2:
        return 0.0
    
    # Exact match
    set1 = set(normalize_text(k) for k in kw1)
    set2 = set(normalize_text(k) for k in kw2)
    
    if not set1 or not set2:
        return 0.0
    
    # Calculate overlap
    intersection = len(set1 & set2)
    
    # Add stem matches (partial credit)
    stems1 = set()
    stems2 = set()
    for k in set1:
        if len(k) > 4:
            stems1.add(k[:5])
    for k in set2:
        if len(k) > 4:
            stems2.add(k[:5])
    
    stem_intersection = len(stems1 & stems2)
    
    # Combined score
    union = len(set1 | set2)
    exact_score = intersection / union if union > 0 else 0.0
    stem_bonus = (stem_intersection * 0.5) / union if union > 0 else 0.0
    
    return min(exact_score + stem_bonus, 1.0)


def text_overlap_score(text1, text2):
    """Word overlap with stem matching."""
    if not text1 or not text2:
        return 0.0
    
    words1 = set(w for w in normalize_text(text1).split() if len(w) > 3)
    words2 = set(w for w in normalize_text(text2).split() if len(w) > 3)
    
    if not words1 or not words2:
        return 0.0
    
    # Exact matches
    intersection = len(words1 & words2)
    union = len(words1 | words2)
    
    return intersection / union if union > 0 else 0.0


# ============================================
# EXPANDED SECURITY CONCEPTS
# ============================================

SECURITY_CONCEPTS = {
    # Injection vulnerabilities
    "sql_injection": ["sql", "sequel", "database query", "sqli"],
    "command_injection": ["command injection", "os command", "shell", "exec", "system call"],
    "code_injection": ["code injection", "script injection", "eval", "deserialization"],
    "xss": ["cross-site scripting", "xss", "reflected", "stored", "dom-based"],
    "xxe": ["xml external entity", "xxe", "xml injection"],
    "ldap_injection": ["ldap", "directory"],
    
    # Authentication & Session
    "authentication": ["authentication", "authn", "verify identity", "login", "credential"],
    "password": ["password", "passphrase", "secret", "credential"],
    "session": ["session", "session id", "session token", "cookie"],
    "token": ["token", "jwt", "bearer", "oauth"],
    "certificate": ["certificate", "cert", "x509", "pki"],
    
    # Authorization & Access Control
    "authorization": ["authorization", "authz", "access control", "permission"],
    "privilege": ["privilege", "privilege escalation", "elevated", "sudo", "admin"],
    "rbac": ["role-based", "role", "rbac"],
    "acl": ["access control list", "acl", "permission"],
    
    # Cryptography
    "encryption": ["encryption", "encrypt", "cipher", "cryptographic"],
    "hashing": ["hash", "hashing", "digest", "checksum"],
    "key_management": ["key management", "key storage", "key generation"],
    "weak_crypto": ["weak cryptography", "broken crypto", "md5", "sha1", "des"],
    "tls_ssl": ["tls", "ssl", "transport layer"],
    
    # Input Validation
    "input_validation": ["input validation", "validate input", "sanitize", "filter"],
    "untrusted_input": ["untrusted input", "user input", "external input"],
    "boundary_check": ["boundary", "bounds check", "length check"],
    "encoding": ["encoding", "encode", "escape", "output encoding"],
    
    # Memory Safety
    "buffer_overflow": ["buffer overflow", "buffer overrun", "stack overflow"],
    "memory_corruption": ["memory corruption", "heap corruption", "use after free"],
    "integer_overflow": ["integer overflow", "integer underflow", "wrap"],
    "null_pointer": ["null pointer", "null dereference", "nullptr"],
    
    # Path & File Operations
    "path_traversal": ["path traversal", "directory traversal", "dot dot slash"],
    "file_upload": ["file upload", "upload", "arbitrary file"],
    "file_inclusion": ["file inclusion", "lfi", "rfi", "include"],
    
    # Configuration & Deployment
    "misconfiguration": ["misconfiguration", "default config", "insecure default"],
    "hardening": ["hardening", "secure configuration", "baseline"],
    "least_privilege": ["least privilege", "principle of least privilege", "minimal permission"],
    
    # Logging & Monitoring
    "logging": ["logging", "log", "audit", "audit trail"],
    "monitoring": ["monitoring", "detection", "alerting", "siem"],
    "forensics": ["forensics", "incident response", "investigation"],
    
    # Data Protection
    "sensitive_data": ["sensitive data", "confidential", "pii", "personal information"],
    "data_exposure": ["information disclosure", "data leakage", "exposure"],
    "privacy": ["privacy", "data protection", "gdpr"],
    
    # Error Handling
    "error_handling": ["error handling", "exception", "error message"],
    "information_leak": ["information leakage", "verbose error", "stack trace"],
    
    # Resource Management
    "resource_exhaustion": ["resource exhaustion", "dos", "denial of service"],
    "memory_leak": ["memory leak", "resource leak"],
    "rate_limiting": ["rate limiting", "throttling", "quota"],
    
    # Network Security
    "network": ["network", "protocol", "tcp", "http"],
    "firewall": ["firewall", "network filter", "packet filter"],
    "segmentation": ["network segmentation", "isolation", "vlan"],
}


def get_concepts(text):
    """Return set of security concepts present in text."""
    text_norm = normalize_text(text)
    matches = set()
    
    for concept_name, keywords in SECURITY_CONCEPTS.items():
        for keyword in keywords:
            if keyword in text_norm:
                matches.add(concept_name)
                break
    
    return matches


# ============================================
# MAPPING: ATT&CK → CWE (IMPROVED)
# ============================================

def map_attack_to_cwe(mitre_nodes, cwe_nodes):
    """
    Map ATT&CK techniques to CWE weaknesses.
    IMPROVED scoring with lower thresholds and better matching.
    """
    mappings = []
    
    print(f"[+] Mapping {len(mitre_nodes)} ATT&CK → {len(cwe_nodes)} CWE...")
    
    for i, mitre in enumerate(mitre_nodes):
        if (i + 1) % 20 == 0:
            print(f"    Progress: {i+1}/{len(mitre_nodes)} ATT&CK techniques...")
        
        att_id = mitre["id"]
        att_title = mitre.get("title", "")
        att_desc = mitre.get("description", "")[:500]  # First 500 chars
        att_keywords = mitre.get("keywords", [])
        att_full = f"{att_title} {att_desc}"
        att_concepts = get_concepts(att_full)
        
        for cwe in cwe_nodes:
            cwe_id = cwe["id"]
            cwe_title = cwe.get("title", "")
            cwe_desc = cwe.get("description", "")[:500]
            cwe_keywords = cwe.get("keywords", [])
            cwe_full = f"{cwe_title} {cwe_desc}"
            cwe_concepts = get_concepts(cwe_full)
            
            score = 0.0
            
            # 1. Title similarity (fuzzy matching - more lenient)
            title_sim = fuzzy_similarity(att_title, cwe_title)
            if title_sim > 0.7:
                score += 0.4
            elif title_sim > 0.5:
                score += 0.3
            elif title_sim > 0.3:
                score += 0.2
            elif title_sim > 0.2:
                score += 0.1
            elif title_sim > 0.1:
                score += 0.05
            
            # 2. Keyword overlap (with stem matching)
            kw_overlap = keyword_overlap_score(att_keywords, cwe_keywords)
            if kw_overlap > 0.4:
                score += 0.35
            elif kw_overlap > 0.25:
                score += 0.25
            elif kw_overlap > 0.15:
                score += 0.18
            elif kw_overlap > 0.08:
                score += 0.12
            elif kw_overlap > 0.03:
                score += 0.06
            
            # 3. Security concepts (expanded list)
            shared = att_concepts & cwe_concepts
            concept_bonus = min(len(shared) * 0.12, 0.35)  # 0.12 per concept, max 0.35
            score += concept_bonus
            
            # 4. Description overlap
            desc_overlap = text_overlap_score(att_desc, cwe_desc)
            if desc_overlap > 0.2:
                score += 0.2
            elif desc_overlap > 0.12:
                score += 0.15
            elif desc_overlap > 0.06:
                score += 0.08
            elif desc_overlap > 0.03:
                score += 0.04
            
            # 5. Bonus: if keywords appear in opposite descriptions
            att_in_cwe = sum(1 for k in att_keywords if normalize_text(k) in normalize_text(cwe_full))
            cwe_in_att = sum(1 for k in cwe_keywords if normalize_text(k) in normalize_text(att_full))
            cross_mention = (att_in_cwe + cwe_in_att) / max(len(att_keywords) + len(cwe_keywords), 1)
            if cross_mention > 0.1:
                score += min(cross_mention * 0.3, 0.15)
            
            score = min(score, 1.0)
            
            if score > MIN_SCORE_TO_SAVE:
                mappings.append({
                    "src_id": att_id,
                    "dst_id": cwe_id,
                    "relation_type": "related_to",
                    "evidence": round(score, 3)
                })
    
    print(f"    ✓ Found {len(mappings)} ATT&CK→CWE mappings")
    return mappings


# ============================================
# MAPPING: CWE → NIST (IMPROVED)
# ============================================

def map_cwe_to_nist(cwe_nodes, nist_nodes):
    """
    Map CWE weaknesses to NIST controls.
    IMPROVED scoring - mitigation relationships.
    """
    mappings = []
    
    print(f"[+] Mapping {len(cwe_nodes)} CWE → {len(nist_nodes)} NIST...")
    
    for i, cwe in enumerate(cwe_nodes):
        if (i + 1) % 50 == 0:
            print(f"    Progress: {i+1}/{len(cwe_nodes)} CWE weaknesses...")
        
        cwe_id = cwe["id"]
        cwe_title = cwe.get("title", "")
        cwe_desc = cwe.get("description", "")[:600]
        cwe_keywords = cwe.get("keywords", [])
        cwe_categories = cwe.get("categories", [])
        cwe_full = f"{cwe_title} {cwe_desc}"
        cwe_concepts = get_concepts(cwe_full)
        
        for nist in nist_nodes:
            nist_id = nist["id"]
            nist_title = nist.get("title", "")
            nist_desc = nist.get("description", "")[:600]
            nist_keywords = nist.get("keywords", [])
            nist_categories = nist.get("categories", [])
            nist_full = f"{nist_title} {nist_desc}"
            nist_concepts = get_concepts(nist_full)
            
            score = 0.0
            
            # 1. Title similarity
            title_sim = fuzzy_similarity(cwe_title, nist_title)
            if title_sim > 0.6:
                score += 0.35
            elif title_sim > 0.4:
                score += 0.25
            elif title_sim > 0.25:
                score += 0.18
            elif title_sim > 0.15:
                score += 0.1
            elif title_sim > 0.08:
                score += 0.05
            
            # 2. Keyword overlap (very important for mitigation)
            kw_overlap = keyword_overlap_score(cwe_keywords, nist_keywords)
            if kw_overlap > 0.3:
                score += 0.4
            elif kw_overlap > 0.2:
                score += 0.3
            elif kw_overlap > 0.12:
                score += 0.22
            elif kw_overlap > 0.06:
                score += 0.15
            elif kw_overlap > 0.03:
                score += 0.08
            
            # 3. Security concepts
            shared = cwe_concepts & nist_concepts
            concept_bonus = min(len(shared) * 0.14, 0.4)  # 0.14 per concept, max 0.4
            score += concept_bonus
            
            # 4. Description overlap (control describes mitigation)
            desc_overlap = text_overlap_score(cwe_desc, nist_desc)
            if desc_overlap > 0.15:
                score += 0.25
            elif desc_overlap > 0.08:
                score += 0.18
            elif desc_overlap > 0.04:
                score += 0.1
            elif desc_overlap > 0.02:
                score += 0.05
            
            # 5. Category alignment (e.g., AC family for authorization issues)
            category_match = False
            for cc in cwe_categories:
                for nc in nist_categories:
                    if normalize_text(cc) in normalize_text(nc) or normalize_text(nc) in normalize_text(cc):
                        category_match = True
                        break
            if category_match:
                score += 0.1
            
            # 6. Cross-mention bonus
            cwe_in_nist = sum(1 for k in cwe_keywords if normalize_text(k) in normalize_text(nist_full))
            nist_in_cwe = sum(1 for k in nist_keywords if normalize_text(k) in normalize_text(cwe_full))
            cross_mention = (cwe_in_nist + nist_in_cwe) / max(len(cwe_keywords) + len(nist_keywords), 1)
            if cross_mention > 0.08:
                score += min(cross_mention * 0.4, 0.2)
            
            score = min(score, 1.0)
            
            if score > MIN_SCORE_TO_SAVE:
                mappings.append({
                    "src_id": cwe_id,
                    "dst_id": nist_id,
                    "relation_type": "mitigated_by",
                    "evidence": round(score, 3)
                })
    
    print(f"    ✓ Found {len(mappings)} CWE→NIST mappings")
    return mappings


# ============================================
# MAIN
# ============================================

def main():
    print("=" * 70)
    print("CROSSWALK MAPPER: ATT&CK → CWE → NIST")
    print("IMPROVED SCORING ALGORITHM")
    print("=" * 70)
    
    # Load nodes
    print(f"\n[+] Loading standardized nodes from {NODES_FILE}...")
    mitre_nodes, cwe_nodes, nist_nodes = load_nodes_by_source(NODES_FILE)
    
    print(f"    MITRE ATT&CK: {len(mitre_nodes)} techniques")
    print(f"    CWE: {len(cwe_nodes)} weaknesses")
    print(f"    NIST: {len(nist_nodes)} controls")
    
    # Generate mappings
    print(f"\n[+] Generating mappings with improved scoring...")
    
    attack_cwe = map_attack_to_cwe(mitre_nodes, cwe_nodes)
    cwe_nist = map_cwe_to_nist(cwe_nodes, nist_nodes)
    
    # Combine all
    all_mappings = attack_cwe + cwe_nist
    
    print(f"\n[+] Total mappings: {len(all_mappings):,}")
    print(f"    ATT&CK → CWE: {len(attack_cwe):,}")
    print(f"    CWE → NIST: {len(cwe_nist):,}")
    
    # Score distribution
    print(f"\n[+] Score distribution:")
    buckets = defaultdict(int)
    for m in all_mappings:
        score = m["evidence"]
        if score >= 0.8:
            buckets["0.8-1.0"] += 1
        elif score >= 0.6:
            buckets["0.6-0.8"] += 1
        elif score >= 0.4:
            buckets["0.4-0.6"] += 1
        elif score >= 0.2:
            buckets["0.2-0.4"] += 1
        else:
            buckets["0.0-0.2"] += 1
    
    for bucket in ["0.8-1.0", "0.6-0.8", "0.4-0.6", "0.2-0.4", "0.0-0.2"]:
        count = buckets[bucket]
        pct = (count / len(all_mappings) * 100) if all_mappings else 0
        print(f"    {bucket}: {count:,} ({pct:.1f}%)")
    
    # Write CSV
    print(f"\n[+] Writing mappings to {OUT_MAPPINGS}...")
    with open(OUT_MAPPINGS, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["src_id", "dst_id", "relation_type", "evidence"])
        writer.writeheader()
        
        # Sort by score descending
        for m in sorted(all_mappings, key=lambda x: -x["evidence"]):
            writer.writerow(m)
    
    print("\n" + "=" * 70)
    print("✓ CROSSWALK GENERATION COMPLETE")
    print("=" * 70)
    print(f"Output: {OUT_MAPPINGS}")
    print(f"Total mappings: {len(all_mappings):,}")


if __name__ == "__main__":
    main()