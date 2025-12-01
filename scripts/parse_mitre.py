#!/usr/bin/env python3
import json
from pathlib import Path
import html
import re

# ============================================
# PATHS
# ============================================
REPO_ROOT = Path(__file__).resolve().parents[1]
RAW = REPO_ROOT / "data/source"
INTERIM = REPO_ROOT / "data/interim"

INTERIM.mkdir(exist_ok=True)

MITRE_FILE = RAW / "mitre_attack_stix.json"   # <-- Replace if your file name differs
OUT_FILE = INTERIM / "mitre_parsed.jsonl"


# ============================================
# UTILS
# ============================================

def clean_html(text):
    if not text:
        return ""
    text = html.unescape(text)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def normalize_id(stix_id):
    # Example: attack-pattern--uuid → T1047
    if not stix_id:
        return ""
    return stix_id.strip()


def get_attack_id(obj):
    """
    STIX ATT&CK IDs stored in:
    external_references: [{ source_name: "mitre-attack", external_id: "T1059.003" }]
    """
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ["mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"]:
            if "external_id" in ref:
                return ref["external_id"]
    return None


def get_description(obj):
    if obj.get("description"):
        return clean_html(obj["description"])
    if obj.get("x_mitre_description"):
        return clean_html(obj["x_mitre_description"])
    return ""


def get_keywords(obj):
    kws = []

    if obj.get("kill_chain_phases"):
        for k in obj["kill_chain_phases"]:
            if "phase_name" in k:
                kws.append(k["phase_name"].lower())

    if obj.get("x_mitre_platforms"):
        for p in obj["x_mitre_platforms"]:
            kws.append(p.lower())

    if obj.get("x_mitre_permissions_required"):
        for p in obj["x_mitre_permissions_required"]:
            kws.append(p.lower())

    return list(sorted(set(kws)))


def get_tactics(obj):
    """Returns list of ATT&CK tactics."""
    if not obj.get("kill_chain_phases"):
        return []
    t = []
    for phase in obj["kill_chain_phases"]:
        if phase.get("kill_chain_name") == "mitre-attack":
            t.append(phase.get("phase_name"))
    return t


# ============================================
# MAIN PARSER
# ============================================

def parse_mitre():
    print(f"[+] Loading MITRE ATT&CK {MITRE_FILE}")
    with open(MITRE_FILE, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])
    nodes = []

    print(f"[+] Parsing {len(objects)} STIX objects...")

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        external_id = get_attack_id(obj)
        if not external_id:
            continue   # skip non-techniques

        node = {
            "id": external_id,                         # T1059 / T1059.003
            "source": "MITRE",
            "title": obj.get("name", ""),
            "description": get_description(obj),

            "summary_512": "",                         # to be filled later
            "categories": [],                          # ATT&CK doesn't really have categories
            "keywords": get_keywords(obj),
            "tactics": get_tactics(obj),               # Discovery, Execution, etc.
            "mitigations": "",                         # filled later
            "rev_date": obj.get("modified", "") or obj.get("created", ""),
            "url": f"https://attack.mitre.org/techniques/{external_id}/"
        }

        nodes.append(node)

    # ========================================
    # ADD MITIGATIONS FROM RELATIONSHIPS
    # ========================================

    mitigation_map = {}   # technique ID => list of mitigations

    for obj in objects:
        if obj.get("type") != "relationship":
            continue

        if obj.get("relationship_type") != "mitigates":
            continue

        src = obj.get("source_ref", "")     # mitigation object
        tgt = obj.get("target_ref", "")     # attack-pattern object

        # Extract ATT&CK external ID from target
        attack_id = None
        for o in objects:
            if o.get("id") == tgt and o.get("type") == "attack-pattern":
                attack_id = get_attack_id(o)
                break

        if not attack_id:
            continue

        # Extract mitigation text from source
        mitigation_text = ""
        for o in objects:
            if o.get("id") == src and o.get("type") == "course-of-action":
                mitigation_text = clean_html(o.get("description", ""))
                break

        if not mitigation_text:
            continue

        mitigation_map.setdefault(attack_id, []).append(mitigation_text)

    # Attach mitigation text
    for n in nodes:
        if n["id"] in mitigation_map:
            n["mitigations"] = " ".join(mitigation_map[n["id"]])

    print(f"[+] Final MITRE nodes: {len(nodes)}")

    return nodes


# ============================================
# WRITE OUTPUT
# ============================================

if __name__ == "__main__":
    nodes = parse_mitre()
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for n in nodes:
            f.write(json.dumps(n) + "\n")

    print(f"[+] Saved MITRE parsed dataset → {OUT_FILE}")
