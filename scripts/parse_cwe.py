import xml.etree.ElementTree as ET
import jsonlines
from pathlib import Path

# === Paths ===
SOURCE_PATH = Path("data/source/cwe.xml")
OUTPUT_PATH = Path("data/interim/cwe_parsed.jsonl")

# === Parse XML ===
print("[+] Parsing CWE XML...")
tree = ET.parse(SOURCE_PATH)
root = tree.getroot()

# Use correct namespace (from your file)
ns = {"ns": "http://cwe.mitre.org/cwe-7"}

records = []
for weakness in root.findall(".//ns:Weakness", ns):
    cwe_id = weakness.attrib.get("ID")
    name = weakness.attrib.get("Name")
    weakness_abstraction = weakness.attrib.get("Abstraction")

    # Get description text
    desc_elem = weakness.find("ns:Description", ns)
    description = desc_elem.text.strip() if desc_elem is not None else ""

    # Extract relationships
    relationships = []
    for rel in weakness.findall(".//ns:Related_Weakness", ns):
        related_id = rel.attrib.get("CWE_ID")
        rel_type = rel.attrib.get("Nature")
        if related_id:
            relationships.append({"related_id": related_id, "type": rel_type})

    records.append({
        "id": f"CWE-{cwe_id}",
        "name": name,
        "description": description,
        "weakness_abstraction":weakness_abstraction,
        "relationships": relationships
    })

print(f"[+] Extracted {len(records)} CWE entries")

# === Write to JSONL ===
OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
with jsonlines.open(OUTPUT_PATH, mode="w") as writer:
    writer.write_all(records)

print(f"Saved parsed data to {OUTPUT_PATH}")
