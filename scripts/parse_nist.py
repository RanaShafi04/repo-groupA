import pandas as pd
import jsonlines
from pathlib import Path

SOURCE_PATH = Path("data/source/nist_sp800-53_controls.xlsx")
OUT_JSONL = Path("data/interim/nist_parsed.jsonl")

print("[+] Loading NIST Excel...")
df = pd.read_excel(SOURCE_PATH)

# Normalize column names for safety
df.columns = df.columns.str.strip()

# Identify your exact columns
col_family    = "Control Family"
col_id        = "Control (or Control Enhancement) Identifier"
col_name      = "Control (or Control Enhancement) Name"
col_statement = "Control Statement"
col_supp      = "Discussion"

# --- FIX THE MERGED FAMILY CELLS ---
df[col_family] = df[col_family].ffill()

records = []

for _, row in df.iterrows():
    control_id = str(row[col_id]).strip()
    if not control_id or control_id == "nan":
        continue

    record = {
        "id": control_id,
        "family": str(row[col_family]).strip(),
        "title": str(row[col_name]).strip(),
        "text": str(row[col_statement]).strip(),
        "supplemental_guidance": str(row[col_supp]).strip()
    }

    records.append(record)

print(f"[+] Extracted {len(records)} NIST controls")

# Save JSONL
OUT_JSONL.parent.mkdir(parents=True, exist_ok=True)
with jsonlines.open(OUT_JSONL, "w") as writer:
    writer.write_all(records)

print(f"[✓] Saved NIST JSONL → {OUT_JSONL}")

print("\nSample record:")
print(records[0] if records else "No records found.")
