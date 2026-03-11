

import json
import os
import chromadb
from sentence_transformers import SentenceTransformer

# ─── Config ───────────────────────────────────────────────────────────────────

DATA_FILE   = "data/assets_v2.json"
CHROMA_PATH = "chroma_db"
COLLECTION  = "cyber_assets"
EMBED_MODEL = "all-MiniLM-L6-v2"

# ─── Load Models & DB ─────────────────────────────────────────────────────────

print("🔄 Loading embedding model...")
model = SentenceTransformer(EMBED_MODEL)

print(f"🔄 Connecting to ChromaDB at '{CHROMA_PATH}'...")
client     = chromadb.PersistentClient(path=CHROMA_PATH)

# Delete existing collection so re-runs always start fresh
existing = [c.name for c in client.list_collections()]
if COLLECTION in existing:
    client.delete_collection(name=COLLECTION)
    print(f"🗑️  Deleted existing collection '{COLLECTION}'")

collection = client.create_collection(name=COLLECTION)
print(f"✅ Created fresh collection '{COLLECTION}'")

# ─── Load Data ────────────────────────────────────────────────────────────────

with open(DATA_FILE, "r") as f:
    assets = json.load(f)

print(f"📂 Loaded {len(assets)} assets from '{DATA_FILE}'")

# ─── Build Documents, Metadata, IDs ──────────────────────────────────────────

documents = []
metadatas = []
ids       = []

for asset in assets:
    vulns     = asset.get("vulnerabilities", [])
    owner     = asset.get("owner", {})
    os_info   = asset.get("os", {})
    software  = asset.get("software", {})

    # ── Vulnerability summary text ──
    if vulns:
        vuln_lines = []
        for v in vulns:
            exploit_tag = "⚠️ Exploit available" if v["exploit_available"] else "No exploit"
            patch_tag   = "✅ Patch available"   if v["patch_available"]   else "❌ No patch"
            vuln_lines.append(
                f"  • {v['cve']} | Severity: {v['severity']} | CVSS: {v['cvss_score']} "
                f"| {exploit_tag} | {patch_tag}\n"
                f"    Description: {v['description']}"
            )
        vuln_text = "\n".join(vuln_lines)
    else:
        vuln_text = "  No known vulnerabilities."

    # ── Owner text ──
    if owner.get("status") == "orphan":
        owner_text = "UNOWNED (orphan asset — no responsible team assigned)"
    else:
        owner_text = f"{owner.get('team', 'Unknown')} ({owner.get('email', 'N/A')})"

    # ── Full rich text representation ──
    text = f"""Asset ID: {asset['asset_id']}
Asset Type: {asset['asset_type']}
Environment: {asset['environment']}
Criticality: {asset['criticality']}
IP Address: {asset['ip_address']}
Domain: {asset['domain']}
Internet Exposed: {'Yes' if asset['internet_exposed'] else 'No'}
Operating System: {os_info.get('name', 'Unknown')} {os_info.get('version', '')}
Software: {software.get('name', 'Unknown')} v{software.get('version', 'Unknown')}
Open Ports: {', '.join(str(p) for p in asset.get('open_ports', []))}
Owner / Responsible Team: {owner_text}
Last Scan Date: {asset['last_scan_date']}
Risk Score: {asset['risk_score']} / 100

Vulnerabilities:
{vuln_text}
"""

    # ── Structured metadata (for filtered queries) ──
    max_cvss = max((v["cvss_score"] for v in vulns), default=0.0)
    has_exploit = any(v["exploit_available"] for v in vulns)
    severities  = list({v["severity"] for v in vulns})

    metadata = {
        "asset_id":        asset["asset_id"],
        "asset_type":      asset["asset_type"],
        "environment":     asset["environment"],
        "criticality":     asset["criticality"],
        "ip_address":      asset["ip_address"],
        "internet_exposed": str(asset["internet_exposed"]),   # ChromaDB requires str/int/float
        "os_name":         os_info.get("name", ""),
        "os_version":      os_info.get("version", ""),
        "software_name":   software.get("name", ""),
        "software_version": software.get("version", ""),
        "owner_team":      owner.get("team") or "orphan",
        "owner_status":    owner.get("status", "assigned"),
        "risk_score":      float(asset["risk_score"]),
        "max_cvss":        float(max_cvss),
        "has_exploit":     str(has_exploit),
        "vuln_count":      len(vulns),
        "severities":      ", ".join(severities),
        "last_scan_date":  asset["last_scan_date"],
    }

    documents.append(text)
    metadatas.append(metadata)
    ids.append(asset["asset_id"])

# ─── Embed & Store ────────────────────────────────────────────────────────────

print("🔄 Generating embeddings (this may take a moment)...")
embeddings = model.encode(documents, show_progress_bar=True).tolist()

print("💾 Storing in ChromaDB...")
# Batch insert in chunks of 50 to avoid memory spikes
BATCH = 50
for start in range(0, len(documents), BATCH):
    end = start + BATCH
    collection.add(
        documents  = documents[start:end],
        embeddings = embeddings[start:end],
        metadatas  = metadatas[start:end],
        ids        = ids[start:end],
    )
    print(f"   Stored batch {start//BATCH + 1} ({start}–{min(end, len(documents))-1})")

# ─── Summary ─────────────────────────────────────────────────────────────────

total = collection.count()
print(f"\n✅ Ingestion complete — {total} assets stored in ChromaDB")

orphans   = sum(1 for m in metadatas if m["owner_status"] == "orphan")
exposed   = sum(1 for m in metadatas if m["internet_exposed"] == "True")
exploits  = sum(1 for m in metadatas if m["has_exploit"] == "True")
high_risk = sum(1 for m in metadatas if m["risk_score"] >= 70)

print(f"\n📊 Dataset Summary:")
print(f"   • Total assets      : {total}")
print(f"   • Internet-exposed  : {exposed}")
print(f"   • Have exploits     : {exploits}")
print(f"   • High risk (≥70)   : {high_risk}")
print(f"   • Orphan assets     : {orphans}")
