import json
import chromadb
from sentence_transformers import SentenceTransformer

embed_model = SentenceTransformer("all-MiniLM-L6-v2")
client = chromadb.PersistentClient(path="chroma_db")
collection = client.get_or_create_collection(name="cyber_assets")

with open("data/assets_v2.json") as f:
    assets = json.load(f)

for asset in assets:

    # Chunk 1 — General Info
    general_chunk = f"""
    Asset ID: {asset['asset_id']}
    Type: {asset['asset_type']}
    Environment: {asset['environment']}
    Criticality: {asset['criticality']}
    Owner Team: {asset['owner']['team']}
    Operating System: {asset['os']}
    Risk Score: {asset['risk_score']}
    """

    # Chunk 2 — Network Exposure
    network_chunk = f"""
    Asset {asset['asset_id']} has open ports {asset['open_ports']}
    Services running: {asset['services']}
    """

    # Chunk 3 — Vulnerabilities
    vuln = asset["vulnerabilities"][0]
    vuln_chunk = f"""
    Asset {asset['asset_id']} vulnerability details:
    CVE: {vuln['cve']}
    Severity: {vuln['severity']}
    CVSS Score: {vuln['cvss_score']}
    Exploit Available: {vuln['exploit_available']}
    Patch Available: {vuln['patch_available']}
    Description: {vuln['description']}
    """

    chunks = [general_chunk, network_chunk, vuln_chunk]

    for idx, chunk in enumerate(chunks):
        embedding = embed_model.encode(chunk).tolist()

        collection.add(
            documents=[chunk],
            embeddings=[embedding],
            ids=[f"{asset['asset_id']}_chunk_{idx}"],
            metadatas=[{
                "asset_id": asset["asset_id"],
                "severity": vuln["severity"],
                "environment": asset["environment"]
            }]
        )

print("Ingestion complete.")