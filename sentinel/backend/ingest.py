import json
import chromadb
from sentence_transformers import SentenceTransformer
from chromadb.config import Settings


# Load embedding model (free, small, fast)
model = SentenceTransformer("all-MiniLM-L6-v2")

# Create persistent Chroma database
#client = chromadb.Client()
client = chromadb.Client(
    Settings(
        persist_directory="chroma_db"
    )
)
collection = client.get_or_create_collection(name="cyber_assets")

# Load your single JSON file
with open("data/mock_data.json", "r") as f:
    data = json.load(f)

documents = []
ids = []

for i, asset in enumerate(data):
    # Convert vulnerabilities into readable text
    vuln_text = ""
    for vuln in asset["vulnerabilities"]:
        vuln_text += f"""
        CVE: {vuln['cve']}
        Severity: {vuln['severity']}
        Description: {vuln['description']}
        """

    text_representation = f"""
    Asset ID: {asset['asset_id']}
    Asset Type: {asset['asset_type']}
    Owner: {asset['owner']}
    IP Address: {asset['ip_address']}
    Open Ports: {asset['open_ports']}
    Vulnerabilities:
    {vuln_text}
    """

    documents.append(text_representation)
    ids.append(asset["asset_id"])

# Generate embeddings
embeddings = model.encode(documents).tolist()

# Store in Chroma
collection.add(
    documents=documents,
    embeddings=embeddings,
    ids=ids
)
print("✅ Mock data successfully ingested into Chroma!")