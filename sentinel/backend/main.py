from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
import ollama
import chromadb
from sentence_transformers import SentenceTransformer
from db import get_db, Asset, Vulnerability, Owner
 
app = FastAPI(
    title="Sentinel API",
    description="AI-Driven Cyber Asset & Attack Surface Management",
    version="2.0"
)
 
embed_model = SentenceTransformer("all-MiniLM-L6-v2")
 
chroma_client = chromadb.PersistentClient(path="chroma_db")
collection = chroma_client.get_or_create_collection(name="cyber_assets")
 
@app.get("/")
def root():
    return {"message": "Sentinel backend is running", "version": "2.0"}
 
@app.get("/assets")
def get_assets(
    db: Session = Depends(get_db),
    environment:      str  = None,
    criticality:      str  = None,
    internet_exposed: bool = None,
    owner_status:     str  = None,   # "assigned" or "orphan"
):
    query = db.query(Asset)

    if environment:
        query = query.filter(Asset.environment == environment)
 
    if criticality:
        query = query.filter(Asset.criticality == criticality)
 
    if internet_exposed is not None:
        query = query.filter(Asset.internet_exposed == internet_exposed)
 
    if owner_status:
        query = query.join(Owner).filter(Owner.status == owner_status)
 
    assets = query.all()
 
    return {
        "assets": [a.to_dict() for a in assets],
        "total":  len(assets)
    }

 
@app.get("/assets/{asset_id}")
def get_asset(
    asset_id: str,              # captured from the URL path
    db: Session = Depends(get_db),
):
    
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
 
    if not asset:
        raise HTTPException(
            status_code=404,
            detail=f"Asset '{asset_id}' not found"
        )
 
    return asset.to_dict()
 
 
@app.get("/risk-summary")
def get_risk_summary(db: Session = Depends(get_db)):
    top_assets = (
        db.query(Asset)
        .filter(Asset.risk_score != None)     # exclude assets not yet scored
        .order_by(Asset.risk_score.desc())    # highest score first
        .limit(10)
        .all()
    )
 
    return {
        "top_risk_assets": [a.to_dict() for a in top_assets],
        "total_returned":  len(top_assets)
    }
 
@app.get("/vulnerabilities")
def get_vulnerabilities(
    db:               Session = Depends(get_db),
    severity:         str  = None,    # "Critical", "High", "Medium", "Low"
    exploit_available: bool = None,   # true or false
    patch_available:   bool = None,   # true or false
):
    query = db.query(Vulnerability)
 
    if severity:
        query = query.filter(Vulnerability.severity == severity)
 
    if exploit_available is not None:
        query = query.filter(Vulnerability.exploit_available == exploit_available)
 
    if patch_available is not None:
        query = query.filter(Vulnerability.patch_available == patch_available)
 
    vulns = query.all()
 
    return {
        "vulnerabilities": [v.to_dict() for v in vulns],
        "total":           len(vulns)
    }
 
@app.get("/orphans")
def get_orphans(db: Session = Depends(get_db)):
 
    # JOIN assets with owners and filter where status is "orphan"
    orphan_assets = (
        db.query(Asset)
        .join(Owner)
        .filter(Owner.status == "orphan")
        .all()
    )
 
    return {
        "orphan_assets": [a.to_dict() for a in orphan_assets],
        "total":         len(orphan_assets)
    }
 
@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
 
    # .count() is more efficient than .all() when you only need the number
    # It generates: SELECT COUNT(*) FROM assets WHERE ...
    total_assets   = db.query(Asset).count()
 
    critical_count = db.query(Asset).filter(
        Asset.risk_level == "Critical"
    ).count()
 
    exposed_count  = db.query(Asset).filter(
        Asset.internet_exposed == True
    ).count()
 
    orphan_count   = db.query(Owner).filter(
        Owner.status == "orphan"
    ).count()
 
    high_risk_count = db.query(Asset).filter(
        Asset.risk_score >= 70
    ).count()
 
    total_vulns    = db.query(Vulnerability).count()
 
    exploit_count  = db.query(Vulnerability).filter(
        Vulnerability.exploit_available == True
    ).count()
 
    return {
        "total_assets":    total_assets,
        "critical_count":  critical_count,
        "exposed_count":   exposed_count,
        "orphan_count":    orphan_count,
        "high_risk_count": high_risk_count,
        "total_vulns":     total_vulns,
        "exploit_count":   exploit_count,
    }
 
@app.get("/ask")
def ask(question: str):
 
    # Step 1: Embed the user's question into a vector
    query_embedding = embed_model.encode(question).tolist()
 
    # Step 2: Search ChromaDB for the 5 most similar asset documents
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=5
    )
 
    # Join the retrieved documents into one context string
    retrieved_docs = "\n".join(results["documents"][0])
 
    # Step 3: Send context + question to Phi3 via Ollama
    response = ollama.chat(
        model="phi3",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity asset intelligence assistant. "
                    "Answer strictly using the provided context. "
                    "If the answer is not in the context, say: "
                    "'No relevant asset found.'"
                )
            },
            {
                "role": "user",
                "content": f"""
                Context:
                {retrieved_docs}
 
                Question:
                {question}
                """
            }
        ]
    )
 
    return {"response": response["message"]["content"]}