# ─── PART 1: IMPORTS ─────────────────────────────────────────────────────────
# Everything your original main.py had — kept exactly the same
from fastapi import FastAPI, Depends, HTTPException
# ↑ HTTPException is new — lets us return proper error messages
# ↑ Depends is new — used for database session injection
 
from sqlalchemy.orm import Session
# ↑ Session is the type hint for our database session
 
import ollama
import chromadb
from sentence_transformers import SentenceTransformer
 
# Smart RAG: intent detection + metadata-filtered ChromaDB retrieval.
# This replaces the naive n_results=5 similarity search in /ask.
# smart_rag.py must sit in the same directory as main.py (backend/).
from smart_rag import build_rag_context
 
# New imports for PostgreSQL
# We import everything we need from db.py
from db import get_db, Asset, Vulnerability, Owner
 
# ─── PART 2: APP + MODEL SETUP ───────────────────────────────────────────────
# Everything here is IDENTICAL to your original main.py
# We don't touch the ChromaDB or embedding model setup at all
 
app = FastAPI(
    title="Sentinel API",
    description="AI-Driven Cyber Asset & Attack Surface Management",
    version="2.0"
)
 
# Load embedding model ONCE when the server starts
# Loading it inside an endpoint would be very slow
embed_model = SentenceTransformer("all-MiniLM-L6-v2")
 
# Connect to ChromaDB — same as before
chroma_client = chromadb.PersistentClient(path="chroma_db")
collection = chroma_client.get_or_create_collection(name="cyber_assets")
 
 
# ─── PART 3: HEALTH CHECK ────────────────────────────────────────────────────
# Unchanged from your original
@app.get("/")
def root():
    return {"message": "Sentinel backend is running", "version": "2.0"}
 
 
# ─── PART 4: NEW POSTGRESQL ENDPOINTS ────────────────────────────────────────
 
# ── Endpoint 1: GET /assets ───────────────────────────────────────────────────
# Returns all assets from PostgreSQL
# Supports optional filters via query parameters
 
@app.get("/assets")
def get_assets(
    db: Session = Depends(get_db),
    environment:      str  = None,
    criticality:      str  = None,
    internet_exposed: bool = None,
    owner_status:     str  = None,   # "assigned" or "orphan"
    slim:             bool = True,   # True = skip loading vulnerabilities (fast)
                                     # False = include vulnerabilities (slow)
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
 
    if slim:
        # Slim mode: return only table columns — no CVE list
        # This is MUCH faster for the Asset Inventory table
        # because it avoids loading hundreds of vulnerability rows
        def slim_dict(a):
            owner = a.owner
            return {
                "asset_id":        a.asset_id,
                "asset_type":      a.asset_type,
                "environment":     a.environment,
                "criticality":     a.criticality,
                "ip_address":      a.ip_address,
                "domain":          a.domain,
                "internet_exposed": a.internet_exposed,
                "os": {
                    "name":    a.os_name,
                    "version": a.os_version,
                },
                "software": {
                    "name":    a.software_name,
                    "version": a.software_version,
                },
                "risk_score":  a.risk_score,
                "risk_level":  a.risk_level,
                "last_scan_date": str(a.last_scan_date) if a.last_scan_date else None,
                "owner": {
                    "team":   owner.team if owner else None,
                    "email":  owner.email if owner else None,
                    "status": owner.status if owner else "orphan",
                } if owner else None,
                "vulnerabilities": [],  # empty in slim mode
            }
        return {"assets": [slim_dict(a) for a in assets], "total": len(assets)}
 
    # Full mode: include all vulnerabilities (used by /assets/{id})
    return {
        "assets": [a.to_dict() for a in assets],
        "total":  len(assets)
    }
 
 
# ── Endpoint 2: GET /assets/{asset_id} ───────────────────────────────────────
# Returns full detail for ONE specific asset including its CVEs and owner
# {asset_id} is a path parameter — it comes from the URL itself
# Example: /assets/ASSET-1042
 
@app.get("/assets/{asset_id}")
def get_asset(
    asset_id: str,              # captured from the URL path
    db: Session = Depends(get_db),
):
    # Query for exactly one asset matching this ID
    # .first() returns the first match or None if not found
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
 
    # If no asset was found, return a 404 error
    # HTTPException tells FastAPI to return a proper HTTP error response
    # instead of crashing
    if not asset:
        raise HTTPException(
            status_code=404,
            detail=f"Asset '{asset_id}' not found"
        )
 
    # to_dict() already includes vulnerabilities and owner
    # because we set up the relationships in db.py
    return asset.to_dict()
 
 
# ── Endpoint 3: GET /risk-summary ────────────────────────────────────────────
# Returns the top 10 highest risk assets
# Used by the Risk Dashboard page
 
@app.get("/risk-summary")
def get_risk_summary(db: Session = Depends(get_db)):
 
    # Query assets ordered by risk_score from highest to lowest
    # .desc() means descending (highest first)
    # .limit(10) means only return the top 10
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
 
 
# ── Endpoint 4: GET /vulnerabilities ─────────────────────────────────────────
# Returns all CVEs across all assets
# Supports filters by severity and exploit availability
 
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
 
 
# ── Endpoint 5: GET /orphans ──────────────────────────────────────────────────
# Returns all assets that have no assigned owner
# These are security risks — no one is responsible for them
 
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
 
 
# ── Endpoint 6: GET /stats ────────────────────────────────────────────────────
# Returns summary counts for the dashboard header metric cards
# Example: total assets, critical count, exposed count, orphan count
 
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
 
 
# ─── PART 5: AI Q&A ENDPOINT (UNCHANGED) ─────────────────────────────────────
# This is your original /ask endpoint — NOT modified at all
# ChromaDB + Phi3 RAG pipeline stays exactly as you built it
 
@app.get("/ask")
def ask(question: str):
    """
    AI Q&A endpoint — powered by smart RAG retrieval.
 
    OLD behaviour: embed question → top-5 similarity → Phi3
    NEW behaviour: detect intent → metadata filter → dynamic n_results
                   → intent-tuned system prompt → Phi3
 
    The smart_rag module handles:
      - Intent detection (orphan? exposed? critical? specific asset?)
      - ChromaDB `where` filtering so ALL matching assets are returned
      - Dynamic n_results (e.g. 50 for orphan queries, 15 for general)
      - A tailored system prompt that tells Phi3 exactly what to output
        (e.g. "list every orphan, state total count" vs "give a summary")
 
    Why this matters:
      With 100 assets and 5 orphans, the old endpoint might return 3 orphans
      because the other 2 weren't in the top-5 by embedding similarity.
      The new endpoint filters by owner_status="orphan" first, so it
      always returns all 5 regardless of semantic similarity ranking.
    """
 
    # Step 1: Smart retrieval — returns context + system_prompt + metadata
    rag = build_rag_context(question, collection, embed_model)
 
    # Log retrieval details (useful when debugging RAG quality)
    print(
        f"🔍 RAG | intent={rag['intent']} | "
        f"retrieved={rag['n_retrieved']} | {rag['description']}"
    )
 
    # Step 2: Send to Phi3 with the intent-tuned system prompt
    response = ollama.chat(
        model="phi3",
        messages=[
            {
                "role":    "system",
                "content": rag["system_prompt"],
            },
            {
                "role":    "user",
                "content": f"Context:\n{rag['context']}\n\nQuestion: {question}",
            },
        ]
    )
 
    return {
        "response": response["message"]["content"],
        # rag_debug is shown in the frontend as a small info line under each answer
        # e.g. "Intent: orphan · Retrieved 5 assets · Fetching orphan assets"
        "rag_debug": {
            "intent":      rag["intent"],
            "description": rag["description"],
            "n_retrieved": rag["n_retrieved"],
        },
    }
 
 
# ─── PART 6: ML ENDPOINTS ────────────────────────────────────────────────────
 
# Add ml/ folder to path so we can import predict.py
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ml"))
 
from predict import score_asset
from nvd_connector import get_cves_with_fallback
from ingest import ingest_single_asset
from pydantic import BaseModel
from typing import Optional, List
from datetime import date as DateType
 
 
# ── Request model for POST /assets ───────────────────────────────────────────
# Pydantic model defines exactly what fields the request body must have
# FastAPI validates this automatically — returns 422 if fields are missing
 
class VulnerabilityInput(BaseModel):
    cve:               str
    severity:          str
    cvss_score:        Optional[float] = None
    exploit_available: bool = False
    patch_available:   bool = False
    description:       Optional[str] = ""
 
class OwnerInput(BaseModel):
    team:   Optional[str] = None
    email:  Optional[str] = None
    status: str = "assigned"
 
class AssetInput(BaseModel):
    asset_id:         str
    asset_type:       str
    environment:      str
    criticality:      str
    ip_address:       Optional[str] = None
    domain:           Optional[str] = None
    internet_exposed: bool = False
    os_name:          Optional[str] = None
    os_version:       Optional[str] = None
    software_name:    Optional[str] = None
    software_version: Optional[str] = None
    last_scan_date:   Optional[str] = None
    vulnerabilities:  List[VulnerabilityInput] = []
    owner:            Optional[OwnerInput] = None
 
 
# ── Endpoint: POST /assets ────────────────────────────────────────────────────
# Adds a new asset to PostgreSQL and immediately scores it with ML
# This is the full automation chain in one endpoint
 
@app.post("/assets")
def create_asset(asset_input: AssetInput, db: Session = Depends(get_db)):
    """
    Add a new asset and auto-score it with ML.
 
    Flow:
    1. Check asset_id doesn't already exist
    2. Save asset to PostgreSQL (risk_score = NULL)
    3. Save vulnerabilities to PostgreSQL
    4. Save owner to PostgreSQL
    5. Run ML scoring on the new asset
    6. Update risk_score + risk_level in PostgreSQL
    7. Return the fully scored asset
    """
 
    # Step 1: Check for duplicate asset_id
    existing = db.query(Asset).filter(
        Asset.asset_id == asset_input.asset_id
    ).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Asset '{asset_input.asset_id}' already exists"
        )
 
    # Step 2: Parse last_scan_date string to date object
    last_scan = None
    if asset_input.last_scan_date:
        try:
            from datetime import datetime
            last_scan = datetime.strptime(
                asset_input.last_scan_date[:10], "%Y-%m-%d"
            ).date()
        except ValueError:
            last_scan = None
 
    # Step 3: Create Asset record
    # risk_score and risk_level start as None — ML fills them below
    new_asset = Asset(
        asset_id         = asset_input.asset_id,
        asset_type       = asset_input.asset_type,
        environment      = asset_input.environment,
        criticality      = asset_input.criticality,
        ip_address       = asset_input.ip_address,
        domain           = asset_input.domain,
        internet_exposed = asset_input.internet_exposed,
        os_name          = asset_input.os_name,
        os_version       = asset_input.os_version,
        software_name    = asset_input.software_name,
        software_version = asset_input.software_version,
        last_scan_date   = last_scan,
        risk_score       = None,
        risk_level       = None,
    )
    db.add(new_asset)
 
    # Step 4: Fetch real CVEs from NVD API
    # Try NVD first. If NVD is unavailable, use CVEs from the request body.
    provided_cves = [
        {
            "cve":               v.cve,
            "severity":          v.severity,
            "cvss_score":        v.cvss_score,
            "exploit_available": v.exploit_available,
            "patch_available":   v.patch_available,
            "description":       v.description,
            "source":            "provided",
        }
        for v in asset_input.vulnerabilities
    ]
 
    # get_cves_with_fallback tries NVD first, falls back to provided CVEs
    final_cves, cve_source = get_cves_with_fallback(
        software_name    = asset_input.software_name or "",
        software_version = asset_input.software_version or "",
        mock_cves        = provided_cves,
    )
 
    # Save whichever CVEs we got to PostgreSQL
    for v in final_cves:
        vuln = Vulnerability(
            asset_id          = asset_input.asset_id,
            cve               = v.get("cve", "UNKNOWN"),
            severity          = v.get("severity", "Unknown"),
            cvss_score        = v.get("cvss_score"),
            exploit_available = v.get("exploit_available", False),
            patch_available   = v.get("patch_available", False),
            description       = v.get("description", ""),
        )
        db.add(vuln)
 
    # Step 5: Create Owner record
    if asset_input.owner:
        owner = Owner(
            asset_id = asset_input.asset_id,
            team     = asset_input.owner.team,
            email    = asset_input.owner.email,
            status   = asset_input.owner.status,
        )
    else:
        # No owner provided — mark as orphan
        owner = Owner(
            asset_id = asset_input.asset_id,
            team     = None,
            email    = None,
            status   = "orphan",
        )
    db.add(owner)
    db.commit()
 
    # Step 6: Run ML scoring
    # IMPORTANT: we score against final_cves (which may be real NVD data),
    # NOT asset_input.vulnerabilities (which is what the caller provided).
    # Bug in original: when NVD fetched real CVEs, the ML model was still
    # scoring based on the caller-provided CVEs (often empty), making the
    # risk score meaningless for NVD-enriched assets.
    asset_dict_for_ml = {
        "asset_id":         asset_input.asset_id,
        "asset_type":       asset_input.asset_type,
        "environment":      asset_input.environment,
        "criticality":      asset_input.criticality,
        "internet_exposed": asset_input.internet_exposed,
        "last_scan_date":   asset_input.last_scan_date,
        "vulnerabilities":  final_cves,   # use NVD data if available
    }
 
    try:
        ml_result = score_asset(asset_dict_for_ml)
 
        # Step 7: Update PostgreSQL with ML scores
        new_asset.risk_score = ml_result["risk_score"]
        new_asset.risk_level = ml_result["risk_level"]
        db.commit()
 
    except Exception as e:
        # If ML scoring fails, asset is still saved
        # Just without a risk score — we don't want ML failure
        # to prevent the asset from being saved
        print(f"⚠️  ML scoring failed for {asset_input.asset_id}: {e}")
        ml_result = None
 
    # Step 8: Re-ingest updated asset into ChromaDB
    # This keeps ChromaDB in sync with PostgreSQL
    # The asset text now includes real NVD CVEs if they were fetched
    db.refresh(new_asset)
    try:
        ingest_single_asset(new_asset.to_dict())
    except Exception as e:
        print(f"ChromaDB ingest failed for {asset_input.asset_id}: {e}")
 
    # Step 9: Return the full scored asset
    result = new_asset.to_dict()
    result["cve_source"] = cve_source   # tell the caller where CVEs came from
 
    if ml_result:
        result["ml_scoring"] = {
            "risk_score":   ml_result["risk_score"],
            "risk_level":   ml_result["risk_level"],
            "confidence":   ml_result["confidence"],
            "top_features": ml_result["top_features"],
        }
 
    return result
 
 
# ── Endpoint: GET /analyze/{asset_id} ────────────────────────────────────────
# Returns a full ML risk breakdown for one asset
# More detailed than /assets/{id} — includes confidence + feature explanation
 
@app.get("/analyze/{asset_id}")
def analyze_asset(asset_id: str, db: Session = Depends(get_db)):
    """
    Full ML risk analysis for one asset.
 
    Returns everything /assets/{id} returns PLUS:
    - ML confidence score
    - Top 5 features that drove the risk score
    - All 13 feature values used in scoring
    - Recommended actions based on risk factors
    """
 
    # Load the asset from PostgreSQL
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
    if not asset:
        raise HTTPException(
            status_code=404,
            detail=f"Asset '{asset_id}' not found"
        )
 
    # Get full asset dict including CVEs
    asset_dict = asset.to_dict()
 
    # Run ML scoring
    try:
        ml_result = score_asset(asset_dict)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"ML scoring failed: {str(e)}"
        )
 
    # Build recommended actions based on risk factors
    # These are rule-based suggestions derived from the feature values
    recommendations = []
    features = ml_result["features_used"]
 
    if features.get("exploit_unpatched_count", 0) > 0:
        recommendations.append({
            "priority": "CRITICAL",
            "action":   "Immediately isolate or take offline — active exploit with no patch available",
        })
    if features.get("has_critical_unpatched", 0) == 1:
        recommendations.append({
            "priority": "CRITICAL",
            "action":   "Apply emergency patch or workaround for Critical severity CVE",
        })
    if features.get("internet_exposed", 0) == 1:
        recommendations.append({
            "priority": "HIGH",
            "action":   "Review firewall rules — consider moving behind VPN or restricting public access",
        })
    if features.get("exploit_available", 0) == 1:
        recommendations.append({
            "priority": "HIGH",
            "action":   "Prioritise patching — known exploit exists in the wild",
        })
    if features.get("patch_available", 1) == 0:
        recommendations.append({
            "priority": "HIGH",
            "action":   "Monitor vendor advisories for patch release — apply immediately when available",
        })
    if features.get("days_since_scan", 0) > 30:
        recommendations.append({
            "priority": "MEDIUM",
            "action":   f"Schedule rescan — last scan was {int(features['days_since_scan'])} days ago",
        })
    if asset_dict.get("owner", {}) and \
       asset_dict["owner"].get("status") == "orphan":
        recommendations.append({
            "priority": "MEDIUM",
            "action":   "Assign ownership — orphan assets are rarely monitored or patched",
        })
    if not recommendations:
        recommendations.append({
            "priority": "LOW",
            "action":   "Maintain regular scanning schedule and monitor for new CVEs",
        })
 
    return {
        "asset":           asset_dict,
        "ml_analysis": {
            "risk_score":     ml_result["risk_score"],
            "risk_level":     ml_result["risk_level"],
            "confidence":     ml_result["confidence"],
            "top_features":   ml_result["top_features"],
            "features_used":  ml_result["features_used"],
        },
        "recommendations": recommendations,
    }