from dotenv import load_dotenv
load_dotenv()  # MUST be before any os.environ.get() calls

"""
auth.py — Standalone auth helpers (optional import).

NOTE: The primary auth logic (get_current_user, require_admin, etc.) lives
directly in main.py to avoid circular import issues between main.py and auth.py.

This file is kept for reference and for any future modules that need to
call decode_jwt independently without importing from main.py.

If your page scripts or other modules need auth utilities, import from here.
"""

import os
from jose import jwt
from jose.exceptions import JWTError
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session  # sync session — matches db.py and main.py

from db import get_db, UserRole

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
bearer_scheme = HTTPBearer()

import requests as _req
import json as _json
import base64 as _b64

# Cache JWKS keys so we don't fetch on every single request
_jwks_cache: dict = {}


def _get_jwks_key(kid: str) -> dict:
    global _jwks_cache
    if kid in _jwks_cache:
        return _jwks_cache[kid]
    jwks_url = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
    try:
        resp = _req.get(jwks_url, timeout=10)
        resp.raise_for_status()
        keys = resp.json().get("keys", [])
        for key in keys:
            _jwks_cache[key["kid"]] = key
        if kid in _jwks_cache:
            return _jwks_cache[kid]
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Could not fetch auth keys: {e}")
    raise HTTPException(status_code=401, detail=f"No public key found for kid={kid}")


def decode_jwt(token: str) -> dict:
    """
    Validate and decode a Supabase-issued JWT using ES256 (JWKS).
    Consistent with the implementation in main.py.
    """
    try:
        header_b64 = token.split(".")[0]
        padding = 4 - len(header_b64) % 4
        header = _json.loads(_b64.urlsafe_b64decode(header_b64 + "=" * padding))
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed token header")

    kid = header.get("kid", "")
    alg = header.get("alg", "ES256")
    public_key = _get_jwks_key(kid)

    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[alg],
            options={"verify_aud": False},
        )
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token invalid: {str(e)}")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),          # sync Session, NOT AsyncSession
) -> dict:
    """
    FastAPI dependency. Decodes the JWT, fetches the user's role from
    user_roles table, and returns {"user_id": ..., "role": ..., "email": ...}.
    Attach this to any route that requires authentication.
    """
    payload = decode_jwt(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token has no user ID")

    # Sync query — consistent with how main.py and db.py work
    user_role = db.query(UserRole).filter(UserRole.user_id == user_id).first()

    if not user_role:
        raise HTTPException(status_code=403, detail="User has no role assigned")

    return {"user_id": user_id, "role": user_role.role, "email": payload.get("email")}


# ── Role-specific dependency shortcuts ────────────────────────────────────────

def require_admin(
    current_user: dict = Depends(get_current_user),
) -> dict:
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def require_analyst_or_above(
    current_user: dict = Depends(get_current_user),
) -> dict:
    if current_user["role"] not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Analyst or admin access required")
    return current_user


def require_any_role(
    current_user: dict = Depends(get_current_user),
) -> dict:
    # All three roles pass — just proves the user is logged in
    return current_user