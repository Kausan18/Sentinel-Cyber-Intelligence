"""
register_real_assets.py
Manually registers real known devices into Sentinel.
Uses real metadata gathered from the actual devices.
Run: python register_real_assets.py --api-url http://localhost:8000
"""

import argparse
import requests
import json

# ─── REAL DEVICE DATA ────────────────────────────────────────────────────────
# Gathered manually from actual devices. Update these if hardware changes.

REAL_ASSETS = [
    {
        "asset_id": "ASSET-KAUSTY-LAPTOP",
        "asset_type": "laptop",
        "environment": "Production",
        "criticality": "High",
        "ip_address": "172.16.11.41",
        "domain": None,
        "internet_exposed": False,
        "os_name": "Windows 11 Home",
        "os_version": "25H2 Build 26200.8457",
        "software_name": None,
        "software_version": None,
        "last_scan_date": "2026-05-17",
        "vulnerabilities": [],
        "owner": {
            "team": "Kaustubh Shandilya",
            "email": "kaustubh.shandilya@company.com",
            "status": "assigned"
        }
    },
    {
        "asset_id": "ASSET-KAUSTY-ONEPLUS",
        "asset_type": "mobile",
        "environment": "Production",
        "criticality": "Medium",
        "ip_address": "172.16.12.204",
        "domain": None,
        "internet_exposed": False,
        "os_name": "Android",
        "os_version": "16",
        "software_name": None,
        "software_version": None,
        "last_scan_date": "2026-05-17",
        "vulnerabilities": [],
        "owner": {
            "team": "Kaustubh Shandilya",
            "email": "kaustubh.shandilya@company.com",
            "status": "assigned"
        }
    }
]
# ─────────────────────────────────────────────────────────────────────────────


def post_asset(payload: dict, api_url: str) -> dict:
    try:
        response = requests.post(
            f"{api_url}/assets",
            json=payload,
            timeout=30,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        return {"success": True, "data": response.json()}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": f"Cannot connect to {api_url}. Is Sentinel running?"}
    except requests.exceptions.HTTPError as e:
        return {"success": False, "error": f"HTTP {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Register real assets into Sentinel")
    parser.add_argument("--api-url", default="http://localhost:8000", help="Sentinel API base URL")
    parser.add_argument("--dry-run", action="store_true", help="Print payloads without posting")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  Sentinel — Real Asset Registration")
    print(f"  Registering {len(REAL_ASSETS)} real device(s)")
    print(f"  API: {args.api_url}")
    print(f"{'='*60}\n")

    if args.dry_run:
        print("[DRY RUN] Payloads:")
        print(json.dumps(REAL_ASSETS, indent=2))
        return

    success_count = 0
    for asset in REAL_ASSETS:
        print(f"  Registering: {asset['asset_id']} ({asset['ip_address']})...")
        result = post_asset(asset, args.api_url)
        if result["success"]:
            created = result["data"]
            print(f"  ✓ Created — ID: {created.get('asset_id', 'N/A')} | Risk: {created.get('risk_score', 'pending scoring')}")
            success_count += 1
        else:
            print(f"  ✗ Failed: {result['error']}")

    print(f"\n{'='*60}")
    print(f"  Done. {success_count}/{len(REAL_ASSETS)} assets registered.")
    print(f"  NVD enrichment and ML scoring trigger automatically via POST /assets.")
    print(f"  Open http://localhost:8501 → Asset Inventory to view them.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
