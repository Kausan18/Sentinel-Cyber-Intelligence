"""
run_scan.py
CLI entrypoint for the Sentinel network scanner.

Usage:
    python run_scan.py --targets 192.168.1.1 192.168.1.105
    python run_scan.py --targets 192.168.1.1 --depth quick
    python run_scan.py --targets 192.168.1.1 --api-url http://localhost:8000

IMPORTANT: Run as Administrator on Windows for OS detection.
IMPORTANT: Only use on home WiFi or personal hotspot. Never on college/office networks.
"""

import argparse
import json
import sys
import requests

from nmap_scanner import scan_targets
from asset_builder import build_all_payloads


def post_asset(payload: dict, api_url: str) -> dict:
    """POST a single asset payload to Sentinel API."""
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
        return {"success": False, "error": f"Cannot connect to API at {api_url}. Is Sentinel running?"}
    except requests.exceptions.HTTPError as e:
        return {"success": False, "error": f"HTTP {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Sentinel Network Scanner")
    parser.add_argument("--targets", nargs="+", required=True, help="IP addresses to scan")
    parser.add_argument("--depth", choices=["quick", "full"], default="full", help="Scan depth")
    parser.add_argument("--api-url", default="http://localhost:8000", help="Sentinel API URL")
    parser.add_argument("--owner", default="Kaustubh Shandilya", help="Asset owner name")
    parser.add_argument("--department", default="Engineering", help="Asset department")
    parser.add_argument("--dry-run", action="store_true", help="Print payloads without posting to API")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  Sentinel Network Scanner")
    print(f"  Targets: {', '.join(args.targets)}")
    print(f"  Depth:   {args.depth}")
    print(f"  API:     {args.api_url}")
    print(f"{'='*60}\n")

    # Step 1: Scan
    scan_results = scan_targets(args.targets, depth=args.depth)

    if not scan_results:
        print("\n[!] No live hosts found. Check:")
        print("    - Target IPs are correct")
        print("    - Both devices are on the same network")
        print("    - Cloudflare WARP is disabled on this machine")
        print("    - Terminal is running as Administrator")
        sys.exit(1)

    print(f"\n[+] Discovered {len(scan_results)} live host(s)")

    # Step 2: Build payloads
    payloads = build_all_payloads(scan_results, owner=args.owner, department=args.department)

    if args.dry_run:
        print("\n[DRY RUN] Asset payloads (not posted):")
        print(json.dumps(payloads, indent=2))
        return

    # Step 3: Post to API
    print(f"\n[+] Importing {len(payloads)} asset(s) into Sentinel...\n")
    success_count = 0
    for payload in payloads:
        print(f"  Posting: {payload['asset_id']} ({payload['ip_address']})...")
        result = post_asset(payload, args.api_url)
        if result["success"]:
            print(f"  ✓ Imported successfully")
            success_count += 1
        else:
            print(f"  ✗ Failed: {result['error']}")

    print(f"\n{'='*60}")
    print(f"  Done. {success_count}/{len(payloads)} assets imported into Sentinel.")
    print(f"  Open http://localhost:8501 to view them on the dashboard.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
