"""
asset_builder.py
Maps Nmap scan results to Sentinel's POST /assets request schema.
"""

from datetime import datetime, timezone


def detect_asset_type(os_name: str, os_family: str, vendor: str | None, open_ports: list[int]) -> str:
    """Infer asset type from scan data."""
    os_lower = (os_name + " " + os_family).lower()
    vendor_lower = (vendor or "").lower()

    if "android" in os_lower:
        return "mobile"
    if "ios" in os_lower or "iphone" in os_lower or "ipad" in os_lower:
        return "mobile"
    if "windows" in os_lower or "mac os" in os_lower or "macos" in os_lower:
        return "laptop"
    if "linux" in os_lower:
        # Heuristic: servers typically have ports 22, 80, 443, 8080
        server_ports = {22, 80, 443, 8080, 8000, 3000}
        if server_ports.intersection(set(open_ports)):
            return "server"
        return "laptop"
    if "samsung" in vendor_lower or "apple" in vendor_lower or "oneplus" in vendor_lower:
        return "mobile"
    if "router" in os_lower or "firewall" in os_lower:
        return "network_device"

    return "unknown"


def build_asset_payload(scan_result: dict, owner: str = "Kaustubh Shandilya", department: str = "Engineering") -> dict:
    """
    Convert a single Nmap scan result dict into a Sentinel POST /assets payload.
    
    Args:
        scan_result: one item from nmap_scanner.scan_targets() output
        owner: asset owner name (editable before import)
        department: asset department (editable before import)
    
    Returns:
        dict matching Sentinel's asset creation schema
    """
    ip = scan_result["ip"]
    hostname = scan_result.get("hostname")
    os_name = scan_result.get("os_name", "Unknown")
    os_family = scan_result.get("os_family", "Unknown")
    open_ports = scan_result.get("open_ports", [])
    services = scan_result.get("services", {})
    mac = scan_result.get("mac")
    vendor = scan_result.get("vendor")
    scan_timestamp = scan_result.get("scan_timestamp", datetime.now(timezone.utc).isoformat())

    # Derive asset name
    if hostname:
        name = hostname
    elif vendor:
        name = f"{vendor}-{ip.split('.')[-1]}"
    else:
        name = f"Device-{ip.split('.')[-1]}"

    asset_type = detect_asset_type(os_name, os_family, vendor, open_ports)

    # Heuristic: internet_exposed = True if common internet-facing ports are open
    internet_facing_ports = {80, 443, 8080, 8443, 22, 21, 25, 53}
    internet_exposed = bool(internet_facing_ports.intersection(set(open_ports)))

    return {
        "asset_id": f"ASSET-{ip.replace('.', '')}",
        "asset_type": asset_type,
        "environment": "Production",
        "criticality": "High",
        "ip_address": ip,
        "domain": None,
        "internet_exposed": internet_exposed,
        "os_name": os_name,
        "os_version": os_family,
        "software_name": None,
        "software_version": None,
        "last_scan_date": scan_timestamp,
        "vulnerabilities": [],
        "owner": {
            "team": owner,
            "email": f"{owner.lower().replace(' ', '.')}@company.com",
            "status": "assigned"
        }
    }


def build_all_payloads(scan_results: list[dict], owner: str = "Kaustubh Shandilya", department: str = "Engineering") -> list[dict]:
    """Convert all scan results to asset payloads."""
    return [build_asset_payload(r, owner, department) for r in scan_results]
