"""
nmap_scanner.py
Runs Nmap against target IPs and parses XML output into structured dicts.
Requires: nmap installed on host + python-nmap package
Install: pip install python-nmap
"""

import nmap
import socket
from datetime import datetime, timezone


def scan_targets(targets: list[str], depth: str = "full") -> list[dict]:
    """
    Scan a list of IP addresses and return structured results.
    
    Args:
        targets: list of IP strings e.g. ["192.168.1.1", "192.168.1.105"]
        depth: "quick" (ping only) or "full" (OS + service detection)
    
    Returns:
        list of dicts with raw scan data per host
    """
    nm = nmap.PortScanner()

    if depth == "quick":
        # Ping scan only — fast, no port info
        args = "-sn"
    else:
        # Full: TCP SYN scan + service version + OS detection + aggressive OS guess
        # Requires Administrator/root privileges
        args = "-sV -O --osscan-guess -T4"

    target_string = " ".join(targets)
    print(f"[Scanner] Starting {depth} scan on: {target_string}")
    
    try:
        nm.scan(hosts=target_string, arguments=args)
    except nmap.PortScannerError as e:
        print(f"[Scanner] Nmap error: {e}")
        print("[Scanner] Make sure Nmap is installed and terminal is running as Administrator")
        return []

    results = []

    for host in nm.all_hosts():
        host_data = nm[host]
        
        # Basic info
        state = host_data.state()
        if state != "up":
            continue

        # Hostname
        hostnames = host_data.hostnames()
        hostname = hostnames[0]["name"] if hostnames and hostnames[0]["name"] else None

        # OS detection
        os_name = "Unknown"
        os_family = "Unknown"
        if "osmatch" in host_data and host_data["osmatch"]:
            best_match = host_data["osmatch"][0]
            os_name = best_match.get("name", "Unknown")
            osclasses = best_match.get("osclass", [])
            if osclasses:
                os_family = osclasses[0].get("osfamily", "Unknown")

        # Open ports and services
        open_ports = []
        services = {}
        for proto in host_data.all_protocols():
            port_list = host_data[proto].keys()
            for port in port_list:
                port_info = host_data[proto][port]
                if port_info["state"] == "open":
                    open_ports.append(port)
                    service_name = port_info.get("name", "unknown")
                    services[str(port)] = service_name

        # MAC address and vendor
        mac = None
        vendor = None
        if "addresses" in host_data:
            mac = host_data["addresses"].get("mac")
        if "vendor" in host_data and mac and mac in host_data["vendor"]:
            vendor = host_data["vendor"][mac]

        results.append({
            "ip": host,
            "hostname": hostname,
            "os_name": os_name,
            "os_family": os_family,
            "open_ports": sorted(open_ports),
            "services": services,
            "mac": mac,
            "vendor": vendor,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "state": state,
        })

        print(f"[Scanner] Found: {host} | {hostname or 'no hostname'} | {os_name} | ports: {open_ports}")

    return results
