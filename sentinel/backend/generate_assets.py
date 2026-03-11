import json
import random
from datetime import datetime, timedelta

# ─── Reference Data ───────────────────────────────────────────────────────────

teams = [
    "Cloud Engineering",
    "DevOps",
    "Security Ops",
    "Backend Team",
    "Platform Team",
]

team_emails = {
    "Cloud Engineering": "cloud-eng@company.com",
    "DevOps": "devops@company.com",
    "Security Ops": "secops@company.com",
    "Backend Team": "backend@company.com",
    "Platform Team": "platform@company.com",
}

asset_types = ["Web Server", "Database Server", "Cloud VM", "API Gateway", "Firewall"]

environments = ["Production", "Staging", "Development"]

operating_systems = [
    {"name": "Ubuntu", "version": "22.04"},
    {"name": "Ubuntu", "version": "20.04"},
    {"name": "Windows Server", "version": "2022"},
    {"name": "Windows Server", "version": "2019"},
    {"name": "CentOS", "version": "7"},
    {"name": "Debian", "version": "11"},
]

# Software packages with realistic versions per asset type
software_map = {
    "Web Server":      [("nginx", "1.18.0"), ("nginx", "1.24.0"), ("apache2", "2.4.52"), ("apache2", "2.4.57")],
    "Database Server": [("mysql", "8.0.32"), ("mysql", "8.0.28"), ("postgresql", "14.5"), ("postgresql", "15.2")],
    "Cloud VM":        [("docker", "20.10.7"), ("docker", "24.0.5"), ("containerd", "1.6.4")],
    "API Gateway":     [("nginx", "1.18.0"), ("envoy", "1.25.0"), ("kong", "3.2.0")],
    "Firewall":        [("iptables", "1.8.7"), ("ufw", "0.36"), ("pf", "6.7")],
}

# CVE pool — realistic CVEs mapped to software
cve_pool = {
    "nginx": [
        {"cve": "CVE-2021-23017", "severity": "Critical", "cvss_score": 9.4,
         "exploit_available": True,  "patch_available": True,
         "description": "Off-by-one error in ngx_resolver allowing remote code execution via crafted DNS response."},
        {"cve": "CVE-2022-41741", "severity": "High", "cvss_score": 7.8,
         "exploit_available": True,  "patch_available": True,
         "description": "Memory corruption in ngx_http_mp4_module when processing specially crafted MP4 files."},
        {"cve": "CVE-2023-44487", "severity": "High", "cvss_score": 7.5,
         "exploit_available": True,  "patch_available": True,
         "description": "HTTP/2 Rapid Reset Attack enabling denial of service at scale."},
    ],
    "apache2": [
        {"cve": "CVE-2021-41773", "severity": "Critical", "cvss_score": 9.8,
         "exploit_available": True,  "patch_available": True,
         "description": "Path traversal and remote code execution in Apache HTTP Server 2.4.49."},
        {"cve": "CVE-2022-31813", "severity": "High", "cvss_score": 9.8,
         "exploit_available": False, "patch_available": True,
         "description": "Apache HTTP Server may not send the X-Forwarded-* headers to the origin server, allowing authentication bypass."},
    ],
    "mysql": [
        {"cve": "CVE-2023-21980", "severity": "High", "cvss_score": 7.1,
         "exploit_available": False, "patch_available": True,
         "description": "Vulnerability in MySQL Server optimizer allowing unauthorized data access."},
        {"cve": "CVE-2022-21595", "severity": "Medium", "cvss_score": 4.4,
         "exploit_available": False, "patch_available": True,
         "description": "MySQL Server C API vulnerability allowing denial of service by a privileged attacker."},
    ],
    "postgresql": [
        {"cve": "CVE-2022-1552", "severity": "High", "cvss_score": 8.8,
         "exploit_available": True,  "patch_available": True,
         "description": "Autovacuum, REINDEX, and other processes omit security restricted operations, enabling privilege escalation."},
        {"cve": "CVE-2023-2454", "severity": "High", "cvss_score": 7.2,
         "exploit_available": False, "patch_available": True,
         "description": "CREATE SCHEMA allows superusers to bypass security policies in pg_catalog."},
    ],
    "docker": [
        {"cve": "CVE-2022-0847", "severity": "High", "cvss_score": 7.8,
         "exploit_available": True,  "patch_available": True,
         "description": "Dirty Pipe — Linux kernel flaw allowing overwrite of read-only files in container environments."},
        {"cve": "CVE-2023-28840", "severity": "High", "cvss_score": 8.7,
         "exploit_available": False, "patch_available": True,
         "description": "Insufficient encryption of overlay network traffic in Docker Swarm mode."},
    ],
    "containerd": [
        {"cve": "CVE-2022-23648", "severity": "High", "cvss_score": 7.5,
         "exploit_available": True,  "patch_available": True,
         "description": "containerd allows attackers to gain read access to arbitrary host files via specially crafted image configurations."},
    ],
    "envoy": [
        {"cve": "CVE-2023-35943", "severity": "High", "cvss_score": 8.3,
         "exploit_available": False, "patch_available": True,
         "description": "CORS filter segfault on wildcard origins with empty request origins, enabling denial of service."},
    ],
    "kong": [
        {"cve": "CVE-2022-35796", "severity": "Critical", "cvss_score": 9.0,
         "exploit_available": True,  "patch_available": True,
         "description": "Elevation of privilege in Kong Gateway due to improper request handling."},
    ],
    "iptables": [
        {"cve": "CVE-2012-2663", "severity": "Medium", "cvss_score": 5.0,
         "exploit_available": False, "patch_available": True,
         "description": "Incomplete blacklist allows traffic to bypass iptables rules via crafted packets."},
    ],
    "ufw": [
        {"cve": "CVE-2019-7113", "severity": "Low", "cvss_score": 3.1,
         "exploit_available": False, "patch_available": True,
         "description": "UFW before 0.36 allows local users to bypass firewall rules due to IPv6 misconfiguration."},
    ],
    "pf": [
        {"cve": "CVE-2021-29629", "severity": "High", "cvss_score": 7.5,
         "exploit_available": False, "patch_available": False,
         "description": "pf in FreeBSD allows denial of service via malformed ICMP or ICMPv6 packets."},
    ],
}

# Port pools per asset type
port_map = {
    "Web Server":      [80, 443, 8080, 8443],
    "Database Server": [3306, 5432, 1433, 27017],
    "Cloud VM":        [22, 2222, 8080, 9090],
    "API Gateway":     [80, 443, 8000, 8080],
    "Firewall":        [22, 443, 8443],
}

# Internet-exposed asset types
internet_exposed_types = {"Web Server", "API Gateway", "Firewall"}

# ─── Helper Functions ─────────────────────────────────────────────────────────

def random_ip():
    return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def random_date(days_back=90):
    return (datetime.now() - timedelta(days=random.randint(1, days_back))).strftime("%Y-%m-%d")

def get_open_ports(asset_type):
    pool = port_map.get(asset_type, [22, 80, 443])
    return random.sample(pool, k=min(random.randint(1, 3), len(pool)))

def get_software(asset_type):
    options = software_map.get(asset_type, [("unknown", "1.0.0")])
    name, version = random.choice(options)
    return {"name": name, "version": version}

def get_vulnerabilities(software_name, count=None):
    pool = cve_pool.get(software_name, [])
    if not pool:
        return []
    count = count or random.randint(1, min(2, len(pool)))
    return random.sample(pool, k=min(count, len(pool)))

def compute_risk_score(asset):
    """
    Composite risk score (0-100) based on:
    - Max CVSS score of vulnerabilities     (40%)
    - Internet exposure                     (25%)
    - Asset criticality                     (20%)
    - Exploit availability                  (15%)
    """
    vulns = asset.get("vulnerabilities", [])
    max_cvss = max((v["cvss_score"] for v in vulns), default=0)

    criticality_score = {"Low": 3, "Medium": 6, "High": 10}.get(asset["criticality"], 5)
    exposure_score    = 10 if asset["internet_exposed"] else 3
    exploit_score     = 10 if any(v["exploit_available"] for v in vulns) else 2

    raw = (
        (max_cvss / 10) * 40 +
        (exposure_score / 10) * 25 +
        (criticality_score / 10) * 20 +
        (exploit_score / 10) * 15
    )
    return round(min(raw, 100), 1)

# ─── Asset Generation ─────────────────────────────────────────────────────────

assets = []

# 5 assets intentionally have no owner (orphan assets)
orphan_indices = random.sample(range(100), 5)

for i in range(100):
    asset_type  = random.choice(asset_types)
    environment = random.choice(environments)
    criticality = random.choice(["Low", "Medium", "High"])
    os_info     = random.choice(operating_systems)
    software    = get_software(asset_type)
    vulns       = get_vulnerabilities(software["name"])
    open_ports  = get_open_ports(asset_type)

    # Internet exposure: always true for exposed types in Production,
    # sometimes true for Staging, never for internal types in Development
    if asset_type in internet_exposed_types:
        internet_exposed = True if environment == "Production" else random.choice([True, False])
    else:
        internet_exposed = False

    # Owner — orphan assets have no owner
    if i in orphan_indices:
        owner = {"team": None, "email": None, "status": "orphan"}
    else:
        team  = random.choice(teams)
        owner = {"team": team, "email": team_emails[team], "status": "assigned"}

    asset = {
        "asset_id":        f"ASSET-{1000 + i}",
        "asset_type":      asset_type,
        "environment":     environment,
        "criticality":     criticality,
        "ip_address":      random_ip(),
        "domain":          f"asset-{1000+i}.internal.company.com" if not internet_exposed else f"asset-{1000+i}.company.com",
        "internet_exposed": internet_exposed,
        "os": {
            "name":    os_info["name"],
            "version": os_info["version"],
        },
        "software": software,
        "open_ports":      open_ports,
        "owner":           owner,
        "last_scan_date":  random_date(),
        "vulnerabilities": vulns,
    }

    # Compute composite risk score AFTER all fields are set
    asset["risk_score"] = compute_risk_score(asset)

    assets.append(asset)

# ─── Save ─────────────────────────────────────────────────────────────────────

import os
os.makedirs("data", exist_ok=True)

with open("data/assets_v2.json", "w") as f:
    json.dump(assets, f, indent=2)

print(f"✅ Generated {len(assets)} assets → data/assets_v2.json")
print(f"   • Orphan assets (no owner): {len(orphan_indices)}")
print(f"   • Internet-exposed assets: {sum(1 for a in assets if a['internet_exposed'])}")
print(f"   • Assets with Critical vulns: {sum(1 for a in assets if any(v['severity'] == 'Critical' for v in a['vulnerabilities']))}")
