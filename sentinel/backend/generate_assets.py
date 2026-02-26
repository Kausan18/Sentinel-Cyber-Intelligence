import json
import random
from datetime import datetime, timedelta

teams = ["Cloud Engineering", "DevOps", "Security Ops", "Backend Team", "Platform Team"]
asset_types = ["Web Server", "Database Server", "Cloud VM", "API Gateway", "Firewall"]
environments = ["Production", "Staging", "Development"]
severities = ["Low", "Medium", "High", "Critical"]

def random_date():
    return (datetime.now() - timedelta(days=random.randint(1, 90))).strftime("%Y-%m-%d")

assets = []

for i in range(100):
    severity = random.choice(severities)

    asset = {
        "asset_id": f"ASSET-{1000+i}",
        "asset_type": random.choice(asset_types),
        "environment": random.choice(environments),
        "criticality": random.choice(["Low", "Medium", "High"]),
        "owner": {
            "team": random.choice(teams),
            "email": "team@company.com"
        },
        "os": random.choice(["Ubuntu 22.04", "Windows Server 2022"]),
        "open_ports": random.sample([22, 80, 443, 3306, 8080, 8443], k=2),
        "services": ["Service-A", "Service-B"],
        "risk_score": random.randint(10, 100),
        "last_scan_date": random_date(),
        "vulnerabilities": [
            {
                "cve": f"CVE-2023-{random.randint(1000,9999)}",
                "severity": severity,
                "cvss_score": round(random.uniform(4.0, 10.0), 1),
                "exploit_available": random.choice([True, False]),
                "patch_available": random.choice([True, False]),
                "description": f"{severity} severity vulnerability detected"
            }
        ]
    }

    assets.append(asset)

with open("data/assets_v2.json", "w") as f:
    json.dump(assets, f, indent=2)

print("Generated 100 assets.")