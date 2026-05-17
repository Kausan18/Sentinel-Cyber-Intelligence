"""
9_Network_Scanner.py
Sentinel Network Scanner UI page.
Allows manual IP entry, triggers scan via backend, and imports discovered assets.
"""

import streamlit as st
import requests
import os

API_URL = os.getenv("API_URL", "http://localhost:8000")

st.set_page_config(page_title="Network Scanner", page_icon="🔍", layout="wide")
st.title("🔍 Network Scanner")
st.caption("Discover and import real devices into Sentinel")

# ── Warning banner
st.warning(
    "⚠️ **Network Policy Reminder** — Only scan networks you own or have explicit permission to scan. "
    "Never run scans on college, office, or shared institutional networks.",
    icon="⚠️"
)

st.divider()

# ── Input section
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Target Configuration")
    
    target_input = st.text_area(
        "Target IP Addresses (one per line)",
        placeholder="192.168.1.1\n192.168.1.105",
        height=120,
        help="Enter the IP addresses of devices you want to scan. Use only on your own network."
    )

    scan_depth = st.radio(
        "Scan Depth",
        options=["full", "quick"],
        format_func=lambda x: "Full (OS + services, ~30s, requires Admin)" if x == "full" else "Quick (ping only, ~5s)",
        horizontal=True
    )

with col2:
    st.subheader("Asset Defaults")
    default_owner = st.text_input("Default Owner", value="Kaustubh Shandilya")
    default_dept = st.text_input("Default Department", value="Engineering")
    
    st.info(
        "💡 **Before scanning:**\n"
        "- Disable Cloudflare WARP\n"
        "- Run VS Code / terminal as Administrator\n"
        "- Use home WiFi or personal hotspot only"
    )

st.divider()

# ── Scan trigger
if st.button("🔍 Start Scan", type="primary", use_container_width=True):
    targets = [t.strip() for t in target_input.strip().splitlines() if t.strip()]
    
    if not targets:
        st.error("Please enter at least one target IP address.")
    else:
        with st.spinner(f"Scanning {len(targets)} target(s)... this may take up to 60 seconds for a full scan."):
            try:
                # Call backend scan endpoint
                response = requests.post(
                    f"{API_URL}/scan",
                    json={"targets": targets, "depth": scan_depth},
                    timeout=120,
                    headers={"Authorization": f"Bearer {st.session_state.get('jwt', '')}"}
                )
                response.raise_for_status()
                scan_data = response.json()
                st.session_state["scan_results"] = scan_data.get("discovered", [])
                st.success(f"✅ Scan complete. Found {len(st.session_state['scan_results'])} live host(s).")
            except requests.exceptions.ConnectionError:
                st.error(f"Cannot connect to Sentinel API at {API_URL}. Make sure the backend is running.")
            except requests.exceptions.HTTPError as e:
                st.error(f"API error: {e.response.status_code} — {e.response.text}")
            except Exception as e:
                st.error(f"Scan failed: {e}")

# ── Results display
if "scan_results" in st.session_state and st.session_state["scan_results"]:
    results = st.session_state["scan_results"]
    
    st.subheader(f"Discovered Devices ({len(results)})")
    
    selected = []
    for i, device in enumerate(results):
        with st.expander(f"📡 {device.get('asset_id', device.get('ip_address'))} — {device.get('ip_address')} — {device.get('os_name', 'Unknown OS')}", expanded=True):
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("Asset Type", device.get("asset_type", "unknown"))
            with col_b:
                open_ports = device.get("open_ports", [])
                st.metric("Open Ports", len(open_ports))
            with col_c:
                st.metric("Internet Exposed", "Yes" if device.get("internet_exposed") else "No")
            
            st.json(device)
            
            if st.checkbox(f"Import this device", key=f"import_{i}", value=True):
                selected.append(device)
    
    st.divider()
    
    if selected:
        if st.button(f"⬆️ Import {len(selected)} Selected Asset(s) → Sentinel", type="primary"):
            import_success = 0
            for device in selected:
                try:
                    resp = requests.post(
                        f"{API_URL}/assets",
                        json=device,
                        timeout=30,
                        headers={"Authorization": f"Bearer {st.session_state.get('jwt', '')}"}
                    )
                    resp.raise_for_status()
                    import_success += 1
                except Exception as e:
                    st.warning(f"Failed to import {device.get('asset_id')}: {e}")
            
            if import_success:
                st.success(f"✅ {import_success} asset(s) imported. NVD enrichment and ML scoring running automatically.")
                st.balloons()
                del st.session_state["scan_results"]

st.divider()

# ── Manual registration shortcut
st.subheader("Quick Register — Real Devices")
st.caption("Register your known devices directly without scanning (safe to use on any network)")

if st.button("📱💻 Register Laptop + Phone (Pre-configured)", use_container_width=True):
    real_assets = [
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
                "team": default_owner,
                "email": f"{default_owner.lower().replace(' ', '.')}@company.com",
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
                "team": default_owner,
                "email": f"{default_owner.lower().replace(' ', '.')}@company.com",
                "status": "assigned"
            }
        }
    ]
    
    success = 0
    for asset in real_assets:
        try:
            resp = requests.post(
                f"{API_URL}/assets",
                json=asset,
                timeout=30,
                headers={"Authorization": f"Bearer {st.session_state.get('jwt', '')}"}
            )
            resp.raise_for_status()
            success += 1
            st.success(f"✅ Registered: {asset['asset_id']}")
        except Exception as e:
            st.error(f"Failed: {asset['asset_id']} — {e}")
    
    if success == len(real_assets):
        st.balloons()
        st.info("Both devices registered. Check Asset Inventory to see them with CVEs and risk scores.")
