import streamlit as st
import requests
 
# ─── CONFIG ──────────────────────────────────────────────────────────────────
# This must be the FIRST streamlit command in the file
st.set_page_config(
    page_title="Sentinel",
    page_icon="🛡️",
    layout="wide",                  # use full browser width
    initial_sidebar_state="expanded"
)
 
# ─── API BASE URL ─────────────────────────────────────────────────────────────
# All pages import this — change it once here if you deploy to a server
API = "http://127.0.0.1:8000"
 
# ─── CUSTOM CSS ───────────────────────────────────────────────────────────────
# Streamlit's default styling is plain — this makes it look professional
st.markdown("""
<style>
    /* Main background */
    .stApp { background-color: #0D1117; }
 
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #0F2744;
    }
 
    /* Metric cards */
    [data-testid="stMetric"] {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
    }
 
    /* Metric label */
    [data-testid="stMetricLabel"] {
        color: #94A3B8 !important;
        font-size: 13px !important;
    }
 
    /* Metric value */
    [data-testid="stMetricValue"] {
        color: #F8FAFC !important;
        font-size: 28px !important;
        font-weight: 700 !important;
    }
 
    /* Headers */
    h1, h2, h3 { color: #F8FAFC !important; }
 
    /* General text */
    p, div { color: #CBD5E1; }
 
    /* Divider */
    hr { border-color: #334155; }
</style>
""", unsafe_allow_html=True)
 
 
# ─── HELPER: fetch stats from FastAPI ────────────────────────────────────────
# We wrap API calls in a function so we can handle errors cleanly
# @st.cache_data tells Streamlit to cache the result for 60 seconds
# This prevents calling the API on every single page interaction
@st.cache_data(ttl=60)
def fetch_stats():
    try:
        response = requests.get(f"{API}/stats", timeout=5)
        if response.status_code == 200:
            return response.json(), None      # return data, no error
        return None, f"API error: {response.status_code}"
    except requests.exceptions.ConnectionError:
        return None, "Backend not running. Start with: uvicorn main:app --reload"
    except requests.exceptions.Timeout:
        return None, "Backend timed out."
 
 
# ─── PAGE HEADER ─────────────────────────────────────────────────────────────
col_logo, col_title = st.columns([1, 8])
 
with col_logo:
    st.markdown("# 🛡️")
 
with col_title:
    st.markdown("# Sentinel")
    st.markdown(
        "<p style='color:#94A3B8; margin-top:-12px;'>"
        "AI-Driven Cyber Asset & Attack Surface Management</p>",
        unsafe_allow_html=True
    )
 
st.divider()
 
# ─── BACKEND STATUS ───────────────────────────────────────────────────────────
# Show a green/red indicator so the user knows if FastAPI is running
try:
    health = requests.get(f"{API}/", timeout=3)
    if health.status_code == 200:
        st.success("✅ Backend connected — Sentinel API is running")
    else:
        st.error("⚠️ Backend returned an unexpected response")
except:
    st.error(
        "❌ Backend not running. "
        "Open a terminal in your backend folder and run: "
        "`uvicorn main:app --reload`"
    )
 
st.markdown("## 📊 Security Overview")
 
# ─── STATS CARDS ─────────────────────────────────────────────────────────────
stats, error = fetch_stats()
 
if error:
    # Show a friendly warning instead of crashing
    st.warning(f"Could not load stats: {error}")
 
else:
    # Row 1 — Asset counts
    col1, col2, col3, col4 = st.columns(4)
 
    with col1:
        st.metric(
            label="🖥️ Total Assets",
            value=stats["total_assets"],
        )
 
    with col2:
        st.metric(
            label="🔴 Critical Risk",
            value=stats["critical_count"],
            # delta shows change — negative delta = bad (more critical assets)
            delta=f"{stats['critical_count']} need immediate action",
            delta_color="inverse"   # red for increase (inverse of normal)
        )
 
    with col3:
        st.metric(
            label="🌐 Internet Exposed",
            value=stats["exposed_count"],
            delta="publicly reachable",
            delta_color="inverse"
        )
 
    with col4:
        st.metric(
            label="👻 Orphan Assets",
            value=stats["orphan_count"],
            delta="no owner assigned",
            delta_color="inverse"
        )
 
    st.markdown("")  # spacing
 
    # Row 2 — Vulnerability counts
    col5, col6, col7, _ = st.columns(4)
 
    with col5:
        st.metric(
            label="⚠️ High Risk Assets",
            value=stats["high_risk_count"],
            delta="risk score ≥ 70",
            delta_color="inverse"
        )
 
    with col6:
        st.metric(
            label="🐛 Total CVEs",
            value=stats["total_vulns"],
        )
 
    with col7:
        st.metric(
            label="💥 Active Exploits",
            value=stats["exploit_count"],
            delta="exploits in the wild",
            delta_color="inverse"
        )
 
# ─── QUICK NAVIGATION ────────────────────────────────────────────────────────
st.divider()
st.markdown("## 🧭 Navigate")
st.markdown(
    "<p style='color:#94A3B8'>Use the sidebar or click below to go to a page:</p>",
    unsafe_allow_html=True
)
 
nav1, nav2, nav3 = st.columns(3)
 
# st.page_link only works if the page file exists
# We wrap each in try/except so missing pages don't crash the home page
with nav1:
    try:
        st.page_link("pages/1_Asset_Inventory.py",
                     label="📋 Asset Inventory", )
    except Exception:
        st.button("📋 Asset Inventory", disabled=True, )
    try:
        st.page_link("pages/2_Risk_Dashboard.py",
                     label="📊 Risk Dashboard", )
    except Exception:
        st.button("📊 Risk Dashboard", disabled=True, )
 
with nav2:
    try:
        st.page_link("pages/3_Vulnerability_Explorer.py",
                     label="🔍 Vulnerability Explorer", )
    except Exception:
        st.button("🔍 Vulnerability Explorer", disabled=True, )
    try:
        st.page_link("pages/4_Asset_Detail.py",
                     label="🏠 Asset Detail", )
    except Exception:
        st.button("🏠 Asset Detail", disabled=True, )
 
with nav3:
    try:
        st.page_link("pages/5_AI_Chat.py",
                     label="🤖 AI Chat Assistant", )
    except Exception:
        st.button("🤖 AI Chat", disabled=True, )
    try:
        st.page_link("pages/6_Orphan_Tracker.py",
                     label="👻 Orphan Tracker", )
    except Exception:
        st.button("👻 Orphan Tracker", disabled=True, )
 
# ─── FOOTER ───────────────────────────────────────────────────────────────────
st.divider()
st.markdown(
    "<p style='text-align:center; color:#475569; font-size:12px;'>"
    "Sentinel v2.0 — AI-Driven Cyber Asset & Attack Surface Management | "
    "Phase 2 Complete ✅</p>",
    unsafe_allow_html=True
)