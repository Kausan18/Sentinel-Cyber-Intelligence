import streamlit as st
import requests
 
# ─── CONFIG ──────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Chat — Sentinel",
    page_icon="🤖",
    layout="wide"
)
 
API = "http://127.0.0.1:8000"
 
# ─── INITIALISE SESSION STATE ─────────────────────────────────────────────────
# Must happen BEFORE any widgets are rendered
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
 
if "pending_question" not in st.session_state:
    st.session_state.pending_question = None
 
# ─── SIDEBAR ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ Sentinel")
    st.page_link("streamlit_app.py", label="🏠 Home / Dashboard")
    st.divider()
 
    st.markdown("### 💬 Chat Controls")
    if st.button("🗑️ Clear Chat History"):
        st.session_state.chat_history = []
        st.session_state.pending_question = None
        st.rerun()
 
    st.divider()
    st.markdown(
        "<p style='color:#94A3B8; font-size:12px;'>"
        "Powered by Phi3 running locally via Ollama.<br>"
        "Context retrieved from ChromaDB.</p>",
        unsafe_allow_html=True
    )
 
# ─── CUSTOM CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp { background-color: #0D1117; }
    [data-testid="stSidebar"] { background-color: #0F2744; }
    h1, h2, h3 { color: #F8FAFC !important; }
    p, div { color: #CBD5E1; }
    hr { border-color: #334155; }
    .user-msg {
        background-color: #1E3A5F;
        border: 1px solid #1A56DB;
        border-radius: 12px 12px 4px 12px;
        padding: 12px 16px;
        margin: 8px 0;
        margin-left: 20%;
        color: #F8FAFC;
        font-size: 14px;
    }
    .ai-msg {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 12px 12px 12px 4px;
        padding: 12px 16px;
        margin: 8px 0;
        margin-right: 20%;
        color: #CBD5E1;
        font-size: 14px;
        line-height: 1.6;
    }
</style>
""", unsafe_allow_html=True)
 
 
# ─── HELPER FUNCTION ─────────────────────────────────────────────────────────
 
def ask_ai(question):
    try:
        response = requests.get(
            f"{API}/ask",
            params={"question": question},
            timeout=60
        )
        if response.status_code == 200:
            return response.json().get("response", "No response received."), None
        return None, f"API error {response.status_code}"
    except requests.exceptions.ConnectionError:
        return None, "Backend not running."
    except requests.exceptions.Timeout:
        return None, "AI took too long. Try a simpler question."
 
 
# ─── PAGE HEADER ─────────────────────────────────────────────────────────────
st.markdown("# 🤖 AI Chat Assistant")
st.markdown(
    "<p style='color:#94A3B8'>Ask anything about your assets, "
    "vulnerabilities and security posture.</p>",
    unsafe_allow_html=True
)
st.divider()
 
# ─── SUGGESTED QUESTIONS ─────────────────────────────────────────────────────
# Always show suggestions so user can click them at any point
st.markdown(
    "<p style='color:#94A3B8; font-size:13px;'>💡 Suggested questions:</p>",
    unsafe_allow_html=True
)
 
suggestions = [
    "Which assets have the highest risk scores?",
    "Show me all internet-exposed assets with critical vulnerabilities",
    "What are the most dangerous CVEs in my environment?",
    "Which assets are orphans with no assigned owner?",
    "Give me a security summary of my entire environment",
    "Which assets should I patch immediately?",
]
 
sug_col1, sug_col2 = st.columns(2)
for i, suggestion in enumerate(suggestions):
    col = sug_col1 if i % 2 == 0 else sug_col2
    with col:
        # Store the clicked suggestion in session state
        # Do NOT call st.rerun() here — process it at the bottom
        if st.button(suggestion, key=f"sug_{i}"):
            st.session_state.pending_question = suggestion
 
st.divider()
 
# ─── CHAT HISTORY DISPLAY ────────────────────────────────────────────────────
for msg in st.session_state.chat_history:
    if msg["role"] == "user":
        st.markdown(
            f"<div class='user-msg'>"
            f"<b style='color:#93C5FD;'>You</b><br>{msg['content']}"
            f"</div>",
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f"<div class='ai-msg'>"
            f"<b style='color:#10B981;'>🤖 Sentinel AI</b><br>{msg['content']}"
            f"</div>",
            unsafe_allow_html=True
        )
 
# ─── CHAT INPUT ───────────────────────────────────────────────────────────────
typed_question = st.chat_input("Ask about your assets, CVEs or security posture...")
 
# ─── DETERMINE WHICH QUESTION TO PROCESS ─────────────────────────────────────
# Typed question takes priority over suggestion click
question_to_process = None
 
if typed_question:
    question_to_process = typed_question
    st.session_state.pending_question = None   # clear any pending suggestion
 
elif st.session_state.pending_question:
    question_to_process = st.session_state.pending_question
    st.session_state.pending_question = None   # clear immediately
 
# ─── PROCESS THE QUESTION ────────────────────────────────────────────────────
if question_to_process:
    # Add to history
    st.session_state.chat_history.append({
        "role": "user", "content": question_to_process
    })
 
    # Show user message
    st.markdown(
        f"<div class='user-msg'>"
        f"<b style='color:#93C5FD;'>You</b><br>{question_to_process}"
        f"</div>",
        unsafe_allow_html=True
    )
 
    # Call the AI
    with st.spinner("🤖 Sentinel AI is thinking..."):
        answer, error = ask_ai(question_to_process)
 
    if error:
        st.error(f"❌ {error}")
        st.session_state.chat_history.pop()
    else:
        st.session_state.chat_history.append({
            "role": "assistant", "content": answer
        })
        st.markdown(
            f"<div class='ai-msg'>"
            f"<b style='color:#10B981;'>🤖 Sentinel AI</b><br>{answer}"
            f"</div>",
            unsafe_allow_html=True
        )
 
    # Rerun to refresh cleanly with updated history
    st.rerun()
 
# ─── CHAT STATS ───────────────────────────────────────────────────────────────
if st.session_state.chat_history:
    turns = len(st.session_state.chat_history) // 2
    st.markdown(
        f"<p style='color:#475569; font-size:12px; text-align:center; "
        f"margin-top:20px;'>{turns} conversation turn(s) this session</p>",
        unsafe_allow_html=True
    )
 