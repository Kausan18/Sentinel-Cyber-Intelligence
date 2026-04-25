import streamlit as st
import requests

API_URL = "http://localhost:8000"


def show_login():
    """
    Renders the login/signup UI.

    Called from streamlit_app.py BEFORE st.set_page_config, so we must NOT
    call st.set_page_config here — it is already called in streamlit_app.py.

    Two tabs:
    - Log In  — exchanges credentials for a JWT + role
    - Sign Up — creates a new Supabase user and assigns a role
    """

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("## 🛡️ Sentinel")
        st.markdown("#### Cyber Asset & Attack Surface Management")
        st.divider()

        login_tab, signup_tab = st.tabs(["Log In", "Sign Up"])

        # ── LOGIN TAB ──────────────────────────────────────────────────────────
        with login_tab:
            email    = st.text_input("Email", placeholder="analyst@example.com", key="login_email")
            password = st.text_input("Password", type="password", key="login_password")

            if st.button("Log in", use_container_width=True, type="primary", key="login_btn"):
                if not email or not password:
                    st.error("Enter both email and password.")
                else:
                    try:
                        resp = requests.post(
                            f"{API_URL}/auth/login",
                            json={"email": email, "password": password},
                            timeout=10,
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            st.session_state["jwt"]   = data["access_token"]
                            st.session_state["role"]  = data["role"]
                            st.session_state["email"] = data["email"]
                            st.rerun()
                        else:
                            try:
                                detail = resp.json().get("detail", "Invalid email or password.")
                            except Exception:
                                detail = f"Login failed (status {resp.status_code})."
                                st.error(detail)
                    except requests.exceptions.ConnectionError:
                        st.error("Cannot reach the Sentinel API. Is the backend running?")

        # ── SIGN UP TAB ────────────────────────────────────────────────────────
        with signup_tab:
            st.markdown(
                "<p style='color:#94A3B8; font-size:13px;'>"
                "Create a new account. Choose your role carefully — it controls "
                "what you can access.</p>",
                unsafe_allow_html=True,
            )

            new_email    = st.text_input("Email", placeholder="newuser@example.com", key="signup_email")
            new_password = st.text_input("Password", type="password", key="signup_password")
            new_password2 = st.text_input("Confirm Password", type="password", key="signup_password2")

            role_options = {
                "👁️ Viewer  — read-only summary dashboard":            "viewer",
                "📊 Analyst — full dashboard, AI chat, risk explorer":  "analyst",
                "🔴 Admin   — everything including orphan tracker":      "admin",
            }
            selected_label = st.selectbox(
                "Role",
                options=list(role_options.keys()),
                key="signup_role",
            )
            selected_role = role_options[selected_label]

            if st.button("Create Account", use_container_width=True, type="primary", key="signup_btn"):
                if not new_email or not new_password:
                    st.error("Email and password are required.")
                elif new_password != new_password2:
                    st.error("Passwords do not match.")
                elif len(new_password) < 6:
                    st.error("Password must be at least 6 characters.")
                else:
                    try:
                        resp = requests.post(
                            f"{API_URL}/auth/signup",
                            json={
                                "email":    new_email,
                                "password": new_password,
                                "role":     selected_role,
                            },
                            timeout=15,
                        )
                        st.write(resp.status_code, resp.text)
                        if resp.status_code == 200:
                            st.success(
                                f"✅ Account created for **{new_email}** as **{selected_role}**. "
                                "Switch to the Log In tab to sign in."
                            )
                        else:
                            try:
                                detail = resp.json().get("detail", "Signup failed.")
                            except Exception:
                                detail = f"Signup failed (status {resp.status_code})."
                                st.error(detail)
                    except requests.exceptions.ConnectionError:
                        st.error("Cannot reach the Sentinel API. Is the backend running?")