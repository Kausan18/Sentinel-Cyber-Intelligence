import streamlit as st
import requests

st.title("Cyber RAG Assistant")

if "response" not in st.session_state:
    st.session_state.response = None

question = st.text_input("Ask something:")

if st.button("Send") and question:
    response = requests.get(
        "http://127.0.0.1:8000/ask",
        params={"question": question}
    )

    data = response.json()
    st.session_state.response = data.get("response")

if st.session_state.response:
    st.write(st.session_state.response)
