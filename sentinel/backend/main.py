from fastapi import FastAPI
import ollama
from chromadb.config import Settings
import chromadb
from sentence_transformers import SentenceTransformer

app = FastAPI()

# Load embedding model (ONLY ONCE)
embed_model = SentenceTransformer("all-MiniLM-L6-v2")

# Load persistent Chroma DB (ONLY THIS VERSION)
chroma_client = chromadb.PersistentClient(path="chroma_db")

collection = chroma_client.get_or_create_collection(name="cyber_assets")
@app.get("/")
def root():
    return {"message": "Backend is working"}

@app.get("/ask")
def ask(question: str):

    # Step 1: Embed user question
    query_embedding = embed_model.encode(question).tolist()

    # Step 2: Retrieve top 3 similar assets
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=6
    )

    retrieved_docs = "\n".join(results["documents"][0])

    # Step 3: Send retrieved context to Ollama
    response = ollama.chat(
        model="llama3",
        messages=[
            {
  "role": "system",
  "content": """
  You are a cybersecurity risk analysis assistant.
  Use ONLY the provided context.
  If information is missing, say "Not found in asset records."
  Always reference asset IDs explicitly.
  Be precise and structured.
  """
},
            {
                "role": "user",
                "content": f"""
                Context:
                {retrieved_docs}

                Question:
                {question}
                """
            }
        ]
    )

    return {"response": response["message"]["content"]}