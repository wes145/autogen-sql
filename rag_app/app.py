#!/usr/bin/env python

# -*- coding: utf-8 -*-

# rag_app.py
# A single-file, self-contained RAG application for querying web content.

# 1. --- SETUP AND IMPORTS ---
#
# First, install the required libraries:
# pip install langchain langchain-openai beautifulsoup4 faiss-cpu sentence-transformers python-dotenv

import os
from dotenv import load_dotenv
import pickle
from typing import Set

# Document Loaders
from langchain_community.document_loaders import WebBaseLoader

# Text Splitters
from langchain.text_splitter import RecursiveCharacterTextSplitter

# Vector Stores
from langchain_community.vectorstores import FAISS

# Embeddings
from langchain_openai import OpenAIEmbeddings
# from langchain_community.embeddings import HuggingFaceEmbeddings # Alternative

# LLMs
from langchain_openai import ChatOpenAI

# Chains & Prompts
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain
from langchain_core.prompts import ChatPromptTemplate

# --- CONFIGURATION ---
# Load environment variables from .env file (for API keys)
load_dotenv()

if not os.getenv("OPENAI_API_KEY"):
    raise ValueError("OPENAI_API_KEY is not set. Please set it in your .env file or environment.")

# List of URLs to index. Add your own URLs here.
URLS_TO_INDEX = [
    "https://portswigger.net/web-security/server-side-template-injection",
    "https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti",
    "https://redfoxsec.com/blog/server-side-template-injection-ssti/",
    "https://portswigger.net/web-security/sql-injection",
    "https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/",
    "https://portswigger.net/web-security/sql-injection/cheat-sheet",
    "https://www.w3schools.com/sql/sql_injection.asp",
    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    "https://hackviser.com/tactics/pentesting/web/sql-injection",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
    "https://learn.snyk.io/lesson/sql-injection/"
]

# Get the absolute path to the workspace directory
WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Paths for persistence - using absolute paths
VECTOR_STORE_PATH = os.path.join(WORKSPACE_DIR, "rag_data", "vector_store")
INDEXED_URLS_PATH = os.path.join(WORKSPACE_DIR, "rag_data", "indexed_urls.pkl")

# --- THE RAG APPLICATION CLASS ---

class SimpleRAG:
    """A simple, self-contained RAG application with persistence."""

    def __init__(self, urls: list[str]):
        """
        Initializes the RAG application.

        Args:
            urls: A list of URLs to load and index.
        """
        print("Initializing RAG application...")
        self.vector_store = None
        self.rag_chain = None
        self.urls = urls
        self.indexed_urls: Set[str] = set()

        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(VECTOR_STORE_PATH), exist_ok=True)

        # Initialize core components
        self._initialize_components()

        # Load or create the vector store and indexed URLs
        self._load_or_create_stores()

        # Build the RAG chain upon initialization
        self.build_rag_chain()

    def _initialize_components(self):
        """Initializes the LLM, Embeddings, and Text Splitter."""
        # Use OpenAI for both the LLM and embeddings (requires API key)
        self.llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.2)
        self.embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
        
        # Alternative: Use a free, local HuggingFace model for embeddings
        # self.embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

        # Define the text splitter
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            add_start_index=True
        )

    def _load_or_create_stores(self):
        """Loads or creates the vector store and indexed URLs set."""
        print(f"Looking for vector store at: {VECTOR_STORE_PATH}")
        print(f"Looking for indexed URLs at: {INDEXED_URLS_PATH}")
        
        # Load indexed URLs if they exist
        if os.path.exists(INDEXED_URLS_PATH):
            print(f"Loading indexed URLs from {INDEXED_URLS_PATH}")
            with open(INDEXED_URLS_PATH, 'rb') as f:
                self.indexed_urls = pickle.load(f)
            print(f"Loaded {len(self.indexed_urls)} indexed URLs")
        
        # Load vector store if it exists
        if os.path.exists(os.path.join(VECTOR_STORE_PATH, "index.faiss")):
            print("Loading existing vector store...")
            self.vector_store = FAISS.load_local(VECTOR_STORE_PATH, self.embeddings)
            print("Vector store loaded successfully")
        else:
            print(f"No existing vector store found at {VECTOR_STORE_PATH}")
            self.vector_store = None

    def _save_stores(self):
        """Saves the vector store and indexed URLs to disk."""
        if self.vector_store:
            self.vector_store.save_local(VECTOR_STORE_PATH)
        with open(INDEXED_URLS_PATH, 'wb') as f:
            pickle.dump(self.indexed_urls, f)

    def build_rag_chain(self):
        """Loads data from new URLs, updates vector store, and builds the RAG chain."""
        # Find new URLs that haven't been indexed yet
        new_urls = [url for url in self.urls if url not in self.indexed_urls]
        
        if new_urls:
            print(f"Found {len(new_urls)} new URL(s) to index...")
            
            # 1. Load documents from new web pages
            loader = WebBaseLoader(new_urls)
            docs = loader.load()

            # 2. Split documents into chunks
            chunks = self.text_splitter.split_documents(docs)
            print(f"Split {len(docs)} documents into {len(chunks)} chunks.")

            # 3. Update or create FAISS vector store
            print("Updating vector store with new embeddings...")
            if self.vector_store is None:
                self.vector_store = FAISS.from_documents(chunks, self.embeddings)
            else:
                self.vector_store.add_documents(chunks)

            # 4. Update indexed URLs and save stores
            self.indexed_urls.update(new_urls)
            self._save_stores()
            print("Vector store updated and saved successfully.")
        else:
            print("No new URLs to index.")

        if not self.vector_store:
            raise ValueError("No vector store available. Please provide at least one URL to index.")

        # 5. Define the prompt for the RAG chain
        prompt_template = """
        You are an assistant for question-answering tasks.
        Answer the following question based ONLY on the provided context.
        If the answer is not in the context, say "I don't know based on the provided documents."
        Be concise and helpful.

        <context>
        {context}
        </context>

        Question: {input}
        """
        prompt = ChatPromptTemplate.from_template(prompt_template)
        
        # 6. Create the "stuff" chain (feeds documents to the LLM)
        question_answer_chain = create_stuff_documents_chain(self.llm, prompt)

        # 7. Create the retrieval chain
        self.rag_chain = create_retrieval_chain(
            self.vector_store.as_retriever(),
            question_answer_chain
        )
        print("RAG chain is ready to answer questions.")

    def query(self, question: str) -> str:
        """
        Queries the RAG chain with a question.

        Args:
            question: The question to ask.

        Returns:
            The answer from the RAG chain.
        """
        if not self.rag_chain:
            return "RAG chain is not initialized. Please run build_rag_chain() first."
            
        response = self.rag_chain.invoke({"input": question})
        return response.get("answer", "Sorry, I couldn't find an answer.")

# --- EXPORTABLE FUNCTION & DEMO ---

# Create a global instance of our RAG app.
# This will automatically load and index the URLs when the script is imported or run.
try:
    rag_app_instance = SimpleRAG(urls=URLS_TO_INDEX)

    # This is the function you can import into other Python scripts
    def query_rag(question: str) -> str:
        """
        A simple, exportable function to query the RAG system.

        Example usage in another file:
        from rag_app import query_rag
        answer = query_rag("What is a RAG system?")
        print(answer)
        """
        return rag_app_instance.query(question)

except Exception as e:
    print(f"\n--- An error occurred during initialization: {e} ---")
    print("Please ensure your OpenAI API key is correct and you have an internet connection.")
    # Define a dummy function so imports don't break
    def query_rag(question: str) -> str:
        return "RAG application failed to initialize. Please check the error message."


# This block runs if you execute the script directly (e.g., `python rag_app.py`)
if __name__ == "__main__":
    print("\n--- RAG Application Demo ---")
    print("Type your question and press Enter. Type 'exit' or 'quit' to end.")

    # Check if the app initialized correctly before starting the loop
    if 'rag_app_instance' not in globals() or not rag_app_instance.rag_chain:
        print("\nCould not start demo because the RAG application failed to initialize.")
    else:
        while True:
            user_question = input("\n> ")
            if user_question.lower() in ["exit", "quit"]:
                break
            
            answer = query_rag(user_question)
            print(f"\nAnswer: {answer}")