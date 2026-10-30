import os
import requests

OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://192.168.63.1:11434/api/chat")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen3.5:4b")

def call_ollama(messages: list, tools: list):
    payload = {
        "model": LLM_MODEL,
        "messages": messages,
        "tools": tools,
        "stream": False
    }
    response = requests.post(OLLAMA_API_URL, json=payload, timeout=45)
    response.raise_for_status()
    return response.json()

