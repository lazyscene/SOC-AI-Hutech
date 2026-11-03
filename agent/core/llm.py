import os
import requests

OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://192.168.63.1:11434/api/chat")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen3.5:4b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))

def call_ollama(messages: list, tools: list = None):
    payload = {
        "model": LLM_MODEL,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 2048
        }
    }
    if tools:
        payload["tools"] = tools
    response = requests.post(OLLAMA_API_URL, json=payload, timeout=OLLAMA_TIMEOUT)
    response.raise_for_status()
    return response.json()

