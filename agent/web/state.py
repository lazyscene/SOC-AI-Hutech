import os
import json
import threading
from collections import deque
from datetime import datetime
from typing import Optional

STATE_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "soc_state.json")
_STATE_LOCK = threading.RLock()

STATE = {
    "stats": {
        "total_alerts": 0,
        "true_positives": 0,
        "false_positives": 0,
        "suspicious": 0,
        "unknown": 0,
        "total_cases": 0,
        "active_cases": 0,
        "blocked_ips": [],
        "endpoint_actions": []
    },
    "pfsense_block_details": {},
    "endpoint_containment": {},
    "agent_ip_registry": {},
    "cases": [],
    "parent_incidents": [],
    "reasoning_stream": deque(maxlen=50),
    "decisions": deque(maxlen=30)
}


def save_persistent_state(state_file: Optional[str] = None) -> bool:
    """Lưu trạng thái hệ thống (pfSense, Wazuh AR, thống kê, lịch sử phán quyết) xuống đĩa bền vững."""
    if os.getenv("SOC_DISABLE_STATE_PERSISTENCE") == "1":
        return False

    target_path = state_file or STATE_FILE_PATH
    try:
        with _STATE_LOCK:
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            payload = {
                "stats": {
                    "total_alerts": int(STATE["stats"].get("total_alerts", 0)),
                    "true_positives": int(STATE["stats"].get("true_positives", 0)),
                    "false_positives": int(STATE["stats"].get("false_positives", 0)),
                    "suspicious": int(STATE["stats"].get("suspicious", 0)),
                    "unknown": int(STATE["stats"].get("unknown", 0)),
                    "total_cases": len(STATE.get("cases", [])),
                    "active_cases": sum(1 for c in STATE.get("cases", []) if isinstance(c, dict) and c.get("status") != "CLOSED"),
                    "blocked_ips": list(STATE["stats"].get("blocked_ips", [])),
                    "endpoint_actions": list(STATE["stats"].get("endpoint_actions", [])),
                },
                "pfsense_block_details": dict(STATE.get("pfsense_block_details", {})),
                "endpoint_containment": dict(STATE.get("endpoint_containment", {})),
                "agent_ip_registry": dict(STATE.get("agent_ip_registry", {})),
                "cases": list(STATE.get("cases", [])),
                "parent_incidents": list(STATE.get("parent_incidents", [])),
                "decisions": list(STATE.get("decisions", [])),
                "reasoning_stream": list(STATE.get("reasoning_stream", [])),
                "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            tmp_path = f"{target_path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, target_path)
        return True
    except Exception as e:
        print(f"[WARNING] Không thể lưu persistent state ({target_path}): {e}", flush=True)
        return False


def load_persistent_state(state_file: Optional[str] = None) -> bool:
    """Khôi phục trạng thái hệ thống từ tệp soc_state.json khi khởi động lại."""
    if os.getenv("SOC_DISABLE_STATE_PERSISTENCE") == "1":
        return False

    target_path = state_file or STATE_FILE_PATH
    if not os.path.exists(target_path):
        return False

    try:
        with _STATE_LOCK:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                return False

            saved_stats = data.get("stats", {})
            if isinstance(saved_stats, dict):
                for key in ["total_alerts", "true_positives", "false_positives", "suspicious", "unknown", "total_cases", "active_cases"]:
                    if key in saved_stats:
                        STATE["stats"][key] = int(saved_stats.get(key, 0) or 0)
                if isinstance(saved_stats.get("blocked_ips"), list):
                    STATE["stats"]["blocked_ips"] = list(saved_stats["blocked_ips"])
                if isinstance(saved_stats.get("endpoint_actions"), list):
                    STATE["stats"]["endpoint_actions"] = list(saved_stats["endpoint_actions"])

            if isinstance(data.get("pfsense_block_details"), dict):
                STATE["pfsense_block_details"] = dict(data["pfsense_block_details"])

            if isinstance(data.get("endpoint_containment"), dict):
                STATE["endpoint_containment"] = dict(data["endpoint_containment"])

            if isinstance(data.get("agent_ip_registry"), dict):
                STATE["agent_ip_registry"] = dict(data["agent_ip_registry"])

            if isinstance(data.get("cases"), list):
                # Đảm bảo reset cờ is_analyzing nếu container khởi động lại giữa chừng
                restored_cases = []
                for c in data["cases"][:100]:
                    if isinstance(c, dict):
                        c["is_analyzing"] = False
                        restored_cases.append(c)
                STATE["cases"] = restored_cases
                STATE["stats"]["total_cases"] = len(restored_cases)
                STATE["stats"]["active_cases"] = sum(1 for c in restored_cases if c.get("status") != "CLOSED")

            if isinstance(data.get("parent_incidents"), list):
                STATE["parent_incidents"] = list(data["parent_incidents"][:50])

            if isinstance(data.get("decisions"), list):
                STATE["decisions"] = deque(data["decisions"][:30], maxlen=30)

            if isinstance(data.get("reasoning_stream"), list):
                STATE["reasoning_stream"] = deque(data["reasoning_stream"][:50], maxlen=50)
        return True
    except Exception as e:
        print(f"[WARNING] Không thể nạp persistent state ({target_path}): {e}", flush=True)
        return False


def get_agent_memory_context(
    src_ip: str = "unknown",
    agent_id: str = "000",
    file_path: Optional[str] = None,
    primary_hash: Optional[str] = None,
    case_id: Optional[str] = None,
) -> str:
    """
    Tổng hợp Trí nhớ bền vững (pfSense, Wazuh AR, Case Management, Lịch sử sự cố) để tiêm vào ngữ cảnh AI Agent.
    """
    notes = []
    clean_src = (src_ip or "").strip()
    has_valid_src = clean_src.lower() not in ["unknown", "none", "n/a", ""]

    # 1. Trí nhớ pfSense SOC_BLOCKLIST
    blocked_ips = STATE["stats"].get("blocked_ips", [])
    if has_valid_src and clean_src in blocked_ips:
        detail = STATE.get("pfsense_block_details", {}).get(clean_src) or "Đã chặn trong Alias SOC_BLOCKLIST"
        notes.append(
            f"- [pfSense Memory] IP {clean_src} hiện ĐÃ NẰM TRONG danh sách chặn SOC_BLOCKLIST trên pfSense "
            f"(Lý do trước đó: {detail}). Nếu cảnh báo vẫn lặp lại hoặc là tấn công mới, hãy ghi nhận IP này đang bị chặn."
        )

    # 2. Trí nhớ Wazuh Endpoint AR
    clean_agent = str(agent_id or "").strip()
    if clean_agent and clean_agent not in ["000", "unknown", "none"]:
        ep_record = STATE.get("endpoint_containment", {}).get(clean_agent)
        if isinstance(ep_record, dict) and ep_record:
            iso_status = ep_record.get("isolation_status", "UNKNOWN")
            q_files = ep_record.get("quarantined_files", [])
            k_procs = ep_record.get("killed_processes", [])
            notes.append(
                f"- [Wazuh AR Memory] Agent {clean_agent} có hồ sơ phản ứng trước đó: "
                f"Trạng thái={iso_status}, File đã cách ly={q_files or 'Không'}, Tiến trình đã dừng={k_procs or 'Không'}."
            )

    # 3. Trí nhớ Case Management & Liên kết Kill-Chain
    active_case = None
    for c in STATE.get("cases", []):
        if not isinstance(c, dict):
            continue
        if case_id and c.get("id") == case_id:
            active_case = c
            break
        if c.get("status") != "CLOSED":
            if has_valid_src and c.get("domain") == "NETWORK" and c.get("src_ip") == clean_src:
                active_case = c
                break
            if not has_valid_src and c.get("domain") == "ENDPOINT" and str(c.get("agent_id", "")) == clean_agent:
                active_case = c
                break

    if active_case:
        victims = active_case.get("victim_ips", [])
        rel_ids = active_case.get("related_case_ids", [])
        parent_inc = active_case.get("parent_incident_id")
        rel_info = f", Liên kết: {rel_ids} (Incident cha: {parent_inc})" if (rel_ids or parent_inc) else ""
        notes.append(
            f"- [Case Memory] Case {active_case.get('id')} ({active_case.get('domain')}) hiện đã gom "
            f"{active_case.get('alert_count', 1)} alerts, các mục tiêu: {victims or 'N/A'}, "
            f"Verdict hiện tại: {active_case.get('verdict', 'UNKNOWN')}, Severity: {active_case.get('severity', 'LOW')}{rel_info}."
        )

    # 4. Trí nhớ Lịch sử Sự cố (decisions) - tối đa 2 sự cố gần nhất khớp ngữ cảnh
    matched_decisions = []
    for dec in list(STATE.get("decisions", [])):
        if not isinstance(dec, dict):
            continue
        is_match = False
        if has_valid_src and dec.get("src_ip") == clean_src:
            is_match = True
        elif not has_valid_src:
            if primary_hash and dec.get("primary_hash") == primary_hash:
                is_match = True
            elif file_path and dec.get("file_path") == file_path and str(dec.get("agent_id", "")) == clean_agent:
                is_match = True
            elif clean_agent not in ["000", "unknown", "none", ""] and str(dec.get("agent_id", "")) == clean_agent:
                is_match = True

        if is_match:
            matched_decisions.append(
                f"[{dec.get('time', '?')}] {dec.get('verdict', 'UNKNOWN')} - {dec.get('title', '')}"
            )
            if len(matched_decisions) >= 2:
                break

    if matched_decisions:
        notes.append(
            f"- [Incident History Memory] Hệ thống đã từng xử lý {len(matched_decisions)} sự cố liên quan gần đây: "
            + " ; ".join(matched_decisions)
        )

    if not notes:
        return ""
    return "[BỘ NHỚ HỆ THỐNG SOC (PERSISTENT MEMORY)]:\n" + "\n".join(notes)


def log_event(step_type: str, message: str):
    entry = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": step_type,
        "message": message
    }
    STATE["reasoning_stream"].appendleft(entry)
    print(f"[{entry['time']}][{step_type}] {message}", flush=True)