import os
import json
import time
import threading
from collections import deque
from datetime import datetime, timezone, timedelta
from typing import Optional

os.environ.setdefault("TZ", "Asia/Ho_Chi_Minh")
if hasattr(time, "tzset"):
    time.tzset()

VN_TZ = timezone(timedelta(hours=7))


def format_vn_time(ts: Optional[float] = None, fmt: str = "%H:%M:%S") -> str:
    """Định dạng mốc thời gian theo múi giờ Việt Nam (UTC+7)."""
    if ts is None:
        return datetime.now(VN_TZ).strftime(fmt)
    return datetime.fromtimestamp(float(ts), tz=VN_TZ).strftime(fmt)

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
    "assets": [],
    "dismissed_asset_agents": [],
    "contingency_rooms": [],
    "tactical_decisions": [],
    "control_audit_logs": [],
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
                "assets": list(STATE.get("assets", [])),
                "dismissed_asset_agents": list(STATE.get("dismissed_asset_agents", [])),
                "contingency_rooms": list(STATE.get("contingency_rooms", [])),
                "tactical_decisions": list(STATE.get("tactical_decisions", [])),
                "control_audit_logs": list(STATE.get("control_audit_logs", [])),
                "decisions": list(STATE.get("decisions", [])),
                "reasoning_stream": list(STATE.get("reasoning_stream", [])),
                "saved_at": format_vn_time(fmt="%Y-%m-%d %H:%M:%S"),
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
                from watchers.tailers import filter_restored_case_alerts

                # Đảm bảo reset cờ is_analyzing và chuẩn hóa múi giờ UTC+7 khi nạp lại soc_state.json
                restored_cases = []
                for c in data["cases"][:100]:
                    if not isinstance(c, dict):
                        continue
                    c["is_analyzing"] = False
                    c.pop("analyzing_since_ts", None)
                    created_ts = c.get("created_at_ts") or c.get("first_alert_ts")
                    if created_ts:
                        c["created_at"] = format_vn_time(created_ts)
                    updated_ts = c.get("last_alert_ts") or created_ts
                    if updated_ts:
                        c["updated_at"] = format_vn_time(updated_ts)
                    for a in c.get("incident_alerts", []) or []:
                        if isinstance(a, dict) and a.get("captured_at_ts"):
                            a["captured_at"] = format_vn_time(a["captured_at_ts"])

                    if not filter_restored_case_alerts(c):
                        continue
                    restored_cases.append(c)

                STATE["cases"] = restored_cases
                STATE["stats"]["total_cases"] = len(restored_cases)
                STATE["stats"]["active_cases"] = sum(1 for c in restored_cases if c.get("status") != "CLOSED")

            if isinstance(data.get("parent_incidents"), list):
                restored_parents = []
                for p in data["parent_incidents"][:50]:
                    if not isinstance(p, dict):
                        continue
                    for ev in p.get("combined_timeline", []) or []:
                        if isinstance(ev, dict) and ev.get("ts"):
                            ev["time"] = format_vn_time(ev["ts"])
                    restored_parents.append(p)
                STATE["parent_incidents"] = restored_parents

            if isinstance(data.get("assets"), list):
                STATE["assets"] = [dict(a) for a in data["assets"] if isinstance(a, dict)]

            if isinstance(data.get("dismissed_asset_agents"), list):
                STATE["dismissed_asset_agents"] = [str(x) for x in data["dismissed_asset_agents"] if str(x).strip()]

            if isinstance(data.get("contingency_rooms"), list):
                restored_rooms = []
                for room in data["contingency_rooms"][:50]:
                    if not isinstance(room, dict):
                        continue
                    r_copy = dict(room)
                    r_copy["ai_thinking"] = False
                    if r_copy.get("created_at_ts"):
                        r_copy["created_at"] = format_vn_time(r_copy["created_at_ts"])
                    if r_copy.get("updated_at_ts"):
                        r_copy["updated_at"] = format_vn_time(r_copy["updated_at_ts"])
                    msgs = []
                    for m in r_copy.get("messages", []) or []:
                        if not isinstance(m, dict):
                            continue
                        m_copy = dict(m)
                        if m_copy.get("ts"):
                            m_copy["time"] = format_vn_time(m_copy["ts"])
                        msgs.append(m_copy)
                    r_copy["messages"] = msgs
                    restored_rooms.append(r_copy)
                STATE["contingency_rooms"] = restored_rooms
                if restored_rooms:
                    STATE["_rooms_initialized"] = True

            if isinstance(data.get("tactical_decisions"), list):
                restored_decs = []
                for dec in data["tactical_decisions"][:200]:
                    if not isinstance(dec, dict):
                        continue
                    d_copy = dict(dec)
                    if d_copy.get("created_at_ts"):
                        d_copy["created_at"] = format_vn_time(d_copy["created_at_ts"])
                    if d_copy.get("reverted_at_ts"):
                        d_copy["reverted_at"] = format_vn_time(d_copy["reverted_at_ts"])
                    if d_copy.get("expires_at_ts"):
                        d_copy["expires_at"] = format_vn_time(d_copy["expires_at_ts"])
                    restored_decs.append(d_copy)
                STATE["tactical_decisions"] = restored_decs
            if isinstance(data.get("control_audit_logs"), list):
                STATE["control_audit_logs"] = [
                    dict(x) for x in data["control_audit_logs"][:500] if isinstance(x, dict)
                ]

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
    victim_ip: Optional[str] = None,
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

    # 5. Trí nhớ Tài sản Thiết bị (Asset Manager)
    target_ips = set()
    if active_case:
        for vip in active_case.get("victim_ips", []) or []:
            vip_s = str(vip or "").strip()
            if vip_s and vip_s.lower() not in ["unknown", "none", "n/a", ""]:
                target_ips.add(vip_s)
    clean_victim = str(victim_ip or "").strip()
    if clean_victim and clean_victim.lower() not in ["unknown", "none", "n/a", ""]:
        target_ips.add(clean_victim)

    matched_assets = []
    for asset in list(STATE.get("assets", [])):
        if not isinstance(asset, dict):
            continue
        asset_agent = str(asset.get("agent_id") or "").strip()
        asset_ips = set()
        main_ip = str(asset.get("ip") or "").strip()
        if main_ip:
            asset_ips.add(main_ip)
        for ex_ip in asset.get("extra_ips", []) or []:
            ex_s = str(ex_ip or "").strip()
            if ex_s:
                asset_ips.add(ex_s)

        agent_matched = (
            clean_agent not in ["", "000", "unknown", "none"]
            and asset_agent == clean_agent
        )
        ip_matched = bool(target_ips & asset_ips) or (has_valid_src and clean_src in asset_ips)
        if agent_matched or ip_matched:
            labels_str = ", ".join(str(lbl) for lbl in (asset.get("labels") or []) if str(lbl).strip()) or "N/A"
            owner_str = asset.get("owner") or "N/A"
            matched_assets.append(
                f"{asset.get('name', asset.get('id', 'Unknown'))} "
                f"(IP: {main_ip or 'N/A'}, Nhãn: [{labels_str}], Chủ sở hữu: {owner_str})"
            )
            if len(matched_assets) >= 2:
                break

    if matched_assets:
        notes.append(
            "- [Asset Memory] Thiết bị trong danh mục tài sản hệ thống liên quan: "
            + " ; ".join(matched_assets)
        )

    if not notes:
        return ""
    return "[BỘ NHỚ HỆ THỐNG SOC (PERSISTENT MEMORY)]:\n" + "\n".join(notes)


def log_event(step_type: str, message: str):
    entry = {
        "time": format_vn_time(),
        "type": step_type,
        "message": message
    }
    STATE["reasoning_stream"].appendleft(entry)
    print(f"[{entry['time']}][{step_type}] {message}", flush=True)