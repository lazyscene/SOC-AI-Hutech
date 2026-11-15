import re
import json
import time
import threading
from typing import Any, Dict, List, Optional, Set, Tuple
from web.state import STATE, log_event, save_persistent_state, format_vn_time
from core.llm import call_ollama, LLM_MODEL
from tools.base import TOOLS_SCHEMA, TOOLS_MAP
from core.case_manager import (
    _CASE_LOCK,
    _next_sequence_id,
    get_case_by_id,
    update_case_status,
    get_nat_ip_map,
)
from core.asset_manager import (
    get_assets_with_case_counts,
    _does_case_match_asset,
)

VALID_STAGES = ["Containment", "Investigation", "Eradication", "Post-Incident"]
VALID_PRIORITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
VALID_DECISION_TYPES = {
    "BLOCK_IP",
    "ISOLATE_ENDPOINT",
    "RELEASE_ENDPOINT",
    "FLAG_ASSET",
    "CLOSE_CASE",
}

MAX_ROOM_MESSAGES = 200


def _now_and_str(now_ts: Optional[float] = None) -> Tuple[float, str]:
    ts = now_ts if now_ts is not None else time.time()
    return ts, format_vn_time(ts)


def _normalize_stage(raw_stage: Any) -> str:
    s = str(raw_stage or "").strip().lower()
    for st in VALID_STAGES:
        if st.lower() == s:
            return st
    return "Containment"


def _normalize_priority(raw_priority: Any) -> str:
    p = str(raw_priority or "").strip().upper()
    return p if p in VALID_PRIORITIES else "HIGH"


def _get_room_by_id(room_id: str) -> Optional[Dict[str, Any]]:
    clean_id = str(room_id or "").strip()
    for r in STATE.get("contingency_rooms", []):
        if isinstance(r, dict) and r.get("id") == clean_id:
            return r
    return None


def _get_decision_by_id(decision_id: str) -> Optional[Dict[str, Any]]:
    clean_id = str(decision_id or "").strip()
    for d in STATE.get("tactical_decisions", []):
        if isinstance(d, dict) and d.get("id") == clean_id:
            return d
    return None


def _append_room_message(
    room: Dict[str, Any],
    sender: str,
    role: str,
    text: str,
    case_id: str = "",
    decision_id: str = "",
    now_ts: Optional[float] = None,
) -> Dict[str, Any]:
    ts, time_str = _now_and_str(now_ts)
    msgs = room.setdefault("messages", [])
    msg = {
        "id": _next_sequence_id("MSG", msgs),
        "sender": sender,
        "role": role,
        "text": text,
        "time": time_str,
        "ts": ts,
        "case_id": case_id,
        "decision_id": decision_id,
    }
    msgs.append(msg)
    if len(msgs) > MAX_ROOM_MESSAGES:
        del msgs[:-MAX_ROOM_MESSAGES]
    room["updated_at_ts"] = ts
    room["updated_at"] = time_str
    return msg


def _find_room_for_case(case_id: str) -> Optional[Dict[str, Any]]:
    for r in STATE.get("contingency_rooms", []):
        if isinstance(r, dict) and case_id in (r.get("case_ids") or []):
            return r
    return None


def _sync_single_case_decisions_locked(case: Dict[str, Any], room_id: str = "") -> List[Dict[str, Any]]:
    """Đồng bộ các hành động SOAR của 1 Case thành Decision có thể đảo ngược (gọi bên trong _CASE_LOCK)."""
    if not isinstance(case, dict) or not case.get("id"):
        return []

    case_id = str(case["id"])
    decisions = STATE.setdefault("tactical_decisions", [])
    attached_room = room_id or (_find_room_for_case(case_id) or {}).get("id", "")
    created_or_matched: List[Dict[str, Any]] = []
    ts, time_str = _now_and_str()

    # Gắn room_id cho các decision thuộc case chưa gắn room
    if attached_room:
        for d in decisions:
            if isinstance(d, dict) and d.get("case_id") == case_id and not d.get("room_id"):
                d["room_id"] = attached_room

    blocked_ips = set(str(ip).strip() for ip in (STATE["stats"].get("blocked_ips") or []) if str(ip).strip())
    actions_taken = [str(a) for a in (case.get("actions_taken") or [])]

    # 1. Kiểm tra hành động chặn IP trên pfSense
    ip_targets: List[str] = []
    case_src = str(case.get("src_ip") or "").strip()
    if case_src and case_src in blocked_ips:
        ip_targets.append(case_src)
    for act in actions_taken:
        m = re.search(r"pfSense Block IP\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", act)
        if m and m.group(1) not in ip_targets:
            ip_targets.append(m.group(1))

    for ip_target in ip_targets:
        existing = next(
            (
                d for d in decisions
                if isinstance(d, dict)
                and d.get("case_id") == case_id
                and d.get("action_type") == "BLOCK_IP"
                and d.get("target") == ip_target
            ),
            None,
        )
        if existing:
            created_or_matched.append(existing)
        else:
            dec_id = _next_sequence_id("DEC", decisions)
            dec = {
                "id": dec_id,
                "room_id": attached_room,
                "case_id": case_id,
                "action_type": "BLOCK_IP",
                "target": ip_target,
                "title": f"Chặn IP {ip_target} trên pfSense Firewall",
                "reason": STATE.get("pfsense_block_details", {}).get(ip_target) or f"SOAR tự động chặn IP từ {case_id}",
                "source": "AI_SOAR",
                "status": "ACTIVE",
                "reversible": True,
                "execution_result": f"Đã thêm {ip_target} vào Alias SOC_BLOCKLIST",
                "revert_result": "",
                "revert_reason": "",
                "created_at": case.get("updated_at") or time_str,
                "created_at_ts": float(case.get("last_alert_ts") or ts),
                "reverted_at": "",
                "reverted_at_ts": None,
            }
            decisions.insert(0, dec)
            created_or_matched.append(dec)

    # 2. Kiểm tra hành động cô lập / mở cô lập Endpoint (Wazuh AR)
    ep_containment = STATE.get("endpoint_containment", {})
    case_agent = str(case.get("agent_id") or "").strip()
    ep_rec = ep_containment.get(case_agent) if case_agent and isinstance(ep_containment, dict) else None
    has_ep_action = bool(ep_rec) or any("Phase 1" in a or "Phase 2" in a for a in actions_taken)
    if has_ep_action and case_agent and case_agent.lower() not in ("000", "unknown", "none"):
        iso_status = str((ep_rec or {}).get("isolation_status") or "").upper()
        if "UNISOLATED" in iso_status:
            ep_type = "RELEASE_ENDPOINT"
            ep_title = f"Mở cô lập mạng Agent {case_agent} (Giữ cách ly tệp)"
        else:
            ep_type = "ISOLATE_ENDPOINT"
            ep_title = f"Cô lập mạng Endpoint Agent {case_agent} qua Wazuh AR"

        existing_ep = next(
            (
                d for d in decisions
                if isinstance(d, dict)
                and d.get("case_id") == case_id
                and d.get("target") == case_agent
                and d.get("action_type") in ("ISOLATE_ENDPOINT", "RELEASE_ENDPOINT")
            ),
            None,
        )
        if existing_ep:
            created_or_matched.append(existing_ep)
        else:
            dec_id = _next_sequence_id("DEC", decisions)
            dec = {
                "id": dec_id,
                "room_id": attached_room,
                "case_id": case_id,
                "action_type": ep_type,
                "target": case_agent,
                "title": ep_title,
                "reason": (ep_rec or {}).get("reason") or f"Wazuh Active Response cho {case_id}",
                "source": "AI_SOAR",
                "status": "ACTIVE",
                "reversible": True,
                "execution_result": f"Trạng thái hiện tại: {iso_status or 'ISOLATED'}",
                "revert_result": "",
                "revert_reason": "",
                "created_at": (ep_rec or {}).get("updated_at") or case.get("updated_at") or time_str,
                "created_at_ts": float(case.get("last_alert_ts") or ts),
                "reverted_at": "",
                "reverted_at_ts": None,
            }
            decisions.insert(0, dec)
            created_or_matched.append(dec)

    return created_or_matched


def sync_case_decisions(case: Dict[str, Any], room_id: str = "") -> List[Dict[str, Any]]:
    """Đồng bộ các hành động SOAR của 1 Case thành Decision có nút đảo ngược."""
    with _CASE_LOCK:
        return _sync_single_case_decisions_locked(case, room_id=room_id)


def sync_case_decisions_for_all_cases() -> List[Dict[str, Any]]:
    """Quét toàn bộ Case đang có để đồng bộ Decision còn thiếu."""
    with _CASE_LOCK:
        for c in STATE.get("cases", []):
            if isinstance(c, dict):
                _sync_single_case_decisions_locked(c)
        return list(STATE.get("tactical_decisions", []))


def ensure_default_rooms() -> List[Dict[str, Any]]:
    """Khởi tạo phòng tác chiến mặc định nếu hệ thống chưa khởi tạo phòng và đồng bộ Decision."""
    with _CASE_LOCK:
        rooms = STATE.setdefault("contingency_rooms", [])
        if not rooms and not STATE.get("_rooms_initialized"):
            ts, time_str = _now_and_str()
            default_room = {
                "id": "ROOM-0001",
                "name": "Main Contingency Room - Phòng Tác Chiến Trung Tâm",
                "stage": "Containment",
                "priority": "HIGH",
                "status": "OPEN",
                "commander": "SOC Commander",
                "case_ids": [],
                "flagged_asset_ids": [],
                "messages": [
                    {
                        "id": "MSG-0001",
                        "sender": "SOC System",
                        "role": "SYSTEM",
                        "text": (
                            "🚨 Phòng tác chiến ROOM-0001 đã sẵn sàng. Kéo hoặc chọn Case đưa vào Room để xem Board "
                            "tổng quan, trao đổi chiến thuật (gõ @ai để hỏi cố vấn AI) và quản lý các Decisions có thể đảo ngược."
                        ),
                        "time": time_str,
                        "ts": ts,
                        "case_id": "",
                        "decision_id": "",
                    }
                ],
                "created_at": time_str,
                "updated_at": time_str,
                "created_at_ts": ts,
                "updated_at_ts": ts,
            }
            rooms.append(default_room)
            STATE["_rooms_initialized"] = True

        for c in STATE.get("cases", []):
            if isinstance(c, dict):
                _sync_single_case_decisions_locked(c)
        return rooms


def compute_room_board_metrics(
    room: Dict[str, Any],
    all_cases: List[Dict[str, Any]],
    all_assets: List[Dict[str, Any]],
    all_decisions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Tính toán bộ chỉ số Board tổng quan của một Contingency Room."""
    room_id = str(room.get("id") or "")
    room_case_ids = [str(cid) for cid in (room.get("case_ids") or []) if str(cid).strip()]
    room_case_set = set(room_case_ids)
    cases_by_id = {str(c.get("id")): c for c in all_cases if isinstance(c, dict) and c.get("id")}
    room_cases = [cases_by_id[cid] for cid in room_case_ids if cid in cases_by_id]

    room_decisions = [
        d for d in all_decisions
        if isinstance(d, dict) and (d.get("room_id") == room_id or d.get("case_id") in room_case_set)
    ]

    flagged_asset_set: Set[str] = set(str(aid) for aid in (room.get("flagged_asset_ids") or []) if str(aid).strip())
    nat_map = get_nat_ip_map()
    blocked_ips = set(str(ip).strip() for ip in (STATE["stats"].get("blocked_ips") or []))
    ep_containment = STATE.get("endpoint_containment", {})

    compromised_assets: List[Dict[str, Any]] = []
    compromised_asset_ids: Set[str] = set()
    contained_asset_ids: Set[str] = set()

    for asset in all_assets:
        if not isinstance(asset, dict):
            continue
        aid = str(asset.get("id") or "")
        c_status = str(asset.get("containment_status") or "").upper()
        is_isolated = "TEMP_ISOLATED" in c_status or "ISOLATED (LOCKED)" in c_status
        is_contained_any = is_isolated or ("UNISOLATED" in c_status)

        matched_room_cases = [c for c in room_cases if _does_case_match_asset(c, asset, nat_map)]
        if is_contained_any and matched_room_cases:
            contained_asset_ids.add(aid)

        is_compromised_by_case = any(
            str(c.get("verdict", "")).upper() in ("TRUE POSITIVE", "SUSPICIOUS") or is_isolated
            for c in matched_room_cases
        )
        if aid in flagged_asset_set or is_compromised_by_case:
            compromised_asset_ids.add(aid)
            compromised_assets.append(asset)

    room_assets_flags = []
    for asset in all_assets:
        if not isinstance(asset, dict):
            continue
        aid = str(asset.get("id") or "")
        matched_count = sum(1 for c in room_cases if _does_case_match_asset(c, asset, nat_map))
        if aid in compromised_asset_ids:
            flag = "COMPROMISED"
        elif aid in contained_asset_ids:
            flag = "CONTAINED"
        else:
            flag = "CLEAN"
        room_assets_flags.append({
            "id": aid,
            "name": asset.get("name", aid),
            "ip": asset.get("ip", ""),
            "agent_id": asset.get("agent_id", ""),
            "flag": flag,
            "room_case_count": matched_count,
        })

    in_progress_cases_count = sum(1 for c in room_cases if c.get("status") != "CLOSED")
    done_cases_count = sum(1 for c in room_cases if c.get("status") == "CLOSED")
    open_decisions = [d for d in room_decisions if d.get("status") == "ACTIVE"]
    reverted_decisions = [d for d in room_decisions if d.get("status") == "REVERTED"]
    reversible_decisions_count = sum(1 for d in open_decisions if d.get("reversible", True))

    open_vulns_alerts = sum(int(c.get("alert_count", 0) or 0) for c in room_cases if c.get("status") != "CLOSED")
    exploited_open_count = sum(
        1 for c in room_cases
        if str(c.get("verdict", "")).upper() == "TRUE POSITIVE" and c.get("status") != "CLOSED"
    )

    contained_ips = {
        str(c.get("src_ip")) for c in room_cases
        if c.get("src_ip") and str(c.get("src_ip")) in blocked_ips
    }
    contained_agents = {
        str(c.get("agent_id")) for c in room_cases
        if c.get("agent_id")
        and isinstance(ep_containment.get(str(c.get("agent_id"))), dict)
        and (
            "TEMP_ISOLATED" in str(ep_containment[str(c["agent_id"])].get("isolation_status", "")).upper()
            or "ISOLATED (LOCKED)" in str(ep_containment[str(c["agent_id"])].get("isolation_status", "")).upper()
        )
    }
    contained_targets_count = len(contained_ips) + len(contained_agents)

    mitre_set: Set[str] = set()
    for c in room_cases:
        for tag in (c.get("mitre_tags") or []):
            mitre_set.add(str(tag).split(" - ")[0].strip().upper())
        for code in (c.get("seen_mitre_ids") or []):
            mitre_set.add(str(code).strip().upper())
    mitre_list = sorted(m for m in mitre_set if m)

    room_cases_enriched = []
    for c in room_cases:
        cid = str(c.get("id"))
        case_decs = [d for d in room_decisions if d.get("case_id") == cid]
        dec_total = len(case_decs)
        dec_active = sum(1 for d in case_decs if d.get("status") == "ACTIVE")
        dec_reverted = sum(1 for d in case_decs if d.get("status") == "REVERTED")
        matched_asset_names = [a.get("name", a.get("id")) for a in all_assets if _does_case_match_asset(c, a, nat_map)]
        case_comp_assets = [a.get("name", a.get("id")) for a in compromised_assets if _does_case_match_asset(c, a, nat_map)]

        if c.get("status") == "CLOSED":
            progress_pct = 100
        elif dec_total > 0:
            progress_pct = int(round((dec_active / dec_total) * 100))
        else:
            progress_pct = 0

        room_cases_enriched.append({
            "id": cid,
            "title": c.get("title", ""),
            "domain": c.get("domain", ""),
            "status": c.get("status", "OPEN"),
            "severity": c.get("severity", "LOW"),
            "verdict": c.get("verdict", "UNKNOWN"),
            "src_ip": c.get("src_ip", "unknown"),
            "victim_ips": list(c.get("victim_ips") or []),
            "agent_id": c.get("agent_id", ""),
            "alert_count": int(c.get("alert_count", 0) or 0),
            "slm_calls": int(c.get("slm_calls", 0) or 0),
            "stage_label": room.get("stage", "Containment") if c.get("status") != "CLOSED" else "Closed / Resolved",
            "commander": room.get("commander", "SOC Commander"),
            "decisions_total": dec_total,
            "decisions_active": dec_active,
            "decisions_reverted": dec_reverted,
            "matched_assets": matched_asset_names,
            "compromised_count": len(case_comp_assets),
            "progress_pct": progress_pct,
            "updated_at": c.get("updated_at", ""),
        })

    return {
        "case_count": len(room_cases),
        "in_progress_cases_count": in_progress_cases_count,
        "done_cases_count": done_cases_count,
        "compromised_assets_count": len(compromised_assets),
        "unflagged_assets_count": max(0, len(all_assets) - len(compromised_assets)),
        "open_decisions_count": len(open_decisions),
        "reversible_decisions_count": reversible_decisions_count,
        "exceptions_reverted_count": len(reverted_decisions),
        "open_tasks_count": len(room_decisions),
        "open_vulnerabilities_alerts_count": open_vulns_alerts,
        "exploited_open_count": exploited_open_count,
        "contained_targets_count": contained_targets_count,
        "mitre_techniques_count": len(mitre_list),
        "mitre_techniques": mitre_list,
        "room_cases_enriched": room_cases_enriched,
        "room_assets_flags": room_assets_flags,
        "refreshed_at": format_vn_time(),
    }


def get_contingency_rooms_overview() -> Dict[str, Any]:
    """Trả về toàn bộ Contingency Rooms kèm Board metrics và danh sách Tactical Decisions."""
    with _CASE_LOCK:
        rooms = ensure_default_rooms()
        all_cases = list(STATE.get("cases", []))
        all_assets = get_assets_with_case_counts()
        all_decisions = list(STATE.get("tactical_decisions", []))

        enriched_rooms = []
        for r in rooms:
            if not isinstance(r, dict):
                continue
            r_id = r.get("id", "")
            r_case_set = set(str(cid) for cid in (r.get("case_ids") or []))
            board = compute_room_board_metrics(r, all_cases, all_assets, all_decisions)
            room_decs = [
                dict(d) for d in all_decisions
                if isinstance(d, dict) and (d.get("room_id") == r_id or d.get("case_id") in r_case_set)
            ]
            room_copy = dict(r)
            room_copy["board"] = board
            room_copy["room_decisions"] = room_decs
            enriched_rooms.append(room_copy)

        return {
            "rooms": enriched_rooms,
            "decisions": [dict(d) for d in all_decisions if isinstance(d, dict)],
        }


def create_contingency_room(payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], str]:
    """Tạo một phòng tác chiến Contingency Room mới."""
    if not isinstance(payload, dict):
        return False, {}, "Dữ liệu tạo Room không hợp lệ."

    name = str(payload.get("name") or "").strip()
    if not name:
        return False, {}, "Thiếu tên phòng tác chiến (name)."

    stage = _normalize_stage(payload.get("stage", "Containment"))
    priority = _normalize_priority(payload.get("priority", "HIGH"))
    commander = str(payload.get("commander") or "").strip() or "SOC Commander"
    initial_cases = [str(cid).strip() for cid in (payload.get("case_ids") or []) if str(cid).strip()]

    with _CASE_LOCK:
        rooms = ensure_default_rooms()
        ts, time_str = _now_and_str()
        room_id = _next_sequence_id("ROOM", rooms)
        valid_case_ids: List[str] = []
        for cid in initial_cases:
            c_obj = get_case_by_id(cid)
            if c_obj and cid not in valid_case_ids:
                valid_case_ids.append(cid)

        new_room = {
            "id": room_id,
            "name": name,
            "stage": stage,
            "priority": priority,
            "status": "OPEN",
            "commander": commander,
            "case_ids": valid_case_ids,
            "flagged_asset_ids": [],
            "messages": [],
            "created_at": time_str,
            "updated_at": time_str,
            "created_at_ts": ts,
            "updated_at_ts": ts,
        }
        _append_room_message(
            new_room,
            sender="SOC System",
            role="SYSTEM",
            text=f"🚨 Khởi tạo phòng tác chiến {room_id}: {name} (Giai đoạn: {stage}, Ưu tiên: {priority}).",
            now_ts=ts,
        )
        for cid in valid_case_ids:
            c_obj = get_case_by_id(cid)
            if c_obj:
                _sync_single_case_decisions_locked(c_obj, room_id=room_id)
                _append_room_message(
                    new_room,
                    sender="SOC System",
                    role="SYSTEM",
                    text=f"📥 Đã kéo hồ sơ {cid} ({c_obj.get('title', '')}) vào phòng.",
                    case_id=cid,
                    now_ts=ts,
                )

        rooms.insert(0, new_room)
        STATE["_rooms_initialized"] = True
        save_persistent_state()
        log_event("SYSTEM", f"🚨 Đã tạo Contingency Room {room_id}: {name}")
        return True, _enrich_single_room_locked(new_room), f"Đã tạo phòng tác chiến {room_id} ({name})."


def _enrich_single_room_locked(room: Dict[str, Any]) -> Dict[str, Any]:
    all_cases = list(STATE.get("cases", []))
    all_assets = get_assets_with_case_counts()
    all_decisions = list(STATE.get("tactical_decisions", []))
    r_id = room.get("id", "")
    r_case_set = set(str(cid) for cid in (room.get("case_ids") or []))

    room_copy = dict(room)
    room_copy["board"] = compute_room_board_metrics(room, all_cases, all_assets, all_decisions)
    room_copy["room_decisions"] = [
        dict(d) for d in all_decisions
        if isinstance(d, dict) and (d.get("room_id") == r_id or d.get("case_id") in r_case_set)
    ]
    return room_copy


def update_contingency_room(room_id: str, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], str]:
    """Cập nhật tên, giai đoạn (stage), độ ưu tiên hoặc trạng thái của phòng tác chiến."""
    if not isinstance(payload, dict):
        return False, {}, "Dữ liệu cập nhật Room không hợp lệ."

    with _CASE_LOCK:
        ensure_default_rooms()
        room = _get_room_by_id(room_id)
        if not room:
            return False, {}, f"Không tìm thấy phòng tác chiến {room_id}."

        ts, time_str = _now_and_str()
        changes = []
        if payload.get("name"):
            room["name"] = str(payload["name"]).strip()
            changes.append(f"Tên: {room['name']}")
        if payload.get("stage"):
            room["stage"] = _normalize_stage(payload["stage"])
            changes.append(f"Giai đoạn: {room['stage']}")
        if payload.get("priority"):
            room["priority"] = _normalize_priority(payload["priority"])
            changes.append(f"Ưu tiên: {room['priority']}")
        if payload.get("status"):
            st = str(payload["status"]).strip().upper()
            if st in ("OPEN", "ARCHIVED"):
                room["status"] = st
                changes.append(f"Trạng thái: {st}")

        room["updated_at_ts"] = ts
        room["updated_at"] = time_str
        if changes:
            _append_room_message(
                room,
                sender="SOC System",
                role="SYSTEM",
                text=f"⚙️ Cập nhật phòng {room_id}: {', '.join(changes)}.",
                now_ts=ts,
            )
        save_persistent_state()
        return True, _enrich_single_room_locked(room), f"Đã cập nhật phòng {room_id}."


def delete_contingency_room(room_id: str) -> Tuple[bool, str]:
    """Xóa phòng tác chiến theo mã ROOM-xxxx."""
    clean_id = str(room_id or "").strip()
    with _CASE_LOCK:
        rooms = ensure_default_rooms()
        idx = next((i for i, r in enumerate(rooms) if isinstance(r, dict) and r.get("id") == clean_id), None)
        if idx is None:
            return False, f"Không tìm thấy phòng {clean_id}."

        removed = rooms.pop(idx)
        STATE["_rooms_initialized"] = True
        for d in STATE.get("tactical_decisions", []):
            if isinstance(d, dict) and d.get("room_id") == clean_id:
                d["room_id"] = ""
        save_persistent_state()
        log_event("SYSTEM", f"🗑️ Đã xóa phòng tác chiến {clean_id}: {removed.get('name', '')}")
        return True, f"Đã xóa phòng tác chiến {clean_id}."


def attach_case_to_room(room_id: str, case_id: str) -> Tuple[bool, Dict[str, Any], str]:
    """Kéo/gắn một hồ sơ Case vào phòng tác chiến và đồng bộ Decisions của Case."""
    clean_cid = str(case_id or "").strip()
    if not clean_cid:
        return False, {}, "Thiếu mã Case (case_id)."

    with _CASE_LOCK:
        ensure_default_rooms()
        room = _get_room_by_id(room_id)
        if not room:
            return False, {}, f"Không tìm thấy phòng tác chiến {room_id}."

        case_obj = get_case_by_id(clean_cid)
        if not case_obj:
            return False, {}, f"Không tìm thấy hồ sơ {clean_cid}."

        case_ids = room.setdefault("case_ids", [])
        if clean_cid in case_ids:
            _sync_single_case_decisions_locked(case_obj, room_id=room["id"])
            return True, _enrich_single_room_locked(room), f"Hồ sơ {clean_cid} đã có trong phòng {room['id']}."

        case_ids.append(clean_cid)
        synced = _sync_single_case_decisions_locked(case_obj, room_id=room["id"])
        _append_room_message(
            room,
            sender="SOC System",
            role="SYSTEM",
            text=(
                f"📥 Đã kéo hồ sơ {clean_cid} ({case_obj.get('domain', '')} | {case_obj.get('verdict', 'UNKNOWN')} | "
                f"{case_obj.get('title', '')}) vào phòng {room['id']} — Đồng bộ {len(synced)} quyết định liên quan."
            ),
            case_id=clean_cid,
        )
        save_persistent_state()
        log_event("CASE", f"🚨 Đã đưa {clean_cid} vào Contingency Room {room['id']}")
        return True, _enrich_single_room_locked(room), f"Đã kéo {clean_cid} vào phòng {room['id']}."


def detach_case_from_room(room_id: str, case_id: str) -> Tuple[bool, Dict[str, Any], str]:
    """Gỡ một Case khỏi phòng tác chiến."""
    clean_cid = str(case_id or "").strip()
    with _CASE_LOCK:
        ensure_default_rooms()
        room = _get_room_by_id(room_id)
        if not room:
            return False, {}, f"Không tìm thấy phòng {room_id}."

        case_ids = room.setdefault("case_ids", [])
        if clean_cid not in case_ids:
            return False, {}, f"Hồ sơ {clean_cid} không nằm trong phòng {room_id}."

        case_ids.remove(clean_cid)
        for d in STATE.get("tactical_decisions", []):
            if (
                isinstance(d, dict)
                and d.get("room_id") == room["id"]
                and d.get("case_id") == clean_cid
                and d.get("source") == "AI_SOAR"
            ):
                d["room_id"] = ""

        _append_room_message(
            room,
            sender="SOC System",
            role="SYSTEM",
            text=f"📤 Đã gỡ hồ sơ {clean_cid} khỏi phòng {room['id']}.",
            case_id=clean_cid,
        )
        save_persistent_state()
        return True, _enrich_single_room_locked(room), f"Đã gỡ {clean_cid} khỏi phòng {room['id']}."


ROOM_INVESTIGATION_TOOL_NAMES = {
    "tool_check_ip_reputation",
    "tool_check_ip_context",
    "tool_check_file_hash",
    "tool_query_misp_ioc",
    "tool_lookup_mitre_attack",
    "tool_decode_base64",
}

ROOM_ACTION_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "tool_room_execute_decision",
            "description": (
                "Thuc thi mot hanh dong tac chien trong Contingency Room va ghi nhan thanh Decision co nut Dao nguoc "
                "(BLOCK_IP tren pfSense, ISOLATE_ENDPOINT / RELEASE_ENDPOINT tren Wazuh AR, FLAG_ASSET, hoac CLOSE_CASE)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action_type": {
                        "type": "string",
                        "enum": ["BLOCK_IP", "ISOLATE_ENDPOINT", "RELEASE_ENDPOINT", "FLAG_ASSET", "CLOSE_CASE"],
                        "description": "Loai quyet dinh tac chien",
                    },
                    "target": {
                        "type": "string",
                        "description": "Muc tieu (IP nhu 192.168.63.x, Agent ID nhu 002, ASSET-xxxx, hoac CASE-xxxx)",
                    },
                    "reason": {"type": "string", "description": "Ly do thuc thi quyet dinh"},
                    "case_id": {"type": "string", "description": "Ma Case lien quan (neu co, vi du CASE-0001)"},
                },
                "required": ["action_type", "target", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "tool_room_revert_decision",
            "description": "Dao nguoc (Rollback) mot quyet dinh DEC-xxxx dang ACTIVE (vi du go chan IP, mo co lap endpoint, mo lai Case).",
            "parameters": {
                "type": "object",
                "properties": {
                    "decision_id": {"type": "string", "description": "Ma quyet dinh can dao nguoc (vi du DEC-0001)"},
                    "reason": {"type": "string", "description": "Ly do dao nguoc"},
                },
                "required": ["decision_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "tool_room_attach_case",
            "description": "Keo mot ho so CASE-xxxx vao Contingency Room hien tai de dieu tra va theo doi tren Board.",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Ma Case can keo vao Room (vi du CASE-0001)"},
                },
                "required": ["case_id"],
            },
        },
    },
]


def _get_room_agent_tools_schema() -> List[Dict[str, Any]]:
    """Tổng hợp công cụ điều tra + công cụ tác chiến Room cho Qwen AI Agent."""
    import tools.analysis_tools  # noqa: F401
    import tools.threat_intel_tools  # noqa: F401

    tools = [
        schema for schema in TOOLS_SCHEMA
        if isinstance(schema, dict)
        and schema.get("function", {}).get("name") in ROOM_INVESTIGATION_TOOL_NAMES
    ]
    tools.extend(ROOM_ACTION_TOOLS_SCHEMA)
    return tools


def _build_ai_advisor_reply(room: Dict[str, Any], user_text: str) -> str:
    """Bản tóm tắt dự phòng (fallback) nếu Ollama GPU tạm thời không kết nối được."""
    enriched = _enrich_single_room_locked(room)
    board = enriched["board"]
    room_cases = board.get("room_cases_enriched", [])
    if not room_cases:
        return (
            f"Phòng {room['id']} hiện chưa có hồ sơ Case nào. "
            "Hãy kéo ít nhất 1 Case vào Room để phân tích đường đi tấn công và tài sản bị ảnh hưởng."
        )

    case_lines = ", ".join(
        f"{c['id']} ({c['verdict']}/{c['severity']}, {c['alert_count']} alerts)"
        for c in room_cases[:5]
    )
    mitre_str = ", ".join(board.get("mitre_techniques") or []) or "Chưa ánh xạ"
    return (
        f"[Tóm tắt dự phòng {room['id']}] Yêu cầu: \"{user_text[:80]}\"\n"
        f"• Hồ sơ ({board['case_count']}): {case_lines}\n"
        f"• Thiết bị Compromised: {board['compromised_assets_count']} | Mục tiêu chặn/cô lập: {board['contained_targets_count']}\n"
        f"• Decisions hiệu lực: {board['open_decisions_count']} | Đã đảo ngược: {board['exceptions_reverted_count']}\n"
        f"• MITRE ATT&CK: {mitre_str}."
    )


def _build_room_llm_messages(
    room: Dict[str, Any],
    user_text: str,
    focus_case_id: str = "",
    exclude_msg_id: str = "",
) -> List[Dict[str, Any]]:
    """Chuẩn bị prompt ngữ cảnh thực tế của Contingency Room + lịch sử chat cho Qwen LLM trên GPU."""
    enriched = _enrich_single_room_locked(room)
    board = enriched["board"]
    all_cases = list(STATE.get("cases", []))
    all_assets = get_assets_with_case_counts()
    room_case_ids = set(room.get("case_ids") or [])

    cases_by_id = {str(c.get("id")): c for c in all_cases if isinstance(c, dict) and c.get("id")}
    in_room_cases_detail = []
    for cid in room.get("case_ids") or []:
        c = cases_by_id.get(str(cid))
        if not c:
            continue
        alerts_sample = [
            f"[{a.get('captured_at', '')}] Rule {a.get('rule_id', '?')} Lv.{a.get('level', 0)}: {a.get('title', '')} "
            f"({a.get('src_ip', 'unknown')} -> {a.get('victim_ip', 'unknown')})"
            for a in (c.get("incident_alerts") or [])[-5:]
        ]
        in_room_cases_detail.append({
            "id": c.get("id"),
            "domain": c.get("domain"),
            "status": c.get("status"),
            "verdict": c.get("verdict"),
            "severity": c.get("severity"),
            "src_ip": c.get("src_ip"),
            "victim_ips": c.get("victim_ips") or [],
            "agent_id": c.get("agent_id"),
            "alert_count": c.get("alert_count"),
            "mitre_tags": c.get("mitre_tags") or [],
            "ti_summary": c.get("ti_summary") or "",
            "summary_excerpt": str(c.get("summary") or "")[:300],
            "recent_alerts": alerts_sample,
        })

    other_open_cases = [
        {
            "id": c.get("id"),
            "domain": c.get("domain"),
            "verdict": c.get("verdict"),
            "severity": c.get("severity"),
            "src_ip": c.get("src_ip"),
            "victim_ips": c.get("victim_ips") or [],
            "title": c.get("title"),
        }
        for c in all_cases
        if isinstance(c, dict) and c.get("id") not in room_case_ids and c.get("status") != "CLOSED"
    ][:8]

    decisions_summary = [
        {
            "id": d.get("id"),
            "status": d.get("status"),
            "action_type": d.get("action_type"),
            "target": d.get("target"),
            "case_id": d.get("case_id"),
            "reason": d.get("reason"),
            "source": d.get("source"),
        }
        for d in (enriched.get("room_decisions") or [])[:15]
    ]

    assets_summary = [
        {
            "id": a.get("id"),
            "name": a.get("name"),
            "ip": a.get("ip"),
            "agent_id": a.get("agent_id"),
            "labels": a.get("labels") or [],
            "containment_status": a.get("containment_status"),
            "case_count": a.get("case_count"),
        }
        for a in all_assets[:15]
    ]

    board_brief = {
        "case_count": board.get("case_count", 0),
        "in_progress_cases_count": board.get("in_progress_cases_count", 0),
        "compromised_assets_count": board.get("compromised_assets_count", 0),
        "open_decisions_count": board.get("open_decisions_count", 0),
        "exceptions_reverted_count": board.get("exceptions_reverted_count", 0),
        "exploited_open_count": board.get("exploited_open_count", 0),
        "contained_targets_count": board.get("contained_targets_count", 0),
        "mitre_techniques": board.get("mitre_techniques") or [],
    }

    system_prompt = (
        f"Ban la Qwen AI SOC Tactical Commander dang truc chien trong Contingency Room {room.get('id')} "
        f"({room.get('name')}, giai doan: {room.get('stage')}, uu tien: {room.get('priority')}).\n"
        "NHIEM VU:\n"
        "1. Tra loi truc tiep bang TIENG VIET, chinh xac, ngan gon, dua HOAN TOAN vao du lieu that ben duoi hoac ket qua goi tool (TUYET DOI KHONG bia IP, hash, log hay ket qua VirusTotal).\n"
        "2. Co quyen goi cac tool dieu tra (tool_check_ip_reputation, tool_check_ip_context, tool_check_file_hash, tool_query_misp_ioc, tool_lookup_mitre_attack, tool_decode_base64) khi can kiem tra them IOC.\n"
        "3. Khi SOC Commander yeu cau thuc thi hanh dong ung pho (chan IP, co lap/mo co lap endpoint, gan co compromised asset, dong case), dao nguoc quyet dinh (DEC-xxxx), hoac keo them Case vao Room -> hay goi tool_room_execute_decision / tool_room_revert_decision / tool_room_attach_case tuong ung!\n"
        "4. Neu chi la hoi dap, phan tich hoac de xuat chien thuat -> tra loi ngay dua tren du lieu Room hien tai va neu ro cac buoc tiep theo.\n\n"
        f"THONG TIN BOARD ROOM HIEN TAI:\n{json.dumps(board_brief, ensure_ascii=False)}\n\n"
        f"CASES TRONG ROOM:\n{json.dumps(in_room_cases_detail, ensure_ascii=False)}\n\n"
        f"CASES DANG MO KHAC CHUA VAO ROOM:\n{json.dumps(other_open_cases, ensure_ascii=False)}\n\n"
        f"DECISIONS TRONG ROOM (CO THE DAO NGUOC):\n{json.dumps(decisions_summary, ensure_ascii=False)}\n\n"
        f"ASSET MANAGER:\n{json.dumps(assets_summary, ensure_ascii=False)}"
    )

    messages: List[Dict[str, Any]] = [{"role": "system", "content": system_prompt}]

    conv_history = [
        m for m in (room.get("messages") or [])
        if isinstance(m, dict)
        and m.get("id") != exclude_msg_id
        and m.get("role") in ("COMMANDER", "AI_AGENT")
    ][-8:]

    for m in conv_history:
        role_mapped = "user" if m.get("role") == "COMMANDER" else "assistant"
        prefix = f"[{m['case_id']}] " if (m.get("case_id") and role_mapped == "user") else ""
        messages.append({"role": role_mapped, "content": f"{prefix}{m.get('text', '')}"})

    user_prompt = f"[Focus Case: {focus_case_id}] {user_text}" if focus_case_id else user_text
    messages.append({"role": "user", "content": user_prompt})
    return messages


def _execute_room_ai_tool(room_id: str, fn_name: str, fn_args: Dict[str, Any], focus_case_id: str = "") -> str:
    """Thực thi tool call do Qwen phát sinh trong Contingency Room."""
    import tools.analysis_tools  # noqa: F401
    import tools.threat_intel_tools  # noqa: F401

    if fn_name == "tool_room_execute_decision":
        payload = {
            "action_type": fn_args.get("action_type", ""),
            "target": fn_args.get("target", ""),
            "reason": fn_args.get("reason") or "AI SOC Commander đề xuất trong Contingency Room",
            "case_id": fn_args.get("case_id") or focus_case_id,
        }
        _ok, _res, msg = create_and_execute_decision(room_id, payload)
        return msg

    if fn_name == "tool_room_revert_decision":
        _ok, _res, msg = revert_tactical_decision(
            fn_args.get("decision_id", ""),
            reason=fn_args.get("reason") or "AI SOC Advisor đảo ngược theo yêu cầu trong Room",
        )
        return msg

    if fn_name == "tool_room_attach_case":
        _ok, _res, msg = attach_case_to_room(room_id, fn_args.get("case_id", ""))
        return msg

    if fn_name == "tool_block_firewall_ip":
        _ok, _res, msg = create_and_execute_decision(room_id, {
            "action_type": "BLOCK_IP",
            "target": fn_args.get("ip", ""),
            "reason": fn_args.get("reason") or "AI SOC Advisor đề xuất chặn IP",
            "case_id": focus_case_id,
        })
        return msg

    if fn_name == "tool_wazuh_endpoint_response":
        raw_act = str(fn_args.get("action", "keep_isolated")).strip().lower()
        mapped_act = "RELEASE_ENDPOINT" if raw_act == "release_isolation" else "ISOLATE_ENDPOINT"
        _ok, _res, msg = create_and_execute_decision(room_id, {
            "action_type": mapped_act,
            "target": fn_args.get("agent_id", ""),
            "reason": fn_args.get("reason") or "AI SOC Advisor điều chỉnh cô lập Endpoint",
            "case_id": focus_case_id,
        })
        return msg

    if fn_name in TOOLS_MAP and fn_name in ROOM_INVESTIGATION_TOOL_NAMES:
        try:
            return str(TOOLS_MAP[fn_name](**fn_args))
        except Exception as e:
            return f"Lỗi thực thi tool {fn_name}: {e}"

    return f"Tool '{fn_name}' không được hỗ trợ trong Contingency Room."


def _run_room_ai_turn(
    room_id: str,
    user_text: str,
    focus_case_id: str = "",
    trigger_msg_id: str = "",
) -> None:
    """Chạy vòng suy luận thực tế trên GPU qua call_ollama() và đẩy câu trả lời vào chat Room."""
    try:
        with _CASE_LOCK:
            room = _get_room_by_id(room_id)
            if not room:
                return
            messages = _build_room_llm_messages(
                room,
                user_text=user_text,
                focus_case_id=focus_case_id,
                exclude_msg_id=trigger_msg_id,
            )
            tools_schema = _get_room_agent_tools_schema()

        log_event("THOUGHT", f"[{room_id}] 🧠 Qwen AI ({LLM_MODEL}) đang suy luận trên GPU cho: {user_text[:80]}")

        final_text = ""
        ollama_error = None
        for step in range(3):
            current_tools = tools_schema if step < 2 else None
            try:
                resp = call_ollama(messages, current_tools)
            except Exception as ex:
                ollama_error = str(ex)
                log_event("ERROR", f"[{room_id}] Lỗi kết nối Ollama GPU ({LLM_MODEL}): {ex}")
                break

            msg = resp.get("message", {}) if isinstance(resp, dict) else {}
            if not isinstance(msg, dict):
                msg = {}
            messages.append(msg)

            tool_calls = msg.get("tool_calls") or []
            if not tool_calls or step == 2:
                content_val = str(msg.get("content") or "").strip()
                thinking_val = str(msg.get("thinking") or "").strip()
                final_text = content_val or thinking_val

                if not content_val and (step > 0 or thinking_val):
                    followup_msgs = list(messages)
                    followup_msgs.append({
                        "role": "user",
                        "content": "Hãy tổng hợp ngắn gọn bằng tiếng Việt câu trả lời cuối cùng cho SOC Commander dựa trên thông tin trên.",
                    })
                    try:
                        s_resp = call_ollama(followup_msgs, None)
                        s_msg = s_resp.get("message", {}) if isinstance(s_resp, dict) else {}
                        s_content = str(s_msg.get("content") or "").strip()
                        s_thinking = str(s_msg.get("thinking") or "").strip()
                        if s_content:
                            final_text = s_content
                        elif s_thinking:
                            final_text = s_thinking
                    except Exception as ex2:
                        log_event("WARNING", f"[{room_id}] Lỗi tổng hợp trả lời Qwen: {ex2}")
                break

            for call in tool_calls:
                fn_info = call.get("function", {}) if isinstance(call, dict) else {}
                fn_name = str(fn_info.get("name") or "").strip()
                fn_args = fn_info.get("arguments")
                if isinstance(fn_args, str):
                    try:
                        fn_args = json.loads(fn_args)
                    except Exception:
                        fn_args = {}
                if not isinstance(fn_args, dict):
                    fn_args = {}

                log_event("THOUGHT", f"[{room_id}] Qwen Room gọi tool: {fn_name}({json.dumps(fn_args, ensure_ascii=False)})")
                result_str = _execute_room_ai_tool(room_id, fn_name, fn_args, focus_case_id=focus_case_id)
                log_event("TOOL", f"[{room_id}] Kết quả {fn_name}: {result_str[:140]}")
                messages.append({"role": "tool", "name": fn_name, "content": result_str})

        with _CASE_LOCK:
            room = _get_room_by_id(room_id)
            if not room:
                return
            if ollama_error:
                fallback_summary = _build_ai_advisor_reply(room, user_text)
                final_text = (
                    f"⚠️ Không kết nối được Qwen GPU Ollama ({ollama_error}).\n"
                    f"{fallback_summary}"
                )
            elif not final_text:
                final_text = _build_ai_advisor_reply(room, user_text)

            _append_room_message(
                room,
                sender=f"Qwen AI ({LLM_MODEL})",
                role="AI_AGENT",
                text=final_text,
                case_id=focus_case_id,
            )
            room["ai_thinking"] = False
            save_persistent_state()
    finally:
        with _CASE_LOCK:
            room_end = _get_room_by_id(room_id)
            if room_end and room_end.get("ai_thinking"):
                room_end["ai_thinking"] = False
                save_persistent_state()


def post_room_message(room_id: str, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], str]:
    """Gửi tin nhắn chat tác chiến trong Contingency Room và gọi Qwen AI Agent thật trên GPU."""
    if not isinstance(payload, dict):
        return False, {}, "Payload tin nhắn không hợp lệ."

    text = str(payload.get("text") or "").strip()
    if not text:
        return False, {}, "Nội dung tin nhắn trống."

    sender = str(payload.get("sender") or "").strip() or "SOC Commander"
    case_id = str(payload.get("case_id") or "").strip()
    if "ask_ai" in payload:
        ask_ai = bool(payload.get("ask_ai"))
    else:
        ask_ai = True
    if "@ai" in text.lower():
        ask_ai = True
    async_ai = bool(payload.get("async_ai", False))

    with _CASE_LOCK:
        ensure_default_rooms()
        room = _get_room_by_id(room_id)
        if not room:
            return False, {}, f"Không tìm thấy phòng tác chiến {room_id}."

        ts, _ = _now_and_str()
        user_msg = _append_room_message(
            room,
            sender=sender,
            role="COMMANDER",
            text=text,
            case_id=case_id,
            now_ts=ts,
        )
        if ask_ai:
            room["ai_thinking"] = True
        save_persistent_state()
        target_room_id = room["id"]
        trigger_msg_id = user_msg["id"]

    if ask_ai:
        if async_ai:
            threading.Thread(
                target=_run_room_ai_turn,
                args=(target_room_id, text, case_id, trigger_msg_id),
                daemon=True,
            ).start()
        else:
            _run_room_ai_turn(target_room_id, text, case_id, trigger_msg_id)

    with _CASE_LOCK:
        room_latest = _get_room_by_id(target_room_id)
        if not room_latest:
            return False, {}, f"Không tìm thấy phòng tác chiến {room_id}."
        return True, _enrich_single_room_locked(room_latest), "Đã gửi tin nhắn vào phòng tác chiến."


def _execute_decision_side_effect(
    action_type: str,
    target: str,
    reason: str,
    room: Optional[Dict[str, Any]] = None,
    case_id: str = "",
) -> Tuple[bool, str, str]:
    """Thực thi hành động ứng phó tương ứng với action_type; trả (ok, summary, auto_title)."""
    clean_target = str(target or "").strip()
    if not clean_target:
        return False, "Thiếu mục tiêu thực thi (target).", ""

    if action_type == "BLOCK_IP":
        from tools.firewall_tools import tool_block_firewall_ip

        res = str(tool_block_firewall_ip(ip=clean_target, reason=reason))
        if res.startswith("Từ chối chặn") or res.startswith("IP không hợp lệ") or res.startswith("Không thể kết nối") or res.startswith("Lỗi pfSense"):
            return False, res, ""
        blocked_list = STATE["stats"].setdefault("blocked_ips", [])
        if clean_target not in blocked_list:
            blocked_list.append(clean_target)
        STATE.setdefault("pfsense_block_details", {})[clean_target] = reason[:80]
        if case_id:
            c_obj = get_case_by_id(case_id)
            if c_obj:
                act_str = f"pfSense Block IP {clean_target}"
                if act_str not in c_obj.setdefault("actions_taken", []):
                    c_obj["actions_taken"].append(act_str)
        return True, res, f"Chặn IP {clean_target} trên pfSense Firewall"

    if action_type == "ISOLATE_ENDPOINT":
        from tools.wazuh_tools import tool_wazuh_endpoint_response

        res = str(tool_wazuh_endpoint_response(agent_id=clean_target, action="keep_isolated", reason=reason))
        if res.startswith("Từ chối Wazuh AR"):
            return False, res, ""
        if case_id:
            c_obj = get_case_by_id(case_id)
            if c_obj:
                act_str = f"Wazuh AR: Cô lập mạng Agent {clean_target}"
                if act_str not in c_obj.setdefault("actions_taken", []):
                    c_obj["actions_taken"].append(act_str)
        return True, res, f"Cô lập mạng Endpoint Agent {clean_target}"

    if action_type == "RELEASE_ENDPOINT":
        from tools.wazuh_tools import tool_wazuh_endpoint_response

        res = str(tool_wazuh_endpoint_response(agent_id=clean_target, action="release_isolation", reason=reason))
        if res.startswith("Từ chối Wazuh AR"):
            return False, res, ""
        return True, res, f"Mở cô lập mạng Endpoint Agent {clean_target}"

    if action_type == "FLAG_ASSET":
        if not room:
            return False, "FLAG_ASSET yêu cầu gắn với một Room cụ thể.", ""
        flags = room.setdefault("flagged_asset_ids", [])
        if clean_target not in flags:
            flags.append(clean_target)
        return True, f"Đã gắn cờ Compromised cho thiết bị {clean_target} trong {room['id']}.", f"Đánh dấu Compromised thiết bị {clean_target}"

    if action_type == "CLOSE_CASE":
        ok_close, _c, msg_close = update_case_status(clean_target, "CLOSED", reason=reason)
        if not ok_close:
            return False, msg_close, ""
        return True, msg_close, f"Đóng hồ sơ {clean_target}"

    return False, f"Loại quyết định không hợp lệ: {action_type}", ""


def _revert_decision_side_effect(
    decision: Dict[str, Any],
    reason: str,
    room: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """Thực thi hành động hoàn tác (Rollback) tương ứng khi bấm nút Đảo ngược."""
    action_type = str(decision.get("action_type") or "").upper()
    target = str(decision.get("target") or "").strip()
    case_id = str(decision.get("case_id") or "").strip()

    if action_type == "BLOCK_IP":
        from tools.firewall_tools import tool_unblock_firewall_ip

        res = str(tool_unblock_firewall_ip(target))
        blocked_list = STATE["stats"].setdefault("blocked_ips", [])
        if target in blocked_list:
            blocked_list.remove(target)
        STATE.get("pfsense_block_details", {}).pop(target, None)
        if case_id:
            c_obj = get_case_by_id(case_id)
            if c_obj:
                actions = c_obj.setdefault("actions_taken", [])
                c_obj["actions_taken"] = [a for a in actions if f"pfSense Block IP {target}" not in str(a)]
                c_obj["actions_taken"].append(f"Reverted Block IP {target}")
        return True, res or f"Đã gỡ chặn IP {target} khỏi SOC_BLOCKLIST"

    if action_type == "ISOLATE_ENDPOINT":
        from tools.wazuh_tools import tool_wazuh_endpoint_response

        res = str(
            tool_wazuh_endpoint_response(
                agent_id=target,
                action="release_isolation",
                reason=reason or f"Đảo ngược quyết định {decision.get('id')}",
            )
        )
        return True, res

    if action_type == "RELEASE_ENDPOINT":
        from tools.wazuh_tools import tool_wazuh_endpoint_response

        res = str(
            tool_wazuh_endpoint_response(
                agent_id=target,
                action="keep_isolated",
                reason=reason or f"Đảo ngược mở cô lập {decision.get('id')}",
            )
        )
        return True, res

    if action_type == "FLAG_ASSET":
        search_rooms = [room] if room else list(STATE.get("contingency_rooms", []))
        for r in search_rooms:
            if isinstance(r, dict):
                flags = r.get("flagged_asset_ids") or []
                if target in flags:
                    flags.remove(target)
        return True, f"Đã gỡ cờ Compromised khỏi thiết bị {target}."

    if action_type == "CLOSE_CASE":
        ok_open, _c, msg_open = update_case_status(
            target,
            "OPEN",
            reason=reason or f"Mở lại do đảo ngược {decision.get('id')}",
        )
        return ok_open, msg_open

    return False, f"Không hỗ trợ đảo ngược loại hành động '{action_type}'."


def create_and_execute_decision(room_id: str, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], str]:
    """Tạo và thực thi ngay một Decision có nút đảo ngược trong Contingency Room."""
    if not isinstance(payload, dict):
        return False, {}, "Dữ liệu quyết định không hợp lệ."

    action_type = str(payload.get("action_type") or "").strip().upper()
    if action_type not in VALID_DECISION_TYPES:
        return False, {}, f"Loại quyết định '{action_type}' không hợp lệ. Chỉ hỗ trợ: {', '.join(sorted(VALID_DECISION_TYPES))}."

    target = str(payload.get("target") or "").strip()
    case_id = str(payload.get("case_id") or "").strip()
    reason = str(payload.get("reason") or "").strip() or "Quyết định tác chiến từ SOC Commander"
    custom_title = str(payload.get("title") or "").strip()

    with _CASE_LOCK:
        ensure_default_rooms()
        room = _get_room_by_id(room_id)
        if not room:
            return False, {}, f"Không tìm thấy phòng tác chiến {room_id}."

        if not target and action_type == "CLOSE_CASE" and case_id:
            target = case_id

        ok_exec, exec_msg, auto_title = _execute_decision_side_effect(
            action_type=action_type,
            target=target,
            reason=reason,
            room=room,
            case_id=case_id,
        )
        if not ok_exec:
            return False, {}, exec_msg

        decisions = STATE.setdefault("tactical_decisions", [])
        ts, time_str = _now_and_str()
        dec_id = _next_sequence_id("DEC", decisions)
        dec = {
            "id": dec_id,
            "room_id": room["id"],
            "case_id": case_id,
            "action_type": action_type,
            "target": target,
            "title": custom_title or auto_title,
            "reason": reason,
            "source": "COMMANDER",
            "status": "ACTIVE",
            "reversible": True,
            "execution_result": exec_msg,
            "revert_result": "",
            "revert_reason": "",
            "created_at": time_str,
            "created_at_ts": ts,
            "reverted_at": "",
            "reverted_at_ts": None,
        }
        decisions.insert(0, dec)

        if case_id and case_id not in room.setdefault("case_ids", []) and get_case_by_id(case_id):
            room["case_ids"].append(case_id)

        _append_room_message(
            room,
            sender="SOC System",
            role="SYSTEM",
            text=f"⚖️ [DECISION] Đã thực thi {dec_id}: {dec['title']} (Mục tiêu: {target}) — Có thể đảo ngược.",
            case_id=case_id,
            decision_id=dec_id,
            now_ts=ts,
        )
        save_persistent_state()
        log_event("ACTION", f"⚖️ [{room['id']}] Thực thi quyết định {dec_id}: {dec['title']}")
        return True, {"decision": dec, "room": _enrich_single_room_locked(room)}, f"Đã thực thi quyết định {dec_id}."


def revert_tactical_decision(decision_id: str, reason: str = "") -> Tuple[bool, Dict[str, Any], str]:
    """Đảo ngược (Rollback) một Decision đang ACTIVE về trạng thái ban đầu."""
    clean_did = str(decision_id or "").strip()
    clean_reason = str(reason or "").strip() or "Đảo ngược quyết định từ Contingency Room"

    with _CASE_LOCK:
        ensure_default_rooms()
        dec = _get_decision_by_id(clean_did)
        if not dec:
            return False, {}, f"Không tìm thấy quyết định {clean_did}."
        if dec.get("status") == "REVERTED":
            return False, {}, f"Quyết định {clean_did} đã được đảo ngược trước đó."

        room = _get_room_by_id(dec.get("room_id", "")) or _find_room_for_case(dec.get("case_id", ""))
        ok_rev, rev_msg = _revert_decision_side_effect(dec, reason=clean_reason, room=room)
        if not ok_rev:
            return False, {}, rev_msg

        ts, time_str = _now_and_str()
        dec["status"] = "REVERTED"
        dec["revert_result"] = rev_msg
        dec["revert_reason"] = clean_reason
        dec["reverted_at"] = time_str
        dec["reverted_at_ts"] = ts

        if room:
            _append_room_message(
                room,
                sender="SOC System",
                role="SYSTEM",
                text=f"↩️ [REVERTED] Đã đảo ngược quyết định {clean_did}: {dec.get('title', '')} — Kết quả: {rev_msg}",
                case_id=dec.get("case_id", ""),
                decision_id=clean_did,
                now_ts=ts,
            )

        save_persistent_state()
        log_event("ACTION", f"↩️ Đã đảo ngược quyết định {clean_did} ({dec.get('action_type')} -> {dec.get('target')})")
        room_data = _enrich_single_room_locked(room) if room else None
        return True, {"decision": dict(dec), "room": room_data}, f"Đã đảo ngược quyết định {clean_did}: {rev_msg}"


def reapply_tactical_decision(decision_id: str, reason: str = "") -> Tuple[bool, Dict[str, Any], str]:
    """Thực thi lại một Decision đang ở trạng thái REVERTED."""
    clean_did = str(decision_id or "").strip()
    with _CASE_LOCK:
        ensure_default_rooms()
        dec = _get_decision_by_id(clean_did)
        if not dec:
            return False, {}, f"Không tìm thấy quyết định {clean_did}."
        if dec.get("status") == "ACTIVE":
            return False, {}, f"Quyết định {clean_did} đang ở trạng thái ACTIVE."

        room = _get_room_by_id(dec.get("room_id", "")) or _find_room_for_case(dec.get("case_id", ""))
        exec_reason = str(reason or "").strip() or dec.get("reason") or f"Thực thi lại {clean_did}"
        ok_exec, exec_msg, _ = _execute_decision_side_effect(
            action_type=str(dec.get("action_type") or ""),
            target=str(dec.get("target") or ""),
            reason=exec_reason,
            room=room,
            case_id=str(dec.get("case_id") or ""),
        )
        if not ok_exec:
            return False, {}, exec_msg

        ts, time_str = _now_and_str()
        dec["status"] = "ACTIVE"
        dec["execution_result"] = exec_msg
        dec["created_at"] = time_str
        dec["created_at_ts"] = ts
        dec["reverted_at"] = ""
        dec["reverted_at_ts"] = None

        if room:
            _append_room_message(
                room,
                sender="SOC System",
                role="SYSTEM",
                text=f"🔄 [REAPPLIED] Đã thực thi lại quyết định {clean_did}: {dec.get('title', '')}.",
                case_id=dec.get("case_id", ""),
                decision_id=clean_did,
                now_ts=ts,
            )

        save_persistent_state()
        log_event("ACTION", f"🔄 Đã thực thi lại quyết định {clean_did}")
        room_data = _enrich_single_room_locked(room) if room else None
        return True, {"decision": dict(dec), "room": room_data}, f"Đã thực thi lại quyết định {clean_did}."
