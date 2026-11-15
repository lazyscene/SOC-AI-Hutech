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
    is_ip_matching_agent,
    resolve_agent_ips,
)
from core.asset_manager import (
    ensure_default_assets,
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


DEFAULT_CONTROL_TTL_SECONDS = 3600
MAX_CONTROL_AUDIT_LOGS = 500
_ISOLATED_STATUSES = {"ISOLATED (LOCKED)", "TEMP_ISOLATED", "ISOLATED"}


def _is_isolated_status(status: Any) -> bool:
    return str(status or "").strip().upper() in _ISOLATED_STATUSES


def _make_control_key(action_type: str, target: str) -> str:
    act = str(action_type or "").strip().upper()
    tgt = str(target or "").strip()
    if act in ("ISOLATE_ENDPOINT", "RELEASE_ENDPOINT"):
        clean_aid = tgt.replace("agent:", "").strip()
        return f"ENDPOINT_ISOLATION:{clean_aid}"
    if act == "BLOCK_IP":
        return f"FIREWALL_BLOCK:{tgt}"
    if act == "FLAG_ASSET":
        return f"ASSET_FLAG:{tgt}"
    if act == "CLOSE_CASE":
        return f"CASE_STATUS:{tgt}"
    return f"{act}:{tgt}"


def _default_ttl_for_action(action_type: str) -> int:
    act = str(action_type or "").strip().upper()
    if act in ("BLOCK_IP", "ISOLATE_ENDPOINT", "RELEASE_ENDPOINT"):
        return DEFAULT_CONTROL_TTL_SECONDS
    return 0


def _normalize_ttl_seconds(raw_ttl: Any, action_type: str = "") -> int:
    if raw_ttl is None or str(raw_ttl).strip() == "":
        return _default_ttl_for_action(action_type)
    try:
        val = int(raw_ttl)
        return val if val >= 0 else _default_ttl_for_action(action_type)
    except (TypeError, ValueError):
        return _default_ttl_for_action(action_type)


def _compute_expiry_fields(base_ts: float, ttl_seconds: int) -> Tuple[Optional[float], Optional[str]]:
    if ttl_seconds > 0:
        exp_ts = float(base_ts) + float(ttl_seconds)
        return exp_ts, format_vn_time(exp_ts)
    return None, None


def _get_all_room_case_map_locked() -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for r in STATE.get("contingency_rooms", []):
        if not isinstance(r, dict):
            continue
        rid = str(r.get("id") or "")
        for cid in (r.get("case_ids") or []):
            s_cid = str(cid or "").strip()
            if s_cid and s_cid not in mapping:
                mapping[s_cid] = rid
    return mapping


def _find_matching_cases_for_control(action_type: str, target: str) -> List[Dict[str, Any]]:
    """Tìm tất cả Case có liên quan đến target của một Active Control."""
    act = str(action_type or "").strip().upper()
    tgt = str(target or "").strip()
    if not tgt:
        return []

    cases = [c for c in STATE.get("cases", []) if isinstance(c, dict) and c.get("id")]
    if act == "CLOSE_CASE":
        return [c for c in cases if str(c.get("id")) == tgt]

    nat_map = get_nat_ip_map()
    assets = ensure_default_assets()
    matched: List[Dict[str, Any]] = []

    if act in ("ISOLATE_ENDPOINT", "RELEASE_ENDPOINT"):
        clean_aid = tgt.replace("agent:", "").strip()
        agent_ips: Set[str] = set(str(ip).strip() for ip in (resolve_agent_ips(clean_aid) or []) if str(ip).strip())
        for a in assets:
            if isinstance(a, dict) and str(a.get("agent_id") or "").strip() == clean_aid:
                for raw_ip in [a.get("ip")] + list(a.get("extra_ips") or []):
                    s_ip = str(raw_ip or "").strip()
                    if s_ip:
                        agent_ips.add(s_ip)

        for c in cases:
            if str(c.get("agent_id") or "").strip() == clean_aid:
                matched.append(c)
                continue
            cand_ips = [str(x).strip() for x in ([c.get("src_ip")] + list(c.get("victim_ips") or [])) if str(x or "").strip() and str(x).lower() not in ("unknown", "none", "n/a")]
            if any(
                cip in agent_ips
                or is_ip_matching_agent(cip, clean_aid, c)
                or any(mapped in agent_ips for mapped in nat_map.get(cip, []))
                for cip in cand_ips
            ):
                matched.append(c)
        return matched

    if act == "BLOCK_IP":
        for c in cases:
            src_ip = str(c.get("src_ip") or "").strip()
            vips = [str(v).strip() for v in (c.get("victim_ips") or []) if str(v).strip()]
            acts = " ".join(str(x) for x in (c.get("actions_taken") or []))
            if src_ip == tgt or tgt in vips or f"pfSense Block IP {tgt}" in acts:
                matched.append(c)
        return matched

    if act == "FLAG_ASSET":
        matched_assets = [
            a for a in assets
            if isinstance(a, dict)
            and tgt in (str(a.get("id") or "").strip(), str(a.get("ip") or "").strip(), str(a.get("agent_id") or "").strip())
        ]
        for c in cases:
            if matched_assets:
                if any(_does_case_match_asset(c, ma, nat_map) for ma in matched_assets):
                    matched.append(c)
            elif tgt in [str(c.get("src_ip") or ""), str(c.get("agent_id") or "")] or tgt in (c.get("victim_ips") or []):
                matched.append(c)
        return matched

    return matched


def _refresh_decision_control_cases_locked(dec: Dict[str, Any], extra_case_ids: Optional[List[str]] = None) -> None:
    """Cập nhật canonical control_key, source_case_id, control_cases và control_cases_detail cho Decision."""
    act = str(dec.get("action_type") or "").strip().upper()
    target = str(dec.get("target") or "").strip()
    dec["control_key"] = _make_control_key(act, target)

    source_cid = str(dec.get("source_case_id") or dec.get("case_id") or "").strip()
    if source_cid:
        dec["source_case_id"] = source_cid
        if not dec.get("case_id"):
            dec["case_id"] = source_cid
    else:
        dec["source_case_id"] = ""

    is_manual_cmd = str(dec.get("source") or "").strip().upper() == "COMMANDER"
    if not source_cid and not is_manual_cmd:
        dec["is_orphan"] = True
    elif source_cid:
        dec["is_orphan"] = False
    else:
        dec.setdefault("is_orphan", False)

    room_case_map = _get_all_room_case_map_locked()
    ordered_cids: List[str] = []

    def _add_cid(val: Any) -> None:
        s_cid = str(val or "").strip()
        if s_cid and s_cid not in ordered_cids:
            ordered_cids.append(s_cid)

    _add_cid(source_cid)
    _add_cid(dec.get("case_id"))
    for xc in (extra_case_ids or []):
        _add_cid(xc)
    for existing_cid in (dec.get("control_cases") or []):
        _add_cid(existing_cid)

    if dec.get("status", "ACTIVE") == "ACTIVE":
        for mc in _find_matching_cases_for_control(act, target):
            mcid = str(mc.get("id") or "").strip()
            if not mcid:
                continue
            if mcid == source_cid or mc.get("status") != "CLOSED" or mcid in room_case_map:
                _add_cid(mcid)

    dec["control_cases"] = ordered_cids

    detail: List[Dict[str, Any]] = []
    for cid in ordered_cids:
        cobj = get_case_by_id(cid)
        if not cobj:
            detail.append({
                "case_id": cid,
                "title": cid,
                "domain": "",
                "status": "UNKNOWN",
                "verdict": "UNKNOWN",
                "role": "SOURCE" if cid == source_cid else "REFERENCING",
            })
        else:
            detail.append({
                "case_id": cid,
                "title": cobj.get("title", ""),
                "domain": cobj.get("domain", ""),
                "status": cobj.get("status", "OPEN"),
                "verdict": cobj.get("verdict", "UNKNOWN"),
                "role": "SOURCE" if cid == source_cid else "REFERENCING",
            })
    dec["control_cases_detail"] = detail

    if source_cid:
        ref_only = [c for c in ordered_cids if c != source_cid]
        dec["source_label"] = (
            f"Khởi phát từ {source_cid}"
            + (f" (+{len(ref_only)} case liên quan: {', '.join(ref_only[:3])})" if ref_only else "")
        )
    elif is_manual_cmd:
        dec["source_label"] = f"Lệnh trực tiếp từ SOC Commander ({dec.get('room_id') or 'Room'})"
    else:
        suffix = f" — liên quan: {', '.join(ordered_cids[:3])}" if ordered_cids else ""
        dec["source_label"] = f"Nguồn không xác định (Orphan Control — đồng bộ từ hệ thống phòng thủ{suffix})"


def _record_control_audit(
    audit_action: str,
    decision: Dict[str, Any],
    actor: str,
    reason: str,
    target_case_ids: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
    now_ts: Optional[float] = None,
) -> Dict[str, Any]:
    """Ghi Audit Log tập trung cho Active Control và ghi vết vào timeline mọi Case liên quan."""
    ts, time_str = _now_and_str(now_ts)
    dec_id = str(decision.get("id") or "")
    ckey = str(decision.get("control_key") or _make_control_key(decision.get("action_type", ""), decision.get("target", "")))

    cids: List[str] = []
    raw_list = target_case_ids if target_case_ids is not None else (decision.get("control_cases") or [])
    for cid in raw_list:
        s_cid = str(cid or "").strip()
        if s_cid and s_cid not in cids:
            cids.append(s_cid)
    for fb in (decision.get("source_case_id"), decision.get("case_id")):
        s_cid = str(fb or "").strip()
        if s_cid and s_cid not in cids:
            cids.append(s_cid)

    entry = {
        "id": _next_sequence_id("AUD", STATE.get("control_audit_logs", [])),
        "ts": ts,
        "time": time_str,
        "action": audit_action,
        "decision_id": dec_id,
        "control_key": ckey,
        "action_type": decision.get("action_type", ""),
        "target": decision.get("target", ""),
        "actor": actor or "system",
        "reason": reason or "",
        "case_ids": list(cids),
        "extra": dict(extra or {}),
    }
    audit_logs = STATE.setdefault("control_audit_logs", [])
    audit_logs.insert(0, entry)
    if len(audit_logs) > MAX_CONTROL_AUDIT_LOGS:
        del audit_logs[MAX_CONTROL_AUDIT_LOGS:]

    trail = decision.setdefault("audit_trail", [])
    trail.append({
        "time": time_str,
        "ts": ts,
        "action": audit_action,
        "actor": actor or "system",
        "reason": reason or "",
        "case_ids": list(cids),
    })
    if len(trail) > 30:
        del trail[:-30]

    for cid in cids:
        cobj = get_case_by_id(cid)
        if not cobj:
            continue
        cevents = cobj.setdefault("control_events", [])
        cevents.append({
            "time": time_str,
            "ts": ts,
            "action": audit_action,
            "decision_id": dec_id,
            "control_key": ckey,
            "action_type": decision.get("action_type", ""),
            "target": decision.get("target", ""),
            "actor": actor or "system",
            "reason": reason or "",
        })
        if len(cevents) > 50:
            del cevents[:-50]
        esc_line = (
            f"[{time_str}] CONTROL {audit_action}: {decision.get('action_type')} "
            f"{decision.get('target')} ({dec_id}) bởi {actor or 'system'} — {reason}"
        )
        esc_list = cobj.setdefault("escalation_reasons", [])
        if not esc_list or esc_list[-1] != esc_line:
            esc_list.append(esc_line)
    return entry


def _infer_source_case_for_containment_locked(agent_id: str, ep_rec: Dict[str, Any]) -> str:
    clean_aid = str(agent_id or "").strip()
    explicit_src = str(ep_rec.get("source_case_id") or "").strip()
    if explicit_src:
        return explicit_src
    for c in STATE.get("cases", []):
        if not isinstance(c, dict):
            continue
        if str(c.get("agent_id") or "").strip() != clean_aid:
            continue
        acts = " ".join(str(a) for a in (c.get("actions_taken") or []))
        if not acts:
            continue
        lower_acts = acts.lower()
        if "mở cô lập" in lower_acts or "unisolated" in lower_acts:
            continue
        if "giữ khóa cô lập" in lower_acts or "isolated (locked)" in lower_acts or "cô lập tạm thời" in lower_acts or "phase 1" in lower_acts:
            return str(c.get("id") or "")
    return ""


def _infer_source_case_for_blocked_ip_locked(ip_target: str) -> str:
    clean_ip = str(ip_target or "").strip()
    for c in STATE.get("cases", []):
        if not isinstance(c, dict):
            continue
        acts = [str(a) for a in (c.get("actions_taken") or [])]
        if any(f"pfSense Block IP {clean_ip}" in a for a in acts):
            return str(c.get("id") or "")
    for c in STATE.get("cases", []):
        if not isinstance(c, dict):
            continue
        if str(c.get("src_ip") or "").strip() == clean_ip and c.get("status") != "CLOSED":
            return str(c.get("id") or "")
    return ""


def _infer_room_for_decision_locked(dec: Dict[str, Any]) -> str:
    existing_rid = str(dec.get("room_id") or "").strip()
    if existing_rid and _get_room_by_id(existing_rid):
        return existing_rid
    room_case_map = _get_all_room_case_map_locked()
    for cid in [dec.get("source_case_id"), dec.get("case_id")] + list(dec.get("control_cases") or []):
        s_cid = str(cid or "").strip()
        if s_cid and s_cid in room_case_map:
            return room_case_map[s_cid]
    return ""


def _resolve_decision_by_ref(ref: str) -> Optional[Dict[str, Any]]:
    """Tìm Decision theo ID (DEC-xxxx), canonical control_key, hoặc target (IP / agent_id)."""
    clean_ref = str(ref or "").strip()
    if not clean_ref:
        return None
    direct = _get_decision_by_id(clean_ref)
    if direct:
        return direct
    upper_ref = clean_ref.upper()
    decisions = STATE.get("tactical_decisions", [])
    for status_pref in ("ACTIVE", None):
        for d in decisions:
            if not isinstance(d, dict):
                continue
            if status_pref and d.get("status") != status_pref:
                continue
            if str(d.get("control_key") or "").upper() == upper_ref:
                return d
    for d in decisions:
        if isinstance(d, dict) and d.get("status") == "ACTIVE":
            if str(d.get("target") or "").strip() == clean_ref:
                return d
    return None


def _sync_single_case_decisions_locked(case: Dict[str, Any], room_id: str = "") -> List[Dict[str, Any]]:
    """Đồng bộ các hành động SOAR của 1 Case vào bảng Active Controls canonical theo control_key."""
    if not isinstance(case, dict) or not case.get("id"):
        return []

    case_id = str(case["id"])
    decisions = STATE.setdefault("tactical_decisions", [])
    attached_room = room_id or (_find_room_for_case(case_id) or {}).get("id", "")
    created_or_matched: List[Dict[str, Any]] = []
    ts, time_str = _now_and_str()

    blocked_ips = set(str(ip).strip() for ip in (STATE["stats"].get("blocked_ips") or []) if str(ip).strip())
    actions_taken = [str(a) for a in (case.get("actions_taken") or [])]

    # 1. Đồng bộ hành động chặn IP trên pfSense (chỉ khi IP đang thực sự nằm trong blocklist)
    ip_targets: List[str] = []
    case_src = str(case.get("src_ip") or "").strip()
    if case_src and case_src in blocked_ips:
        ip_targets.append(case_src)
    for act in actions_taken:
        m = re.search(r"pfSense Block IP\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", act)
        if m and m.group(1) in blocked_ips and m.group(1) not in ip_targets:
            ip_targets.append(m.group(1))

    for ip_target in ip_targets:
        ckey = _make_control_key("BLOCK_IP", ip_target)
        existing = next(
            (
                d for d in decisions
                if isinstance(d, dict)
                and d.get("status") == "ACTIVE"
                and (d.get("control_key") or _make_control_key(d.get("action_type", ""), d.get("target", ""))) == ckey
            ),
            None,
        )
        if existing:
            if not existing.get("source_case_id") and any(f"pfSense Block IP {ip_target}" in a for a in actions_taken):
                existing["source_case_id"] = case_id
                existing["case_id"] = existing.get("case_id") or case_id
                existing["is_orphan"] = False
            if attached_room and not existing.get("room_id"):
                existing["room_id"] = attached_room
            _refresh_decision_control_cases_locked(existing, extra_case_ids=[case_id])
            created_or_matched.append(existing)
        else:
            dec_id = _next_sequence_id("DEC", decisions)
            ttl = _default_ttl_for_action("BLOCK_IP")
            c_ts = float(case.get("last_alert_ts") or ts)
            exp_ts, exp_str = _compute_expiry_fields(ts, ttl)
            dec = {
                "id": dec_id,
                "control_key": ckey,
                "room_id": attached_room,
                "case_id": case_id,
                "source_case_id": case_id,
                "control_cases": [case_id],
                "is_orphan": False,
                "action_type": "BLOCK_IP",
                "target": ip_target,
                "title": f"Chặn IP {ip_target} trên pfSense Firewall",
                "reason": STATE.get("pfsense_block_details", {}).get(ip_target) or f"SOAR tự động chặn IP từ {case_id}",
                "source": "AI_SOAR",
                "status": "ACTIVE",
                "reversible": True,
                "ttl_seconds": ttl,
                "expires_at_ts": exp_ts,
                "expires_at": exp_str,
                "pending_revert_proposal": None,
                "drift_status": "SYNCED",
                "execution_result": f"Đã thêm {ip_target} vào Alias SOC_BLOCKLIST",
                "revert_result": "",
                "revert_reason": "",
                "created_at": case.get("updated_at") or time_str,
                "created_at_ts": c_ts,
                "reverted_at": "",
                "reverted_at_ts": None,
            }
            _refresh_decision_control_cases_locked(dec)
            decisions.insert(0, dec)
            _record_control_audit("CONTROL_CREATED", dec, "AI_SOAR", dec["reason"], target_case_ids=[case_id], now_ts=ts)
            created_or_matched.append(dec)

    # 2. Đồng bộ hành động cô lập Endpoint (Wazuh AR) theo trạng thái thực tế
    ep_containment = STATE.get("endpoint_containment", {})
    case_agent = str(case.get("agent_id") or "").strip()
    ep_rec = ep_containment.get(case_agent) if case_agent and isinstance(ep_containment, dict) else None
    iso_status = str((ep_rec or {}).get("isolation_status") or "").strip()
    has_ep_iso_action = any(
        ("giữ khóa cô lập" in a.lower() or "isolated (locked)" in a.lower() or "cô lập tạm thời" in a.lower())
        and "mở cô lập" not in a.lower()
        for a in actions_taken
    )
    if case_agent and case_agent.lower() not in ("000", "unknown", "none") and _is_isolated_status(iso_status):
        ckey = _make_control_key("ISOLATE_ENDPOINT", case_agent)
        existing_ep = next(
            (
                d for d in decisions
                if isinstance(d, dict)
                and d.get("status") == "ACTIVE"
                and (d.get("control_key") or _make_control_key(d.get("action_type", ""), d.get("target", ""))) == ckey
            ),
            None,
        )
        ep_src = str((ep_rec or {}).get("source_case_id") or "").strip()
        is_case_owner = (ep_src == case_id) or (not ep_src and has_ep_iso_action)
        if existing_ep:
            if existing_ep.get("action_type") != "ISOLATE_ENDPOINT":
                existing_ep["action_type"] = "ISOLATE_ENDPOINT"
                existing_ep["title"] = f"Cô lập mạng Endpoint Agent {case_agent} qua Wazuh AR"
                existing_ep["source_case_id"] = case_id if is_case_owner else ep_src
                existing_ep["case_id"] = existing_ep["source_case_id"]
                existing_ep["is_orphan"] = not bool(existing_ep["source_case_id"])
            elif is_case_owner and not existing_ep.get("source_case_id"):
                existing_ep["source_case_id"] = case_id
                existing_ep["case_id"] = case_id
                existing_ep["is_orphan"] = False
            if attached_room and not existing_ep.get("room_id"):
                existing_ep["room_id"] = attached_room
            _refresh_decision_control_cases_locked(existing_ep, extra_case_ids=[case_id])
            created_or_matched.append(existing_ep)
        elif is_case_owner:
            dec_id = _next_sequence_id("DEC", decisions)
            ttl = _default_ttl_for_action("ISOLATE_ENDPOINT")
            c_ts = float((ep_rec or {}).get("updated_at_ts") or case.get("last_alert_ts") or ts)
            exp_ts, exp_str = _compute_expiry_fields(ts, ttl)
            dec = {
                "id": dec_id,
                "control_key": ckey,
                "room_id": attached_room,
                "case_id": case_id,
                "source_case_id": case_id,
                "control_cases": [case_id],
                "is_orphan": False,
                "action_type": "ISOLATE_ENDPOINT",
                "target": case_agent,
                "title": f"Cô lập mạng Endpoint Agent {case_agent} qua Wazuh AR",
                "reason": (ep_rec or {}).get("reason") or f"Wazuh Active Response cho {case_id}",
                "source": "AI_SOAR",
                "status": "ACTIVE",
                "reversible": True,
                "ttl_seconds": ttl,
                "expires_at_ts": exp_ts,
                "expires_at": exp_str,
                "pending_revert_proposal": None,
                "drift_status": "SYNCED",
                "execution_result": f"Trạng thái hiện tại: {iso_status or 'ISOLATED (LOCKED)'}",
                "revert_result": "",
                "revert_reason": "",
                "created_at": (ep_rec or {}).get("updated_at") or case.get("updated_at") or time_str,
                "created_at_ts": c_ts,
                "reverted_at": "",
                "reverted_at_ts": None,
            }
            _refresh_decision_control_cases_locked(dec)
            decisions.insert(0, dec)
            _record_control_audit("CONTROL_CREATED", dec, "AI_SOAR", dec["reason"], target_case_ids=[case_id], now_ts=ts)
            created_or_matched.append(dec)

    return created_or_matched


def reconcile_active_controls_locked(now_ts: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    Single Source of Truth Reconciliation (chạy dưới _CASE_LOCK):
    1. Chống trùng Decision theo canonical control_key (dọn bản ghi trùng cũ như DEC-0002..0006).
    2. Đối chiếu thực tế endpoint_containment (Wazuh) & blocked_ips (pfSense):
       - Nếu đang khóa/chặn mà chưa có Decision ACTIVE -> tạo canonical Active Control (gắn source_case_id hoặc Orphan).
       - Nếu đang có Decision ACTIVE nhưng hạ tầng đã mở khóa/gỡ chặn -> drift reconciliation chuyển REVERTED.
    3. Kiểm tra TTL auto-expiration -> tự động đảo ngược nếu hết hạn.
    4. Cập nhật control_cases đa Case & auto-bind room_id khi có Case thuộc Room.
    """
    ts, time_str = _now_and_str(now_ts)
    decisions = STATE.setdefault("tactical_decisions", [])
    ep_containment = STATE.setdefault("endpoint_containment", {})
    blocked_ips_set = {
        str(ip).strip()
        for ip in (STATE.setdefault("stats", {}).get("blocked_ips") or [])
        if str(ip).strip()
    }

    # 1. Deduplicate ACTIVE decisions theo control_key
    active_by_key: Dict[str, List[Dict[str, Any]]] = {}
    for d in decisions:
        if not isinstance(d, dict):
            continue
        act = str(d.get("action_type") or "").upper()
        tgt = str(d.get("target") or "")
        d["control_key"] = d.get("control_key") or _make_control_key(act, tgt)
        if d.get("status") == "ACTIVE":
            active_by_key.setdefault(d["control_key"], []).append(d)

    drop_ids: Set[int] = set()
    for ckey, group in active_by_key.items():
        if len(group) <= 1:
            continue
        if ckey.startswith("ENDPOINT_ISOLATION:"):
            clean_aid = ckey.split(":", 1)[1]
            live_iso = _is_isolated_status((ep_containment.get(clean_aid) or {}).get("isolation_status"))
            group.sort(
                key=lambda d: (
                    1 if (live_iso and d.get("action_type") == "ISOLATE_ENDPOINT") else 0,
                    1 if (not live_iso and d.get("action_type") == "RELEASE_ENDPOINT") else 0,
                    float(d.get("created_at_ts") or 0),
                    str(d.get("id") or ""),
                ),
                reverse=True,
            )
        else:
            group.sort(
                key=lambda d: (float(d.get("created_at_ts") or 0), str(d.get("id") or "")),
                reverse=True,
            )
        winner = group[0]
        merged_cases: List[str] = []
        for dup in group[1:]:
            drop_ids.add(id(dup))
            for cid in [dup.get("source_case_id"), dup.get("case_id")] + list(dup.get("control_cases") or []):
                s_cid = str(cid or "").strip()
                if s_cid and s_cid not in merged_cases:
                    merged_cases.append(s_cid)
        winner_cids = list(winner.get("control_cases") or [])
        for cid in merged_cases:
            cobj = get_case_by_id(cid)
            if cid not in winner_cids and (not cobj or cobj.get("status") != "CLOSED"):
                winner_cids.append(cid)
        winner["control_cases"] = winner_cids

    if drop_ids:
        decisions[:] = [d for d in decisions if id(d) not in drop_ids]

    # Xóa các bản ghi ACTIVE RELEASE_ENDPOINT cũ nếu hệ thống đang không cô lập host đó
    stale_release_ids: Set[int] = set()
    for d in decisions:
        if not isinstance(d, dict):
            continue
        if d.get("status") == "ACTIVE" and d.get("action_type") == "RELEASE_ENDPOINT" and d.get("source") == "AI_SOAR":
            clean_aid = str(d.get("target") or "").strip()
            ep_rec = ep_containment.get(clean_aid) if isinstance(ep_containment, dict) else None
            iso_status = str((ep_rec or {}).get("isolation_status") or "")
            if not _is_isolated_status(iso_status):
                stale_release_ids.add(id(d))
    if stale_release_ids:
        decisions[:] = [d for d in decisions if id(d) not in stale_release_ids]

    # 2. Đảm bảo TTL fields trên mọi ACTIVE control hiện hữu (neo theo now_ts cho dữ liệu cũ)
    for d in decisions:
        if not isinstance(d, dict):
            continue
        if d.get("status") == "ACTIVE":
            ttl = _normalize_ttl_seconds(d.get("ttl_seconds"), d.get("action_type", ""))
            d["ttl_seconds"] = ttl
            if ttl > 0 and not d.get("expires_at_ts"):
                exp_ts, exp_str = _compute_expiry_fields(ts, ttl)
                d["expires_at_ts"] = exp_ts
                d["expires_at"] = exp_str
            elif d.get("expires_at_ts"):
                d["expires_at"] = format_vn_time(d["expires_at_ts"])

    # 3. Đối chiếu Wazuh endpoint_containment
    seen_ep_keys: Set[str] = set()
    if isinstance(ep_containment, dict):
        for aid, ep_rec in list(ep_containment.items()):
            clean_aid = str(aid or "").strip()
            if not clean_aid or clean_aid == "000" or not isinstance(ep_rec, dict):
                continue
            ckey = _make_control_key("ISOLATE_ENDPOINT", clean_aid)
            seen_ep_keys.add(ckey)
            iso_status = str(ep_rec.get("isolation_status") or "").strip()
            active_dec = next(
                (d for d in decisions if isinstance(d, dict) and d.get("status") == "ACTIVE" and d.get("control_key") == ckey),
                None,
            )

            if _is_isolated_status(iso_status):
                inferred_src = _infer_source_case_for_containment_locked(clean_aid, ep_rec)
                if active_dec:
                    was_release = active_dec.get("action_type") == "RELEASE_ENDPOINT"
                    if was_release:
                        rec_ts = float(ep_rec.get("updated_at_ts") or ts)
                        ttl = _default_ttl_for_action("ISOLATE_ENDPOINT")
                        exp_ts, exp_str = _compute_expiry_fields(ts, ttl)
                        active_dec["action_type"] = "ISOLATE_ENDPOINT"
                        active_dec["title"] = f"Cô lập mạng Endpoint Agent {clean_aid} qua Wazuh AR"
                        active_dec["reason"] = ep_rec.get("reason") or f"Endpoint Agent {clean_aid} đang ở trạng thái {iso_status}"
                        active_dec["source_case_id"] = inferred_src
                        active_dec["case_id"] = inferred_src
                        active_dec["is_orphan"] = not bool(inferred_src)
                        active_dec["drift_status"] = "ORPHAN_RECONCILED" if not inferred_src else "RECONCILED_FROM_ENDPOINT"
                        active_dec["created_at"] = ep_rec.get("updated_at") or format_vn_time(rec_ts)
                        active_dec["created_at_ts"] = rec_ts
                        active_dec["ttl_seconds"] = ttl
                        active_dec["expires_at_ts"] = exp_ts
                        active_dec["expires_at"] = exp_str
                    elif inferred_src and not active_dec.get("source_case_id") and active_dec.get("source") != "COMMANDER":
                        active_dec["source_case_id"] = inferred_src
                        active_dec["case_id"] = inferred_src
                        active_dec["is_orphan"] = False
                        active_dec["drift_status"] = "SYNCED"
                    active_dec["execution_result"] = f"Trạng thái hiện tại: {iso_status}"
                    _refresh_decision_control_cases_locked(active_dec, extra_case_ids=ep_rec.get("case_ids") or [])
                    if was_release:
                        _record_control_audit(
                            "CONTROL_RECONCILED",
                            active_dec,
                            "reconciler",
                            f"Đồng bộ lại control {ckey} từ trạng thái thực tế {iso_status} (thay thế RELEASE_ENDPOINT cũ)",
                            now_ts=ts,
                        )
                else:
                    rec_ts = float(ep_rec.get("updated_at_ts") or ts)
                    ttl = _default_ttl_for_action("ISOLATE_ENDPOINT")
                    exp_ts, exp_str = _compute_expiry_fields(ts, ttl)
                    is_orphan = not bool(inferred_src)
                    new_dec = {
                        "id": _next_sequence_id("DEC", decisions),
                        "control_key": ckey,
                        "room_id": "",
                        "case_id": inferred_src,
                        "source_case_id": inferred_src,
                        "control_cases": [inferred_src] if inferred_src else [],
                        "is_orphan": is_orphan,
                        "action_type": "ISOLATE_ENDPOINT",
                        "target": clean_aid,
                        "title": f"Cô lập mạng Endpoint Agent {clean_aid} qua Wazuh AR",
                        "reason": ep_rec.get("reason") or f"Đồng bộ cô lập thực tế trên Agent {clean_aid} ({iso_status})",
                        "source": "RECONCILER" if is_orphan else "AI_SOAR",
                        "status": "ACTIVE",
                        "reversible": True,
                        "ttl_seconds": ttl,
                        "expires_at_ts": exp_ts,
                        "expires_at": exp_str,
                        "pending_revert_proposal": None,
                        "drift_status": "ORPHAN_RECONCILED" if is_orphan else "RECONCILED_FROM_ENDPOINT",
                        "execution_result": f"Trạng thái hiện tại: {iso_status}",
                        "revert_result": "",
                        "revert_reason": "",
                        "created_at": ep_rec.get("updated_at") or format_vn_time(rec_ts),
                        "created_at_ts": rec_ts,
                        "reverted_at": "",
                        "reverted_at_ts": None,
                    }
                    _refresh_decision_control_cases_locked(new_dec, extra_case_ids=ep_rec.get("case_ids") or [])
                    new_dec["room_id"] = _infer_room_for_decision_locked(new_dec)
                    decisions.insert(0, new_dec)
                    audit_note = (
                        f"Phát hiện Orphan Isolation đang khóa Agent {clean_aid} ({iso_status}) — không tìm thấy Case khởi phát"
                        if is_orphan
                        else f"Đồng bộ Active Control {ckey} từ {inferred_src} ({iso_status})"
                    )
                    _record_control_audit("CONTROL_RECONCILED", new_dec, "reconciler", audit_note, now_ts=ts)
            else:
                if active_dec and active_dec.get("action_type") == "ISOLATE_ENDPOINT":
                    drift_msg = f"Đồng bộ sai lệch trạng thái thực tế: Agent {clean_aid} hiện ở trạng thái {iso_status or 'UNISOLATED'}"
                    active_dec["status"] = "REVERTED"
                    active_dec["drift_status"] = "DRIFT_UNISOLATED"
                    active_dec["reverted_by"] = "drift-reconciliation"
                    active_dec["revert_reason"] = drift_msg
                    active_dec["revert_result"] = drift_msg
                    active_dec["reverted_at"] = time_str
                    active_dec["reverted_at_ts"] = ts
                    active_dec["pending_revert_proposal"] = None
                    _record_control_audit("DRIFT_RECONCILED", active_dec, "drift-reconciliation", drift_msg, now_ts=ts)

    for d in decisions:
        if (
            isinstance(d, dict)
            and d.get("status") == "ACTIVE"
            and d.get("action_type") == "ISOLATE_ENDPOINT"
            and d.get("control_key") not in seen_ep_keys
        ):
            clean_aid = str(d.get("target") or "").strip()
            drift_msg = f"Đồng bộ sai lệch trạng thái thực tế: Agent {clean_aid} không còn trong endpoint_containment"
            d["status"] = "REVERTED"
            d["drift_status"] = "DRIFT_UNISOLATED"
            d["reverted_by"] = "drift-reconciliation"
            d["revert_reason"] = drift_msg
            d["revert_result"] = drift_msg
            d["reverted_at"] = time_str
            d["reverted_at_ts"] = ts
            d["pending_revert_proposal"] = None
            _record_control_audit("DRIFT_RECONCILED", d, "drift-reconciliation", drift_msg, now_ts=ts)

    # 4. Đối chiếu pfSense blocked_ips
    for ip_target in sorted(blocked_ips_set):
        ckey = _make_control_key("BLOCK_IP", ip_target)
        active_dec = next(
            (d for d in decisions if isinstance(d, dict) and d.get("status") == "ACTIVE" and d.get("control_key") == ckey),
            None,
        )
        if not active_dec:
            inferred_src = _infer_source_case_for_blocked_ip_locked(ip_target)
            is_orphan = not bool(inferred_src)
            ttl = _default_ttl_for_action("BLOCK_IP")
            exp_ts, exp_str = _compute_expiry_fields(ts, ttl)
            new_dec = {
                "id": _next_sequence_id("DEC", decisions),
                "control_key": ckey,
                "room_id": "",
                "case_id": inferred_src,
                "source_case_id": inferred_src,
                "control_cases": [inferred_src] if inferred_src else [],
                "is_orphan": is_orphan,
                "action_type": "BLOCK_IP",
                "target": ip_target,
                "title": f"Chặn IP {ip_target} trên pfSense Firewall",
                "reason": STATE.get("pfsense_block_details", {}).get(ip_target) or f"Đồng bộ chặn IP {ip_target} từ pfSense SOC_BLOCKLIST",
                "source": "RECONCILER" if is_orphan else "AI_SOAR",
                "status": "ACTIVE",
                "reversible": True,
                "ttl_seconds": ttl,
                "expires_at_ts": exp_ts,
                "expires_at": exp_str,
                "pending_revert_proposal": None,
                "drift_status": "ORPHAN_RECONCILED" if is_orphan else "RECONCILED_FROM_PFSENSE",
                "execution_result": f"Đã thêm {ip_target} vào Alias SOC_BLOCKLIST",
                "revert_result": "",
                "revert_reason": "",
                "created_at": time_str,
                "created_at_ts": ts,
                "reverted_at": "",
                "reverted_at_ts": None,
            }
            _refresh_decision_control_cases_locked(new_dec)
            new_dec["room_id"] = _infer_room_for_decision_locked(new_dec)
            decisions.insert(0, new_dec)
            audit_note = (
                f"Phát hiện Orphan Block IP {ip_target} trên pfSense — không rõ Case gốc"
                if is_orphan
                else f"Đồng bộ Active Control {ckey} từ {inferred_src}"
            )
            _record_control_audit("CONTROL_RECONCILED", new_dec, "reconciler", audit_note, now_ts=ts)

    for d in decisions:
        if isinstance(d, dict) and d.get("status") == "ACTIVE" and d.get("action_type") == "BLOCK_IP":
            tgt = str(d.get("target") or "").strip()
            if tgt and tgt not in blocked_ips_set:
                drift_msg = f"Đồng bộ sai lệch trạng thái thực tế: IP {tgt} đã được gỡ khỏi pfSense SOC_BLOCKLIST"
                d["status"] = "REVERTED"
                d["drift_status"] = "DRIFT_UNBLOCKED"
                d["reverted_by"] = "drift-reconciliation"
                d["revert_reason"] = drift_msg
                d["revert_result"] = drift_msg
                d["reverted_at"] = time_str
                d["reverted_at_ts"] = ts
                d["pending_revert_proposal"] = None
                _record_control_audit("DRIFT_RECONCILED", d, "drift-reconciliation", drift_msg, now_ts=ts)

    # 5. Kiểm tra hết hạn TTL trên các ACTIVE controls
    for d in decisions:
        if not isinstance(d, dict) or d.get("status") != "ACTIVE":
            continue
        raw_exp = d.get("expires_at_ts")
        if raw_exp is None:
            continue
        try:
            exp_ts_val = float(raw_exp)
        except (TypeError, ValueError):
            continue
        if exp_ts_val > 0 and ts >= exp_ts_val:
            ttl_val = int(d.get("ttl_seconds") or DEFAULT_CONTROL_TTL_SECONDS)
            exp_reason = f"Hết hạn TTL ({ttl_val}s) — tự động thu hồi & đảo ngược control"
            room = _get_room_by_id(d.get("room_id", "")) or _find_room_for_case(d.get("source_case_id") or d.get("case_id", ""))
            ok_rev, rev_msg = _revert_decision_side_effect(d, reason=exp_reason, room=room)
            d["status"] = "REVERTED"
            d["expired"] = True
            d["drift_status"] = "EXPIRED_TTL"
            d["reverted_by"] = "ttl-scheduler"
            d["revert_reason"] = exp_reason
            d["revert_result"] = rev_msg if ok_rev else exp_reason
            d["reverted_at"] = time_str
            d["reverted_at_ts"] = ts
            d["pending_revert_proposal"] = None
            _record_control_audit("CONTROL_EXPIRED", d, "ttl-scheduler", exp_reason, now_ts=ts)
            if room:
                _append_room_message(
                    room,
                    sender="SOC System",
                    role="SYSTEM",
                    text=f"⏱️ [TTL EXPIRED] {d.get('id')} ({d.get('control_key')}) đã tự động đảo ngược do hết hạn TTL ({ttl_val}s).",
                    case_id=d.get("source_case_id") or d.get("case_id", ""),
                    decision_id=d.get("id", ""),
                    now_ts=ts,
                )

    # 6. Cập nhật control_cases_detail và room_id liên kết
    for d in decisions:
        if not isinstance(d, dict):
            continue
        _refresh_decision_control_cases_locked(d)
        if not d.get("room_id"):
            inferred_rid = _infer_room_for_decision_locked(d)
            if inferred_rid:
                d["room_id"] = inferred_rid

    return decisions


def sync_case_decisions(case: Dict[str, Any], room_id: str = "") -> List[Dict[str, Any]]:
    """Đồng bộ các hành động SOAR của 1 Case thành Decision có nút đảo ngược."""
    with _CASE_LOCK:
        res = _sync_single_case_decisions_locked(case, room_id=room_id)
        reconcile_active_controls_locked()
        return res


def sync_case_decisions_for_all_cases() -> List[Dict[str, Any]]:
    """Quét toàn bộ Case đang có và đối chiếu trạng thái thực tế thành bảng Active Controls canonical."""
    with _CASE_LOCK:
        for c in STATE.get("cases", []):
            if isinstance(c, dict):
                _sync_single_case_decisions_locked(c)
        return reconcile_active_controls_locked()


def ensure_default_rooms() -> List[Dict[str, Any]]:
    """Khởi tạo phòng tác chiến mặc định và đối chiếu Active Controls + Drift/Orphan/TTL."""
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
        reconcile_active_controls_locked()
        return rooms


def _get_decisions_for_room_locked(
    room: Dict[str, Any],
    all_decisions: List[Dict[str, Any]],
    room_cases: List[Dict[str, Any]],
    all_assets: Optional[List[Dict[str, Any]]] = None,
    nat_map: Optional[Dict[str, List[str]]] = None,
) -> List[Dict[str, Any]]:
    """Lấy tất cả Decision / Active Control thuộc Room theo room_id, case_id, control_cases đa Case, hoặc target overlap / Orphan."""
    room_id = str(room.get("id") or "")
    r_case_set = {str(cid) for cid in (room.get("case_ids") or []) if str(cid).strip()}
    room_agents = {str(c.get("agent_id") or "").strip() for c in room_cases if str(c.get("agent_id") or "").strip()}
    room_ips: Set[str] = set()
    for c in room_cases:
        if c.get("src_ip") and str(c.get("src_ip")) != "unknown":
            room_ips.add(str(c["src_ip"]).strip())
        for vip in (c.get("victim_ips") or []):
            if vip:
                room_ips.add(str(vip).strip())

    matched_assets = [
        a for a in (all_assets or [])
        if isinstance(a, dict) and nat_map is not None and any(_does_case_match_asset(c, a, nat_map) for c in room_cases)
    ]
    for ma in matched_assets:
        if ma.get("agent_id"):
            room_agents.add(str(ma["agent_id"]).strip())
        for mip in ([ma.get("ip")] + list(ma.get("extra_ips") or [])):
            if mip:
                room_ips.add(str(mip).strip())

    result: List[Dict[str, Any]] = []
    for d in all_decisions:
        if not isinstance(d, dict):
            continue
        if d.get("room_id") == room_id:
            result.append(d)
            continue
        cids_on_dec = {str(d.get("case_id") or "").strip(), str(d.get("source_case_id") or "").strip()}
        cids_on_dec.update(str(x).strip() for x in (d.get("control_cases") or []) if str(x).strip())
        cids_on_dec.discard("")
        if cids_on_dec.intersection(r_case_set):
            result.append(d)
            continue
        if d.get("status") == "ACTIVE":
            if d.get("is_orphan") and room_id == "ROOM-0001":
                result.append(d)
                continue
            act = str(d.get("action_type") or "").upper()
            tgt = str(d.get("target") or "").strip()
            if act in ("ISOLATE_ENDPOINT", "RELEASE_ENDPOINT") and tgt in room_agents:
                result.append(d)
                continue
            if act == "BLOCK_IP" and tgt in room_ips:
                result.append(d)
                continue
    return result


def compute_room_board_metrics(
    room: Dict[str, Any],
    all_cases: List[Dict[str, Any]],
    all_assets: List[Dict[str, Any]],
    all_decisions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Tính toán bộ chỉ số Board tổng quan của một Contingency Room."""
    room_case_ids = [str(cid) for cid in (room.get("case_ids") or []) if str(cid).strip()]
    cases_by_id = {str(c.get("id")): c for c in all_cases if isinstance(c, dict) and c.get("id")}
    room_cases = [cases_by_id[cid] for cid in room_case_ids if cid in cases_by_id]

    flagged_asset_set: Set[str] = set(str(aid) for aid in (room.get("flagged_asset_ids") or []) if str(aid).strip())
    nat_map = get_nat_ip_map()
    blocked_ips = set(str(ip).strip() for ip in (STATE["stats"].get("blocked_ips") or []))
    ep_containment = STATE.get("endpoint_containment", {})

    room_decisions = _get_decisions_for_room_locked(
        room,
        all_decisions,
        room_cases,
        all_assets=all_assets,
        nat_map=nat_map,
    )

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
    contained_ips.update(
        str(d.get("target")) for d in open_decisions
        if d.get("action_type") == "BLOCK_IP" and d.get("target")
    )
    contained_agents = {
        str(c.get("agent_id")) for c in room_cases
        if c.get("agent_id")
        and isinstance(ep_containment.get(str(c.get("agent_id"))), dict)
        and (
            "TEMP_ISOLATED" in str(ep_containment[str(c["agent_id"])].get("isolation_status", "")).upper()
            or "ISOLATED (LOCKED)" in str(ep_containment[str(c["agent_id"])].get("isolation_status", "")).upper()
        )
    }
    contained_agents.update(
        str(d.get("target")) for d in open_decisions
        if d.get("action_type") == "ISOLATE_ENDPOINT" and d.get("target")
    )
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
        case_decs = [
            d for d in room_decisions
            if d.get("case_id") == cid or d.get("source_case_id") == cid or cid in (d.get("control_cases") or [])
        ]
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
        nat_map = get_nat_ip_map()
        cases_by_id = {str(c.get("id")): c for c in all_cases if isinstance(c, dict) and c.get("id")}
        for r in rooms:
            if not isinstance(r, dict):
                continue
            r_cases = [cases_by_id[str(cid)] for cid in (r.get("case_ids") or []) if str(cid) in cases_by_id]
            board = compute_room_board_metrics(r, all_cases, all_assets, all_decisions)
            room_decs = [
                dict(d)
                for d in _get_decisions_for_room_locked(r, all_decisions, r_cases, all_assets=all_assets, nat_map=nat_map)
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
    nat_map = get_nat_ip_map()
    cases_by_id = {str(c.get("id")): c for c in all_cases if isinstance(c, dict) and c.get("id")}
    r_cases = [cases_by_id[str(cid)] for cid in (room.get("case_ids") or []) if str(cid) in cases_by_id]

    room_copy = dict(room)
    room_copy["board"] = compute_room_board_metrics(room, all_cases, all_assets, all_decisions)
    room_copy["room_decisions"] = [
        dict(d)
        for d in _get_decisions_for_room_locked(room, all_decisions, r_cases, all_assets=all_assets, nat_map=nat_map)
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
            "description": (
                "Tao DE XUAT dao nguoc (Revert Proposal) cho mot quyet dinh/Active Control dang ACTIVE "
                "(ho tro DEC-xxxx, control_key nhu ENDPOINT_ISOLATION:002, hoac IP/agent_id). "
                "De an toan SOC, AI CHI duoc tao de xuat cho con nguoi xac nhan trong tab Decisions, KHONG tu y mo khoa."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "decision_id": {"type": "string", "description": "Ma quyet dinh (DEC-xxxx), control_key hoac muc tieu (vi du 002, 192.168.63.240)"},
                    "reason": {"type": "string", "description": "Ly do de xuat dao nguoc"},
                },
                "required": ["decision_id", "reason"],
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
            "control_key": d.get("control_key"),
            "status": d.get("status"),
            "action_type": d.get("action_type"),
            "target": d.get("target"),
            "case_id": d.get("case_id"),
            "source_case_id": d.get("source_case_id"),
            "source_label": d.get("source_label"),
            "is_orphan": bool(d.get("is_orphan")),
            "control_cases": d.get("control_cases") or [],
            "expires_at": d.get("expires_at"),
            "pending_revert_proposal": d.get("pending_revert_proposal"),
            "reason": d.get("reason"),
            "source": d.get("source"),
        }
        for d in (enriched.get("room_decisions") or [])[:20]
    ]

    room_dec_ids = {str(d.get("id")) for d in (enriched.get("room_decisions") or []) if d.get("id")}
    global_active_controls = [
        {
            "id": d.get("id"),
            "control_key": d.get("control_key"),
            "room_id": d.get("room_id"),
            "action_type": d.get("action_type"),
            "target": d.get("target"),
            "source_case_id": d.get("source_case_id"),
            "source_label": d.get("source_label"),
            "is_orphan": bool(d.get("is_orphan")),
            "control_cases": d.get("control_cases") or [],
            "expires_at": d.get("expires_at"),
            "pending_revert_proposal": d.get("pending_revert_proposal"),
            "reason": d.get("reason"),
        }
        for d in STATE.get("tactical_decisions", [])
        if isinstance(d, dict) and d.get("status") == "ACTIVE"
    ][:25]

    assets_summary = [
        {
            "id": a.get("id"),
            "name": a.get("name"),
            "ip": a.get("ip"),
            "agent_id": a.get("agent_id"),
            "labels": a.get("labels") or [],
            "containment_status": a.get("containment_status"),
            "active_control": a.get("active_control"),
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
        "3. Khi kiem tra trang thai co lap Endpoint hoac chan IP, LUON doi chieu ca 'DECISIONS & ACTIVE CONTROLS TRONG ROOM' lan 'GLOBAL ACTIVE CONTROLS TOAN HE THONG' de xac dinh chinh xac: DEC-xxxx nao dang giu lenh, control_key, source_case_id (Case khoi phat) hay is_orphan=true (Nguon khong xac dinh), va danh sach control_cases bi anh huong.\n"
        "4. Khi SOC Commander yeu cau thuc thi hanh dong ung pho (chan IP, co lap endpoint, gan co compromised asset, dong case) hoac keo them Case -> goi tool_room_execute_decision / tool_room_attach_case.\n"
        "5. QUY TAC AN TOAN DAO NGUOC (HUMAN CONFIRMATION GATE): Khi duoc yeu cau go co lap/go chan/dao nguoc Decision -> CHI goi tool_room_revert_decision de tao DE XUAT dao nguoc (pending_revert_proposal). TUYET DOI KHONG bo qua xac nhan con nguoi; hay bao ro ma DEC-xxxx, danh sach control_cases bi anh huong va nhac Commander bam Xac nhan trong tab Decisions.\n\n"
        f"THONG TIN BOARD ROOM HIEN TAI:\n{json.dumps(board_brief, ensure_ascii=False)}\n\n"
        f"CASES TRONG ROOM:\n{json.dumps(in_room_cases_detail, ensure_ascii=False)}\n\n"
        f"CASES DANG MO KHAC CHUA VAO ROOM:\n{json.dumps(other_open_cases, ensure_ascii=False)}\n\n"
        f"DECISIONS & ACTIVE CONTROLS TRONG ROOM (TRONG DO CO CA ORPHAN/LIEN QUAN):\n{json.dumps(decisions_summary, ensure_ascii=False)}\n\n"
        f"GLOBAL ACTIVE CONTROLS TOAN HE THONG (SINGLE SOURCE OF TRUTH):\n{json.dumps(global_active_controls, ensure_ascii=False)}\n\n"
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
        act_type = str(fn_args.get("action_type", "")).strip().upper()
        tgt = str(fn_args.get("target", "")).strip()
        rsn = fn_args.get("reason") or "AI SOC Commander đề xuất trong Contingency Room"
        if act_type == "RELEASE_ENDPOINT":
            active_iso = _resolve_decision_by_ref(_make_control_key("ISOLATE_ENDPOINT", tgt))
            if active_iso and active_iso.get("status") == "ACTIVE" and active_iso.get("action_type") == "ISOLATE_ENDPOINT":
                _ok, _res, msg = propose_revert_decision(
                    active_iso["id"],
                    reason=rsn,
                    proposed_by="AI_SOAR",
                    room_id=room_id,
                )
                return msg
        payload = {
            "action_type": act_type,
            "target": tgt,
            "reason": rsn,
            "case_id": fn_args.get("case_id") or focus_case_id,
            "source": "AI_SOAR",
        }
        _ok, _res, msg = create_and_execute_decision(room_id, payload)
        return msg

    if fn_name == "tool_room_revert_decision":
        _ok, _res, msg = propose_revert_decision(
            fn_args.get("decision_id", ""),
            reason=fn_args.get("reason") or "AI SOC Advisor đề xuất đảo ngược trong Room",
            proposed_by="AI_SOAR",
            room_id=room_id,
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
            "source": "AI_SOAR",
        })
        return msg

    if fn_name == "tool_wazuh_endpoint_response":
        raw_act = str(fn_args.get("action", "keep_isolated")).strip().lower()
        aid = str(fn_args.get("agent_id", "")).strip()
        rsn = fn_args.get("reason") or "AI SOC Advisor điều chỉnh cô lập Endpoint"
        if raw_act == "release_isolation":
            active_iso = _resolve_decision_by_ref(_make_control_key("ISOLATE_ENDPOINT", aid))
            if active_iso and active_iso.get("status") == "ACTIVE" and active_iso.get("action_type") == "ISOLATE_ENDPOINT":
                _ok, _res, msg = propose_revert_decision(
                    active_iso["id"],
                    reason=rsn,
                    proposed_by="AI_SOAR",
                    room_id=room_id,
                )
                return msg
        mapped_act = "RELEASE_ENDPOINT" if raw_act == "release_isolation" else "ISOLATE_ENDPOINT"
        _ok, _res, msg = create_and_execute_decision(room_id, {
            "action_type": mapped_act,
            "target": aid,
            "reason": rsn,
            "case_id": focus_case_id,
            "source": "AI_SOAR",
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

        res = str(tool_wazuh_endpoint_response(agent_id=clean_target, action="keep_isolated", reason=reason, case_id=case_id))
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

        res = str(tool_wazuh_endpoint_response(agent_id=clean_target, action="release_isolation", reason=reason, case_id=case_id))
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
    case_id = str(decision.get("source_case_id") or decision.get("case_id") or "").strip()

    if action_type == "BLOCK_IP":
        from tools.firewall_tools import tool_unblock_firewall_ip

        res = str(tool_unblock_firewall_ip(target))
        blocked_list = STATE["stats"].setdefault("blocked_ips", [])
        if target in blocked_list:
            blocked_list.remove(target)
        STATE.get("pfsense_block_details", {}).pop(target, None)
        related_cids = set(str(x).strip() for x in ([case_id] + list(decision.get("control_cases") or [])) if str(x).strip())
        for cid in related_cids:
            c_obj = get_case_by_id(cid)
            if c_obj:
                actions = c_obj.setdefault("actions_taken", [])
                c_obj["actions_taken"] = [a for a in actions if f"pfSense Block IP {target}" not in str(a)]
                rev_note = f"Reverted Block IP {target}"
                if rev_note not in c_obj["actions_taken"]:
                    c_obj["actions_taken"].append(rev_note)
        return True, res or f"Đã gỡ chặn IP {target} khỏi SOC_BLOCKLIST"

    if action_type == "ISOLATE_ENDPOINT":
        from tools.wazuh_tools import tool_wazuh_endpoint_response

        res = str(
            tool_wazuh_endpoint_response(
                agent_id=target,
                action="release_isolation",
                reason=reason or f"Đảo ngược quyết định {decision.get('id')}",
                case_id=case_id,
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
                case_id=case_id,
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
    """Tạo và thực thi (idempotent theo control_key) một Active Control / Decision có nút đảo ngược trong Contingency Room."""
    if not isinstance(payload, dict):
        return False, {}, "Dữ liệu quyết định không hợp lệ."

    action_type = str(payload.get("action_type") or "").strip().upper()
    if action_type not in VALID_DECISION_TYPES:
        return False, {}, f"Loại quyết định '{action_type}' không hợp lệ. Chỉ hỗ trợ: {', '.join(sorted(VALID_DECISION_TYPES))}."

    target = str(payload.get("target") or "").strip()
    case_id = str(payload.get("case_id") or "").strip()
    reason = str(payload.get("reason") or "").strip() or "Quyết định tác chiến từ SOC Commander"
    custom_title = str(payload.get("title") or "").strip()
    source_actor = str(payload.get("source") or "COMMANDER").strip().upper()
    ttl_seconds = _normalize_ttl_seconds(payload.get("ttl_seconds"), action_type)

    with _CASE_LOCK:
        ensure_default_rooms()
        room = _get_room_by_id(room_id)
        if not room:
            return False, {}, f"Không tìm thấy phòng tác chiến {room_id}."

        if not target and action_type == "CLOSE_CASE" and case_id:
            target = case_id

        ckey = _make_control_key(action_type, target)
        decisions = STATE.setdefault("tactical_decisions", [])
        ts, time_str = _now_and_str()

        # Idempotent check theo canonical control_key
        existing_active = next(
            (
                d for d in decisions
                if isinstance(d, dict)
                and d.get("status") == "ACTIVE"
                and (d.get("control_key") or _make_control_key(d.get("action_type", ""), d.get("target", ""))) == ckey
            ),
            None,
        )
        if existing_active and existing_active.get("action_type") == action_type:
            if not existing_active.get("room_id"):
                existing_active["room_id"] = room["id"]
            if case_id and not existing_active.get("source_case_id"):
                existing_active["source_case_id"] = case_id
                existing_active["case_id"] = case_id
                existing_active["is_orphan"] = False
            if ttl_seconds > 0:
                exp_ts, exp_str = _compute_expiry_fields(ts, ttl_seconds)
                existing_active["ttl_seconds"] = ttl_seconds
                existing_active["expires_at_ts"] = exp_ts
                existing_active["expires_at"] = exp_str
            elif payload.get("ttl_seconds") is not None:
                existing_active["ttl_seconds"] = 0
                existing_active["expires_at_ts"] = None
                existing_active["expires_at"] = None
            _refresh_decision_control_cases_locked(existing_active, extra_case_ids=[case_id] if case_id else None)
            if case_id and case_id not in room.setdefault("case_ids", []) and get_case_by_id(case_id):
                room["case_ids"].append(case_id)
            _record_control_audit(
                "CONTROL_EXTENDED",
                existing_active,
                source_actor,
                f"Tái sử dụng control đang hiệu lực — {reason}",
                target_case_ids=existing_active.get("control_cases") or ([case_id] if case_id else []),
                now_ts=ts,
            )
            save_persistent_state()
            return (
                True,
                {"decision": dict(existing_active), "room": _enrich_single_room_locked(room)},
                f"Active Control {existing_active['id']} ({ckey}) đang có hiệu lực — đã idempotent gia hạn TTL và liên kết Case.",
            )

        ok_exec, exec_msg, auto_title = _execute_decision_side_effect(
            action_type=action_type,
            target=target,
            reason=reason,
            room=room,
            case_id=case_id,
        )
        if not ok_exec:
            return False, {}, exec_msg

        if existing_active and existing_active.get("action_type") != action_type:
            # Thay thế control trái chiều trên cùng control_key (vd: RELEASE_ENDPOINT -> ISOLATE_ENDPOINT)
            decisions[:] = [d for d in decisions if d is not existing_active]

        dec_id = _next_sequence_id("DEC", decisions)
        exp_ts, exp_str = _compute_expiry_fields(ts, ttl_seconds)
        dec = {
            "id": dec_id,
            "control_key": ckey,
            "room_id": room["id"],
            "case_id": case_id,
            "source_case_id": case_id,
            "control_cases": [case_id] if case_id else [],
            "is_orphan": False,
            "action_type": action_type,
            "target": target,
            "title": custom_title or auto_title,
            "reason": reason,
            "source": source_actor,
            "status": "ACTIVE",
            "reversible": True,
            "ttl_seconds": ttl_seconds,
            "expires_at_ts": exp_ts,
            "expires_at": exp_str,
            "pending_revert_proposal": None,
            "drift_status": "SYNCED",
            "execution_result": exec_msg,
            "revert_result": "",
            "revert_reason": "",
            "created_at": time_str,
            "created_at_ts": ts,
            "reverted_at": "",
            "reverted_at_ts": None,
        }

        if case_id and case_id not in room.setdefault("case_ids", []) and get_case_by_id(case_id):
            room["case_ids"].append(case_id)

        _refresh_decision_control_cases_locked(dec)
        decisions.insert(0, dec)
        _record_control_audit(
            "CONTROL_EXECUTED",
            dec,
            source_actor,
            reason,
            target_case_ids=dec.get("control_cases") or ([case_id] if case_id else []),
            now_ts=ts,
        )

        _append_room_message(
            room,
            sender="SOC System",
            role="SYSTEM",
            text=f"⚖️ [DECISION] Đã thực thi {dec_id} ({ckey}): {dec['title']} (Mục tiêu: {target}) — Có thể đảo ngược.",
            case_id=case_id,
            decision_id=dec_id,
            now_ts=ts,
        )
        save_persistent_state()
        log_event("ACTION", f"⚖️ [{room['id']}] Thực thi quyết định {dec_id}: {dec['title']}")
        return True, {"decision": dict(dec), "room": _enrich_single_room_locked(room)}, f"Đã thực thi quyết định {dec_id}."


def propose_revert_decision(
    decision_id: str,
    reason: str = "",
    proposed_by: str = "AI_SOAR",
    room_id: str = "",
) -> Tuple[bool, Dict[str, Any], str]:
    """Tạo đề xuất đảo ngược (chờ con người xác nhận — AI không được phép tự mở khóa/gỡ chặn)."""
    clean_ref = str(decision_id or "").strip()
    clean_reason = str(reason or "").strip() or "AI SOAR Assistant đề xuất đảo ngược sau khi phân tích"
    with _CASE_LOCK:
        ensure_default_rooms()
        dec = _resolve_decision_by_ref(clean_ref)
        if not dec:
            return False, {}, f"Không tìm thấy Active Control / Decision '{clean_ref}' để đề xuất đảo ngược."
        if dec.get("status") == "REVERTED":
            return False, {"decision": dict(dec)}, f"Quyết định {dec.get('id')} ({dec.get('control_key')}) đã ở trạng thái REVERTED."

        _refresh_decision_control_cases_locked(dec)
        ts, time_str = _now_and_str()
        impacted = list(dec.get("control_cases") or [])
        target_room = _get_room_by_id(room_id) or _get_room_by_id(dec.get("room_id", "")) or _find_room_for_case(dec.get("source_case_id") or dec.get("case_id", ""))
        if target_room and not dec.get("room_id"):
            dec["room_id"] = target_room["id"]

        proposal = {
            "proposed_by": proposed_by or "AI_SOAR",
            "proposed_at": time_str,
            "proposed_at_ts": ts,
            "reason": clean_reason,
            "impacted_cases": impacted,
            "source_case_id": dec.get("source_case_id", ""),
            "is_orphan": bool(dec.get("is_orphan")),
            "room_id": target_room["id"] if target_room else dec.get("room_id", ""),
        }
        dec["pending_revert_proposal"] = proposal
        _record_control_audit(
            "REVERT_PROPOSED",
            dec,
            proposed_by or "AI_SOAR",
            clean_reason,
            target_case_ids=impacted,
            now_ts=ts,
        )
        impacted_str = ", ".join(impacted) if impacted else ("Orphan Control (không rõ case gốc)" if dec.get("is_orphan") else "Không gắn Case")
        if target_room:
            _append_room_message(
                target_room,
                sender="SOC System",
                role="SYSTEM",
                text=(
                    f"⏳ [REVERT PROPOSAL] {proposed_by} đề xuất đảo ngược {dec['id']} ({dec.get('control_key')}). "
                    f"Ảnh hưởng tới: {impacted_str}. Cần người vận hành xác nhận thủ công trong tab Decisions."
                ),
                case_id=dec.get("source_case_id") or dec.get("case_id", ""),
                decision_id=dec["id"],
                now_ts=ts,
            )
        save_persistent_state()
        room_data = _enrich_single_room_locked(target_room) if target_room else None
        return (
            True,
            {"decision": dict(dec), "room": room_data},
            (
                f"[CHỜ PHÊ DUYỆT CON NGƯỜI] Đã tạo đề xuất đảo ngược {dec['id']} ({dec.get('control_key')}). "
                f"Origin: {dec.get('source_label', 'Unknown')}. Cases ảnh hưởng: {impacted_str}. "
                "Vui lòng xác nhận thủ công tại Contingency Room -> Tab Decisions."
            ),
        )


def reject_revert_proposal(
    decision_id: str,
    reason: str = "",
    actor: str = "SOC Commander",
) -> Tuple[bool, Dict[str, Any], str]:
    """Từ chối đề xuất đảo ngược do AI hoặc hệ thống đưa ra; giữ nguyên Active Control."""
    clean_did = str(decision_id or "").strip()
    clean_reason = str(reason or "").strip() or "Người vận hành giữ nguyên Active Control"
    with _CASE_LOCK:
        ensure_default_rooms()
        dec = _resolve_decision_by_ref(clean_did)
        if not dec:
            return False, {}, f"Không tìm thấy quyết định {clean_did}."
        if not dec.get("pending_revert_proposal"):
            return True, {"decision": dict(dec)}, f"Quyết định {dec['id']} không có đề xuất đảo ngược đang chờ."

        dec["pending_revert_proposal"] = None
        ts, _ = _now_and_str()
        _record_control_audit(
            "REVERT_PROPOSAL_REJECTED",
            dec,
            actor or "SOC Commander",
            clean_reason,
            target_case_ids=dec.get("control_cases") or [],
            now_ts=ts,
        )
        room = _get_room_by_id(dec.get("room_id", "")) or _find_room_for_case(dec.get("source_case_id") or dec.get("case_id", ""))
        save_persistent_state()
        room_data = _enrich_single_room_locked(room) if room else None
        return True, {"decision": dict(dec), "room": room_data}, f"Đã từ chối đề xuất đảo ngược {dec['id']} — giữ nguyên kiểm soát."


def revert_tactical_decision(
    decision_id: str,
    reason: str = "",
    actor: str = "SOC Commander",
) -> Tuple[bool, Dict[str, Any], str]:
    """Đảo ngược (Rollback) một Decision đang ACTIVE về trạng thái ban đầu (yêu cầu lý do bắt buộc & idempotent)."""
    clean_did = str(decision_id or "").strip()
    clean_reason = str(reason or "").strip()

    with _CASE_LOCK:
        ensure_default_rooms()
        dec = _resolve_decision_by_ref(clean_did)
        if not dec:
            return False, {}, f"Không tìm thấy quyết định {clean_did}."
        room = _get_room_by_id(dec.get("room_id", "")) or _find_room_for_case(dec.get("source_case_id") or dec.get("case_id", ""))
        room_data = _enrich_single_room_locked(room) if room else None

        if dec.get("status") == "REVERTED":
            return (
                True,
                {"decision": dict(dec), "room": room_data},
                f"Quyết định {dec['id']} ({dec.get('control_key')}) đã được đảo ngược trước đó (Idempotent No-Op).",
            )

        if not clean_reason:
            return False, {}, "Bắt buộc nhập lý do đảo ngược quyết định (Audit Requirement)."

        _refresh_decision_control_cases_locked(dec)
        impacted_cases = list(dec.get("control_cases") or [])

        ok_rev, rev_msg = _revert_decision_side_effect(dec, reason=clean_reason, room=room)
        if not ok_rev:
            return False, {}, rev_msg

        ts, time_str = _now_and_str()
        dec["status"] = "REVERTED"
        dec["expired"] = False
        dec["drift_status"] = "REVERTED_BY_OPERATOR"
        dec["reverted_by"] = actor or "SOC Commander"
        dec["pending_revert_proposal"] = None
        dec["revert_result"] = rev_msg
        dec["revert_reason"] = clean_reason
        dec["reverted_at"] = time_str
        dec["reverted_at_ts"] = ts

        _record_control_audit(
            "CONTROL_REVERTED",
            dec,
            actor or "SOC Commander",
            clean_reason,
            target_case_ids=impacted_cases,
            now_ts=ts,
        )

        if room:
            _append_room_message(
                room,
                sender="SOC System",
                role="SYSTEM",
                text=(
                    f"↩️ [REVERTED] Đã đảo ngược quyết định {dec['id']} ({dec.get('control_key')}): {dec.get('title', '')} "
                    f"— Lý do: {clean_reason} — Kết quả: {rev_msg}"
                ),
                case_id=dec.get("source_case_id") or dec.get("case_id", ""),
                decision_id=dec["id"],
                now_ts=ts,
            )

        save_persistent_state()
        log_event("ACTION", f"↩️ Đã đảo ngược quyết định {dec['id']} ({dec.get('action_type')} -> {dec.get('target')})")
        room_data = _enrich_single_room_locked(room) if room else None
        return True, {"decision": dict(dec), "room": room_data}, f"Đã đảo ngược quyết định {dec['id']}: {rev_msg}"


def reapply_tactical_decision(
    decision_id: str,
    reason: str = "",
    actor: str = "SOC Commander",
) -> Tuple[bool, Dict[str, Any], str]:
    """Thực thi lại một Decision đang ở trạng thái REVERTED."""
    clean_did = str(decision_id or "").strip()
    with _CASE_LOCK:
        ensure_default_rooms()
        dec = _resolve_decision_by_ref(clean_did)
        if not dec:
            return False, {}, f"Không tìm thấy quyết định {clean_did}."
        if dec.get("status") == "ACTIVE":
            room = _get_room_by_id(dec.get("room_id", "")) or _find_room_for_case(dec.get("source_case_id") or dec.get("case_id", ""))
            return (
                True,
                {"decision": dict(dec), "room": _enrich_single_room_locked(room) if room else None},
                f"Quyết định {dec['id']} đang ở trạng thái ACTIVE.",
            )

        room = _get_room_by_id(dec.get("room_id", "")) or _find_room_for_case(dec.get("source_case_id") or dec.get("case_id", ""))
        exec_reason = str(reason or "").strip() or dec.get("reason") or f"Thực thi lại {dec['id']}"
        ok_exec, exec_msg, _ = _execute_decision_side_effect(
            action_type=str(dec.get("action_type") or ""),
            target=str(dec.get("target") or ""),
            reason=exec_reason,
            room=room,
            case_id=str(dec.get("source_case_id") or dec.get("case_id") or ""),
        )
        if not ok_exec:
            return False, {}, exec_msg

        ts, time_str = _now_and_str()
        ttl = _normalize_ttl_seconds(dec.get("ttl_seconds"), dec.get("action_type", ""))
        exp_ts, exp_str = _compute_expiry_fields(ts, ttl)
        dec["status"] = "ACTIVE"
        dec["expired"] = False
        dec["drift_status"] = "SYNCED"
        dec["pending_revert_proposal"] = None
        dec["ttl_seconds"] = ttl
        dec["expires_at_ts"] = exp_ts
        dec["expires_at"] = exp_str
        dec["execution_result"] = exec_msg
        dec["created_at"] = time_str
        dec["created_at_ts"] = ts
        dec["reverted_at"] = ""
        dec["reverted_at_ts"] = None
        dec["revert_result"] = ""
        dec["revert_reason"] = ""

        _refresh_decision_control_cases_locked(dec)
        _record_control_audit(
            "CONTROL_REAPPLIED",
            dec,
            actor or "SOC Commander",
            exec_reason,
            target_case_ids=dec.get("control_cases") or [],
            now_ts=ts,
        )

        if room:
            _append_room_message(
                room,
                sender="SOC System",
                role="SYSTEM",
                text=f"🔄 [REAPPLIED] Đã thực thi lại quyết định {dec['id']} ({dec.get('control_key')}): {dec.get('title', '')}.",
                case_id=dec.get("source_case_id") or dec.get("case_id", ""),
                decision_id=dec["id"],
                now_ts=ts,
            )

        save_persistent_state()
        log_event("ACTION", f"🔄 Đã thực thi lại quyết định {dec['id']}")
        room_data = _enrich_single_room_locked(room) if room else None
        return True, {"decision": dict(dec), "room": room_data}, f"Đã thực thi lại quyết định {dec['id']}."
