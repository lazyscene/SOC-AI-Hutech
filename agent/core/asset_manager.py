import re
from typing import Optional, Dict, List, Any, Tuple
from web.state import STATE, log_event, save_persistent_state
from core.case_manager import (
    _CASE_LOCK,
    _next_sequence_id,
    get_nat_ip_map,
    is_ip_matching_agent,
    register_agent_ip,
)

DEFAULT_ASSETS: List[Dict[str, Any]] = [
    {
        "id": "ASSET-0001",
        "name": "pfSense Firewall Gateway",
        "ip": "192.168.171.2",
        "extra_ips": ["192.168.63.134"],
        "agent_id": "",
        "labels": ["firewall", "router", "network"],
        "owner": "NetSec Team",
    },
    {
        "id": "ASSET-0002",
        "name": "Wazuh SIEM & SOC Server",
        "ip": "192.168.171.34",
        "extra_ips": ["192.168.63.138"],
        "agent_id": "000",
        "labels": ["linux", "server", "siem", "soc"],
        "owner": "SOC Admin",
    },
    {
        "id": "ASSET-0003",
        "name": "Victim Linux Web Server",
        "ip": "192.168.214.10",
        "extra_ips": [],
        "agent_id": "002",
        "labels": ["linux", "server", "web"],
        "owner": "Web App Team",
    },
    {
        "id": "ASSET-0004",
        "name": "Victim Windows 10 Workstation",
        "ip": "192.168.45.10",
        "extra_ips": ["192.168.45.17"],
        "agent_id": "003",
        "labels": ["windows", "máy trạm", "endpoint"],
        "owner": "IT Operations",
    },
    {
        "id": "ASSET-0005",
        "name": "Host GPU Ollama Server",
        "ip": "192.168.63.1",
        "extra_ips": [],
        "agent_id": "",
        "labels": ["linux", "server", "gpu-host", "ai-core"],
        "owner": "SOC Admin",
    },
]


def _normalize_asset_labels(raw_labels: Any) -> List[str]:
    """Chuẩn hóa danh sách nhãn loại thiết bị (linux, server, máy trạm, router, firewall...)."""
    if isinstance(raw_labels, str):
        parts = re.split(r"[,;]+", raw_labels)
    elif isinstance(raw_labels, list):
        parts = [str(item or "") for item in raw_labels]
    else:
        return []

    normalized: List[str] = []
    for part in parts:
        cleaned = re.sub(r"\s+", " ", part.strip().lower())
        if cleaned and cleaned not in normalized:
            normalized.append(cleaned)
    return normalized


def _normalize_ip_list(raw_ips: Any, exclude_ip: str = "") -> List[str]:
    """Chuẩn hóa danh sách IP phụ của thiết bị, loại bỏ IP trùng hoặc rỗng."""
    if isinstance(raw_ips, str):
        parts = re.split(r"[,;\s]+", raw_ips)
    elif isinstance(raw_ips, list):
        parts = [str(item or "") for item in raw_ips]
    else:
        return []

    result: List[str] = []
    for part in parts:
        ip_s = part.strip()
        if (
            ip_s
            and ip_s != exclude_ip
            and ip_s.lower() not in ["unknown", "none", "n/a"]
            and ip_s not in result
        ):
            result.append(ip_s)
    return result


def _collect_asset_ips(asset: Dict[str, Any]) -> List[str]:
    """Gom toàn bộ IP (IP chính + extra_ips) của một thiết bị."""
    ips: List[str] = []
    main_ip = str(asset.get("ip") or "").strip()
    if main_ip and main_ip.lower() not in ["unknown", "none", "n/a"]:
        ips.append(main_ip)
    for ex_ip in asset.get("extra_ips", []) or []:
        ex_s = str(ex_ip or "").strip()
        if ex_s and ex_s.lower() not in ["unknown", "none", "n/a"] and ex_s not in ips:
            ips.append(ex_s)
    return ips


def ensure_default_assets() -> List[Dict[str, Any]]:
    """Khởi tạo danh sách thiết bị Lab mặc định nếu trống và đồng bộ IP mới từ agent_ip_registry."""
    with _CASE_LOCK:
        assets = STATE.setdefault("assets", [])
        if not assets:
            for item in DEFAULT_ASSETS:
                assets.append({
                    "id": item["id"],
                    "name": item["name"],
                    "ip": item["ip"],
                    "extra_ips": list(item.get("extra_ips", [])),
                    "agent_id": item.get("agent_id", ""),
                    "labels": list(item.get("labels", [])),
                    "owner": item.get("owner", ""),
                })

        registry = STATE.get("agent_ip_registry", {})
        dismissed = set(str(x).strip() for x in STATE.get("dismissed_asset_agents", []) if str(x).strip())
        if isinstance(registry, dict):
            for reg_agent_id, reg_ips in registry.items():
                clean_aid = str(reg_agent_id or "").strip()
                if not clean_aid or clean_aid.lower() in ["000", "unknown", "none", "local"]:
                    continue
                valid_ips = _normalize_ip_list(reg_ips)
                matched = next(
                    (a for a in assets if isinstance(a, dict) and str(a.get("agent_id") or "").strip() == clean_aid),
                    None,
                )
                if matched:
                    if not matched.get("ip") and valid_ips:
                        matched["ip"] = valid_ips[0]
                    extra = matched.setdefault("extra_ips", [])
                    for ip_s in valid_ips:
                        if ip_s != matched.get("ip") and ip_s not in extra:
                            extra.append(ip_s)
                elif clean_aid not in dismissed:
                    assets.append({
                        "id": _next_sequence_id("ASSET", assets),
                        "name": f"Wazuh Agent {clean_aid}",
                        "ip": valid_ips[0] if valid_ips else "",
                        "extra_ips": valid_ips[1:] if len(valid_ips) > 1 else [],
                        "agent_id": clean_aid,
                        "labels": ["endpoint", "auto-discovered"],
                        "owner": "SOC Auto-Discovery",
                    })
        return assets


def _does_case_match_asset(case: Dict[str, Any], asset: Dict[str, Any], nat_map: Dict[str, List[str]]) -> bool:
    """Kiểm tra một Case có thuộc về thiết bị này hay không (theo agent_id, victim_ips/src_ip hoặc NAT)."""
    asset_agent_id = str(asset.get("agent_id") or "").strip()
    case_agent_id = str(case.get("agent_id") or "").strip()
    case_victims = [
        str(v or "").strip()
        for v in (case.get("victim_ips") or [])
        if str(v or "").strip() and str(v or "").strip().lower() not in ["unknown", "none", "n/a"]
    ]

    if asset_agent_id and asset_agent_id.lower() not in ["000", "unknown", "none"]:
        if case_agent_id == asset_agent_id:
            return True
        for vip in case_victims:
            if is_ip_matching_agent(vip, asset_agent_id):
                return True

    asset_ips = set(_collect_asset_ips(asset))
    if not asset_ips:
        return False

    case_ips = list(case_victims)
    case_src = str(case.get("src_ip") or "").strip()
    if case_src and case_src.lower() not in ["unknown", "none", "n/a"] and case_src not in case_ips:
        case_ips.append(case_src)

    for c_ip in case_ips:
        if c_ip in asset_ips:
            return True
        if c_ip in nat_map and any(mapped in asset_ips for mapped in nat_map[c_ip]):
            return True

    return False


def _enrich_asset_record(
    asset: Dict[str, Any],
    cases: List[Dict[str, Any]],
    nat_map: Dict[str, List[str]],
    ep_containment: Dict[str, Any],
    decisions: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Bổ sung bộ đếm Case động (case_count, open_case_count, case_ids) và Active Control metadata cho một bản ghi thiết bị."""
    matched_cases = [c for c in cases if isinstance(c, dict) and _does_case_match_asset(c, asset, nat_map)]
    case_ids = [str(c.get("id")) for c in matched_cases if c.get("id")]
    open_case_count = sum(1 for c in matched_cases if c.get("status") != "CLOSED")

    all_ips = _collect_asset_ips(asset)
    all_ip_set = set(all_ips)
    agent_id = str(asset.get("agent_id") or "").strip()
    ep_rec = ep_containment.get(agent_id) if agent_id and isinstance(ep_containment, dict) else None
    containment_status = ep_rec.get("isolation_status") if isinstance(ep_rec, dict) else None

    active_control = None
    matched_dec = None
    for d in (decisions or []):
        if not isinstance(d, dict) or d.get("status") != "ACTIVE":
            continue
        act = str(d.get("action_type") or "").upper()
        tgt = str(d.get("target") or "").strip()
        if act == "ISOLATE_ENDPOINT" and agent_id and tgt == agent_id:
            matched_dec = d
            break
    if not matched_dec:
        for d in (decisions or []):
            if not isinstance(d, dict) or d.get("status") != "ACTIVE":
                continue
            act = str(d.get("action_type") or "").upper()
            tgt = str(d.get("target") or "").strip()
            if act == "BLOCK_IP" and tgt and tgt in all_ip_set:
                matched_dec = d
                break

    if matched_dec:
        active_control = {
            "decision_id": matched_dec.get("id", ""),
            "control_key": matched_dec.get("control_key", ""),
            "action_type": matched_dec.get("action_type", ""),
            "source_case_id": matched_dec.get("source_case_id", "") or matched_dec.get("case_id", ""),
            "source_label": matched_dec.get("source_label", ""),
            "is_orphan": bool(matched_dec.get("is_orphan")),
            "control_cases": list(matched_dec.get("control_cases") or []),
            "expires_at": matched_dec.get("expires_at"),
            "room_id": matched_dec.get("room_id", ""),
        }

    return {
        "id": asset.get("id", ""),
        "name": asset.get("name", ""),
        "ip": asset.get("ip", ""),
        "extra_ips": list(asset.get("extra_ips", [])),
        "all_ips": all_ips,
        "agent_id": agent_id,
        "labels": list(asset.get("labels", [])),
        "owner": asset.get("owner", ""),
        "case_count": len(matched_cases),
        "open_case_count": open_case_count,
        "case_ids": case_ids,
        "containment_status": containment_status,
        "active_control": active_control,
    }


def get_assets_with_case_counts() -> List[Dict[str, Any]]:
    """Trả về toàn bộ danh sách thiết bị kèm số Case đã phát sinh trên từng thiết bị."""
    with _CASE_LOCK:
        assets = ensure_default_assets()
        cases = list(STATE.get("cases", []))
        nat_map = get_nat_ip_map()
        ep_containment = STATE.get("endpoint_containment", {})
        decisions = list(STATE.get("tactical_decisions", []))
        return [
            _enrich_asset_record(asset, cases, nat_map, ep_containment, decisions=decisions)
            for asset in assets
            if isinstance(asset, dict)
        ]


def upsert_asset(payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], str]:
    """Thêm mới hoặc cập nhật thông tin thiết bị (tên, IP, agent_id, nhãn, chủ sở hữu)."""
    if not isinstance(payload, dict):
        return False, {}, "Dữ liệu thiết bị không hợp lệ."

    name = str(payload.get("name") or "").strip()
    if not name:
        return False, {}, "Thiếu tên thiết bị (name)."

    ip = str(payload.get("ip") or "").strip()
    extra_ips = _normalize_ip_list(payload.get("extra_ips", []), exclude_ip=ip)
    agent_id = str(payload.get("agent_id") or "").strip()
    labels = _normalize_asset_labels(payload.get("labels", []))
    owner = str(payload.get("owner") or "").strip() or "Unassigned"
    req_id = str(payload.get("id") or "").strip()

    with _CASE_LOCK:
        assets = ensure_default_assets()
        existing = next(
            (a for a in assets if isinstance(a, dict) and req_id and a.get("id") == req_id),
            None,
        )
        if existing:
            existing["name"] = name
            existing["ip"] = ip
            existing["extra_ips"] = extra_ips
            existing["agent_id"] = agent_id
            existing["labels"] = labels
            existing["owner"] = owner
            target = existing
            action_verb = "cập nhật"
        else:
            new_id = _next_sequence_id("ASSET", assets)
            target = {
                "id": new_id,
                "name": name,
                "ip": ip,
                "extra_ips": extra_ips,
                "agent_id": agent_id,
                "labels": labels,
                "owner": owner,
            }
            assets.append(target)
            action_verb = "thêm mới"

        if agent_id and agent_id.lower() not in ["000", "unknown", "none", "local"]:
            dismissed = STATE.setdefault("dismissed_asset_agents", [])
            if agent_id in dismissed:
                dismissed.remove(agent_id)
            if ip:
                register_agent_ip(agent_id, ip, agent_name=name)

        save_persistent_state()
        enriched = _enrich_asset_record(
            target,
            list(STATE.get("cases", [])),
            get_nat_ip_map(),
            STATE.get("endpoint_containment", {}),
        )
        log_event("SYSTEM", f"🖥️ Đã {action_verb} thiết bị {target['id']}: {name} (IP: {ip or 'N/A'}, Chủ sở hữu: {owner})")
        return True, enriched, f"Đã {action_verb} thiết bị {target['id']} ({name})."


def delete_asset(asset_id: str) -> Tuple[bool, str]:
    """Xóa thiết bị khỏi danh mục Asset Manager theo mã ASSET-xxxx."""
    clean_id = str(asset_id or "").strip()
    if not clean_id:
        return False, "Thiếu mã thiết bị cần xóa."

    with _CASE_LOCK:
        assets = ensure_default_assets()
        idx = next(
            (i for i, a in enumerate(assets) if isinstance(a, dict) and a.get("id") == clean_id),
            None,
        )
        if idx is None:
            return False, f"Không tìm thấy thiết bị {clean_id}."

        removed = assets.pop(idx)
        removed_aid = str(removed.get("agent_id") or "").strip()
        if removed_aid and removed_aid.lower() not in ["000", "unknown", "none", "local"]:
            dismissed = STATE.setdefault("dismissed_asset_agents", [])
            if removed_aid not in dismissed:
                dismissed.append(removed_aid)
        save_persistent_state()
        log_event("SYSTEM", f"🗑️ Đã xóa thiết bị {clean_id}: {removed.get('name', '')}")
        return True, f"Đã xóa thiết bị {clean_id} ({removed.get('name', '')})."
