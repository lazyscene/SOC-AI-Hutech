import os
import re
import json
import time
import threading
from datetime import datetime
from typing import Optional, Dict, List, Any, Tuple
from web.state import STATE, log_event, save_persistent_state, format_vn_time

CASE_IDLE_TIMEOUT_SECONDS = int(os.getenv("SOC_CASE_IDLE_TIMEOUT", "1800"))     # 30 phút không có alert mới
CASE_MAX_DURATION_SECONDS = int(os.getenv("SOC_CASE_MAX_DURATION", "14400"))   # Trần 4 giờ cho mỗi case
CASE_ANALYZING_TIMEOUT_SECONDS = int(os.getenv("SOC_CASE_ANALYZING_TIMEOUT", "90"))  # Tự mở khóa nếu SLM treo > 90s
LINK_TIME_WINDOW_SECONDS = int(os.getenv("SOC_CASE_LINK_WINDOW", "1800"))      # Cửa sổ liên kết 30 phút Mạng -> Endpoint
SLM_ALERT_MILESTONES = {10, 25, 50}
MAX_INCIDENT_ALERTS_PER_CASE = 200
MAX_STORED_CASES = 100
MAX_STORED_INCIDENTS = 50
COMMON_SERVICE_PORTS = {80, 443, 3000, 3306, 3389, 5000, 5432, 6379, 8000, 8080, 8443, 9000}

VERDICT_RANK = {
    "FALSE POSITIVE": 1,
    "UNKNOWN": 2,
    "SUSPICIOUS": 3,
    "TRUE POSITIVE": 4,
}

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

DEFAULT_AGENT_IP_MAP: Dict[str, List[str]] = {
    "002": ["192.168.214.10"],
    "003": ["192.168.45.10", "192.168.45.17"],
}

DEFAULT_NAT_IP_MAP: Dict[str, List[str]] = {
    "192.168.63.134": ["192.168.214.10"],
}

_CASE_LOCK = threading.RLock()


def _format_ts(ts: float) -> str:
    return format_vn_time(ts)


def _safe_int_port(val: Any) -> int:
    try:
        p = int(str(val).strip())
        return p if 0 < p <= 65535 else 0
    except Exception:
        return 0


def extract_ports_from_alert(data: Optional[Dict[str, Any]] = None, full_log: str = "") -> Tuple[int, int]:
    """Trích xuất (src_port, dest_port) từ JSON alert hoặc từ chuỗi full_log Suricata/filterlog."""
    src_port = 0
    dest_port = 0
    if isinstance(data, dict):
        nested = data.get("data") if isinstance(data.get("data"), dict) else {}
        src_port = (
            _safe_int_port(nested.get("srcport"))
            or _safe_int_port(nested.get("src_port"))
            or _safe_int_port(data.get("srcport"))
            or _safe_int_port(data.get("src_port"))
        )
        dest_port = (
            _safe_int_port(nested.get("dstport"))
            or _safe_int_port(nested.get("dst_port"))
            or _safe_int_port(nested.get("dest_port"))
            or _safe_int_port(data.get("dstport"))
            or _safe_int_port(data.get("dst_port"))
            or _safe_int_port(data.get("dest_port"))
        )

    if (src_port == 0 or dest_port == 0) and full_log:
        m = re.search(
            r'\b\d{1,3}(?:\.\d{1,3}){3}:(\d{1,5})\s*->\s*\d{1,3}(?:\.\d{1,3}){3}:(\d{1,5})\b',
            full_log,
        )
        if m:
            src_port = src_port or _safe_int_port(m.group(1))
            dest_port = dest_port or _safe_int_port(m.group(2))
        elif "filterlog" in full_log:
            after_colon = full_log.split("filterlog", 1)[1]
            if ":" in after_colon:
                csv_part = after_colon.split(":", 1)[1].strip()
                fields = [f.strip() for f in csv_part.split(",")]
                if len(fields) >= 22 and fields[8] == "4" and fields[16].lower() in ("tcp", "udp"):
                    src_port = src_port or _safe_int_port(fields[20])
                    dest_port = dest_port or _safe_int_port(fields[21])
                elif len(fields) >= 19 and fields[8] == "6" and fields[12].lower() in ("tcp", "udp"):
                    src_port = src_port or _safe_int_port(fields[17])
                    dest_port = dest_port or _safe_int_port(fields[18])

    return src_port, dest_port


def is_server_response_flow(
    src_ip: str,
    dest_ip: str,
    src_port: int,
    dest_port: int,
    title: str = "",
    full_log: str = "",
) -> bool:
    """
    Nhận diện linh động gói tin phản hồi từ Server về Client (không hardcode subnet):
    Chỉ coi là gói trả lời khi có bất đối xứng cổng (src_port dịch vụ -> dest_port ephemeral >= 1024)
    VÀ thỏa ngữ cảnh signature phản hồi hoặc dest_ip đang mở Case tấn công vào src_ip.
    """
    clean_src = str(src_ip or "").strip()
    clean_dst = str(dest_ip or "").strip()
    if (
        clean_src.lower() in ["unknown", "none", "n/a", ""]
        or clean_dst.lower() in ["unknown", "none", "n/a", ""]
        or clean_src == clean_dst
    ):
        return False

    is_src_service = (0 < src_port < 1024) or (src_port in COMMON_SERVICE_PORTS)
    is_dst_ephemeral = (dest_port >= 1024) and (dest_port not in COMMON_SERVICE_PORTS)
    if not (is_src_service and is_dst_ephemeral):
        return False

    text = f"{title} {full_log}".lower()
    response_patterns = (
        "web_server 403",
        "web_server 401",
        "web_server 404",
        "web_server 500",
        "attack_response",
        "http response",
        "unable to match response",
    )
    if any(p in text for p in response_patterns):
        return True

    with _CASE_LOCK:
        for c in STATE.get("cases", []):
            if (
                isinstance(c, dict)
                and c.get("status") != "CLOSED"
                and c.get("domain") == "NETWORK"
                and c.get("src_ip") == clean_dst
                and clean_src in (c.get("victim_ips") or [])
            ):
                return True
    return False


def normalize_network_direction(
    src_ip: str,
    dest_ip: str,
    title: str = "",
    full_log: str = "",
    src_port: int = 0,
    dest_port: int = 0,
    data: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str, int, int, bool]:
    """Chuẩn hóa chiều Attacker -> Victim nếu alert bắt trên gói phản hồi từ Server."""
    sp, dp = src_port, dest_port
    if sp == 0 or dp == 0:
        ext_sp, ext_dp = extract_ports_from_alert(data, full_log)
        sp = sp or ext_sp
        dp = dp or ext_dp

    if is_server_response_flow(src_ip, dest_ip, sp, dp, title=title, full_log=full_log):
        return str(dest_ip).strip(), str(src_ip).strip(), dp, sp, True
    return str(src_ip).strip(), str(dest_ip).strip(), sp, dp, False


def _extract_mitre_codes(mitre_items: Any) -> List[str]:
    """Chuẩn hóa danh sách kỹ thuật MITRE về mã ID chuẩn (ví dụ: T1046, T1059.001)."""
    if not mitre_items:
        return []
    if isinstance(mitre_items, str):
        items = [mitre_items]
    elif isinstance(mitre_items, list):
        items = mitre_items
    else:
        return []

    codes: List[str] = []
    for item in items:
        text = str(item or "").strip().upper()
        if not text:
            continue
        found = re.findall(r"T1\d{3}(?:\.\d{3})?", text)
        if found:
            for c in found:
                if c not in codes:
                    codes.append(c)
        elif text not in codes:
            codes.append(text)
    return codes


def get_nat_ip_map() -> Dict[str, List[str]]:
    """Đọc bảng ánh xạ IP NAT/DMZ từ DEFAULT_NAT_IP_MAP và biến môi trường SOC_NAT_IP_MAP."""
    nat_map: Dict[str, List[str]] = {k: list(v) for k, v in DEFAULT_NAT_IP_MAP.items()}
    raw_env = os.getenv("SOC_NAT_IP_MAP", "").strip()
    if not raw_env:
        return nat_map

    if raw_env.startswith("{"):
        try:
            parsed = json.loads(raw_env)
            if isinstance(parsed, dict):
                for ext_ip, int_ips in parsed.items():
                    ext_clean = str(ext_ip).strip()
                    if not ext_clean:
                        continue
                    vals = int_ips if isinstance(int_ips, list) else [int_ips]
                    nat_map[ext_clean] = [str(v).strip() for v in vals if str(v).strip()]
                return nat_map
        except Exception:
            pass

    for pair in raw_env.split(","):
        pair = pair.strip()
        if not pair:
            continue
        sep = "=" if "=" in pair else (":" if ":" in pair else None)
        if not sep:
            continue
        ext_ip, int_ip = [p.strip() for p in pair.split(sep, 1)]
        if ext_ip and int_ip:
            lst = nat_map.setdefault(ext_ip, [])
            if int_ip not in lst:
                lst.append(int_ip)
    return nat_map


def register_agent_ip(agent_id: str, ip: str, agent_name: str = "") -> None:
    """Cập nhật ánh xạ chuẩn hóa agent_id <-> IP vào STATE['agent_ip_registry']."""
    clean_id = str(agent_id or "").strip()
    if not clean_id or clean_id.lower() in ["000", "unknown", "none", "local"]:
        return

    registry = STATE.setdefault("agent_ip_registry", {})
    for def_id, def_ips in DEFAULT_AGENT_IP_MAP.items():
        if def_id not in registry:
            registry[def_id] = list(def_ips)

    ips_for_agent = registry.setdefault(clean_id, list(DEFAULT_AGENT_IP_MAP.get(clean_id, [])))
    clean_ip = str(ip or "").strip()
    if clean_ip and clean_ip.lower() not in ["unknown", "none", "n/a", ""]:
        if clean_ip not in ips_for_agent:
            ips_for_agent.append(clean_ip)


def resolve_agent_ips(agent_id: str) -> List[str]:
    """Trả về toàn bộ IP nội bộ đã biết ứng với agent_id."""
    clean_id = str(agent_id or "").strip()
    if not clean_id or clean_id.lower() in ["000", "unknown", "none", "local"]:
        return []

    resolved: List[str] = []
    for src in (
        STATE.get("agent_ip_registry", {}).get(clean_id, []),
        DEFAULT_AGENT_IP_MAP.get(clean_id, []),
    ):
        for ip in src:
            ip_s = str(ip or "").strip()
            if ip_s and ip_s not in resolved and ip_s.lower() not in ["unknown", "none"]:
                resolved.append(ip_s)

    ep_rec = STATE.get("endpoint_containment", {}).get(clean_id)
    if isinstance(ep_rec, dict):
        v_ip = str(ep_rec.get("victim_ip") or "").strip()
        if v_ip and v_ip not in resolved and v_ip.lower() not in ["unknown", "none"]:
            resolved.append(v_ip)

    return resolved


def is_ip_matching_agent(ip: str, agent_id: str, ep_case: Optional[Dict[str, Any]] = None) -> bool:
    """Kiểm tra một victim_ip (từ cảnh báo mạng/NAT/DMZ) có trùng với agent_id của Endpoint hay không."""
    clean_ip = str(ip or "").strip()
    if not clean_ip or clean_ip.lower() in ["unknown", "none", "n/a", ""]:
        return False

    known_ips = set(resolve_agent_ips(agent_id))
    if ep_case:
        for v in ep_case.get("victim_ips", []):
            if v and str(v).lower() not in ["unknown", "none"]:
                known_ips.add(str(v).strip())

    if clean_ip in known_ips:
        return True

    nat_map = get_nat_ip_map()
    if clean_ip in nat_map:
        if any(mapped in known_ips for mapped in nat_map[clean_ip]):
            return True

    for ext_ip, internal_list in nat_map.items():
        if clean_ip in internal_list and ext_ip in known_ips:
            return True

    return False


def _next_sequence_id(prefix: str, items: List[Dict[str, Any]]) -> str:
    max_num = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id") or "")
        if item_id.startswith(f"{prefix}-"):
            try:
                num = int(item_id.split("-", 1)[1])
                if num > max_num:
                    max_num = num
            except ValueError:
                pass
    return f"{prefix}-{max_num + 1:04d}"


def compute_worst_verdict(verdicts: List[str]) -> str:
    """Tính verdict tổng của Case theo nguyên tắc 'xấu nhất' (TP > SUSPICIOUS > UNKNOWN > FP)."""
    if not verdicts:
        return "UNKNOWN"
    best = "FALSE POSITIVE"
    best_rank = 0
    for v in verdicts:
        norm = str(v or "UNKNOWN").strip().upper()
        rank = VERDICT_RANK.get(norm, 2)
        if rank > best_rank:
            best_rank = rank
            best = norm if norm in VERDICT_RANK else "UNKNOWN"
    return best


def _recompute_case_stats() -> None:
    cases = STATE.get("cases", [])
    STATE["stats"]["total_cases"] = len(cases)
    STATE["stats"]["active_cases"] = sum(
        1 for c in cases if isinstance(c, dict) and c.get("status") != "CLOSED"
    )


def evaluate_and_escalate_severity(case: Dict[str, Any], extra_reason: Optional[str] = None) -> str:
    """Tự động tính và nâng mức độ nghiêm trọng của Case kèm ghi nhận lý do."""
    current = str(case.get("severity", "LOW")).upper()
    current_rank = SEVERITY_RANK.get(current, 1)

    target = current
    reasons = case.setdefault("escalation_reasons", [])

    verdict = str(case.get("verdict", "UNKNOWN")).upper()
    max_level = int(case.get("max_level", 0) or 0)
    mitre_count = len(case.get("seen_mitre_ids", []))
    alert_count = int(case.get("alert_count", 0) or 0)
    has_related = bool(case.get("related_case_ids"))

    candidate = "LOW"
    auto_reason = None

    if has_related:
        candidate = "CRITICAL"
        auto_reason = f"Liên kết chuỗi tấn công liên miền với Case {', '.join(case.get('related_case_ids', []))}"
    elif verdict == "TRUE POSITIVE" and (mitre_count >= 2 or max_level >= 12 or alert_count >= 10):
        candidate = "CRITICAL"
        auto_reason = f"Xác nhận TRUE POSITIVE với mức cảnh báo cao (alerts={alert_count}, MITRE={mitre_count}, level={max_level})"
    elif verdict == "TRUE POSITIVE" or max_level >= 10:
        candidate = "HIGH"
        auto_reason = f"Xác nhận mối đe dọa mức HIGH (verdict={verdict}, level={max_level})"
    elif verdict == "SUSPICIOUS" or max_level >= 7 or alert_count >= 5:
        candidate = "MEDIUM"
        auto_reason = f"Hoạt động đáng ngờ gia tăng (alerts={alert_count}, level={max_level})"

    if SEVERITY_RANK.get(candidate, 1) > current_rank:
        target = candidate
        case["severity"] = target
        reason_msg = extra_reason or auto_reason
        if reason_msg and reason_msg not in reasons:
            reasons.append(f"[{_format_ts(time.time())}] {current} -> {target}: {reason_msg}")
    elif extra_reason and extra_reason not in reasons:
        reasons.append(f"[{_format_ts(time.time())}] Giữ mức {current}: {extra_reason}")

    return case["severity"]


def close_expired_cases(now_ts: Optional[float] = None) -> int:
    """Đóng các Case vượt quá Idle timeout (30 phút) hoặc Trần thời lượng (4 giờ)."""
    ts = now_ts if now_ts is not None else time.time()
    closed_count = 0
    with _CASE_LOCK:
        for c in STATE.get("cases", []):
            if not isinstance(c, dict) or c.get("status") == "CLOSED":
                continue
            last_ts = float(c.get("last_alert_ts", ts) or ts)
            created_ts = float(c.get("created_at_ts", ts) or ts)

            if (ts - last_ts) >= CASE_IDLE_TIMEOUT_SECONDS:
                c["status"] = "CLOSED"
                c["is_analyzing"] = False
                c["closed_at"] = _format_ts(ts)
                c["close_reason"] = "Idle timeout (30 phút không có cảnh báo mới)"
                closed_count += 1
            elif (ts - created_ts) >= CASE_MAX_DURATION_SECONDS:
                c["status"] = "CLOSED"
                c["is_analyzing"] = False
                c["closed_at"] = _format_ts(ts)
                c["close_reason"] = "Đạt trần thời lượng tối đa (4 giờ)"
                closed_count += 1
        if closed_count > 0:
            _recompute_case_stats()
    return closed_count


def _determine_domain_and_key(alert_summary: Dict[str, Any]) -> Tuple[str, str, str, str, str]:
    src_ip = str(alert_summary.get("src_ip") or "unknown").strip()
    agent_id = str(alert_summary.get("agent_id") or "000").strip()
    agent_ip = str(alert_summary.get("agent_ip") or "unknown").strip()
    victim_ip = str(alert_summary.get("victim_ip") or "unknown").strip()
    file_path = alert_summary.get("file_path")
    source_str = str(alert_summary.get("source") or "").lower()
    rule_id = str(alert_summary.get("rule_id") or "")

    is_fim = (
        "syscheck" in source_str
        or bool(file_path)
        or rule_id in ["550", "553", "554", "750"]
    )
    has_valid_src = src_ip.lower() not in ["unknown", "none", "n/a", ""]

    if is_fim or not has_valid_src:
        domain = "ENDPOINT"
        if agent_id and agent_id.lower() not in ["000", "unknown", "none", ""]:
            corr_key = f"EP:{agent_id}"
        else:
            host_key = victim_ip if victim_ip.lower() not in ["unknown", "none", ""] else agent_ip
            corr_key = f"EP_IP:{host_key}"
    else:
        domain = "NETWORK"
        corr_key = f"NET:{src_ip}"

    return domain, corr_key, src_ip, agent_id, victim_ip


def _build_audit_alert_record(alert_summary: Dict[str, Any], ts: float) -> Dict[str, Any]:
    """Chuẩn hóa bản ghi alert gốc lưu vào incident_alerts để kiểm toán và replay."""
    record = dict(alert_summary)
    record.setdefault("captured_at", _format_ts(ts))
    record["captured_at_ts"] = ts
    return record


def ingest_alert_into_case(alert_summary: Dict[str, Any], now_ts: Optional[float] = None) -> Dict[str, Any]:
    """
    Gom cảnh báo mới vào Case phù hợp theo miền (NETWORK theo src_ip, ENDPOINT theo agent_id)
    và quyết định có cần gọi SLM hay chỉ gộp timeline & tăng bộ đếm.
    """
    ts = now_ts if now_ts is not None else time.time()

    with _CASE_LOCK:
        close_expired_cases(ts)
        cases = STATE.setdefault("cases", [])

        normalized_alert = dict(alert_summary)
        domain, corr_key, src_ip, agent_id, victim_ip = _determine_domain_and_key(normalized_alert)
        if domain == "NETWORK":
            raw_dest = str(normalized_alert.get("dest_ip") or normalized_alert.get("victim_ip") or "unknown").strip()
            norm_src, norm_dst, _, _, swapped = normalize_network_direction(
                src_ip,
                raw_dest,
                title=str(normalized_alert.get("title") or ""),
                full_log=str(normalized_alert.get("full_log") or ""),
                src_port=_safe_int_port(normalized_alert.get("src_port")),
                dest_port=_safe_int_port(normalized_alert.get("dest_port")),
                data=normalized_alert,
            )
            if swapped:
                src_ip = norm_src
                victim_ip = norm_dst
                corr_key = f"NET:{norm_src}"
                normalized_alert["src_ip"] = norm_src
                normalized_alert["dest_ip"] = norm_dst
                normalized_alert["victim_ip"] = norm_dst

        agent_name = str(normalized_alert.get("agent") or "unknown").strip()
        agent_ip = str(normalized_alert.get("agent_ip") or "unknown").strip()

        # Đăng ký ánh xạ agent_id <-> IP vào registry toàn cục
        ep_ip_to_register = agent_ip if agent_ip.lower() not in ["unknown", "none", ""] else victim_ip
        if agent_id not in ["000", "unknown", "none", ""]:
            register_agent_ip(agent_id, ep_ip_to_register, agent_name)
        from core.asset_manager import ensure_default_assets
        ensure_default_assets()

        rule_id = str(alert_summary.get("rule_id") or "").strip()
        level = int(alert_summary.get("level", 0) or 0)
        primary_hash = str(alert_summary.get("primary_hash") or "").strip().lower()
        encoded_payload = str(alert_summary.get("encoded_payload") or "").strip()
        mitre_codes = _extract_mitre_codes(alert_summary.get("mitre") or alert_summary.get("mitre_ids"))

        # Tìm case OPEN đang hoạt động hoặc case FP đã đóng gần nhất cùng khóa
        active_case = None
        last_fp_case = None
        for c in cases:
            if not isinstance(c, dict) or c.get("correlation_key") != corr_key:
                continue
            if c.get("status") != "CLOSED":
                active_case = c
                break
            if str(c.get("verdict", "")).upper() == "FALSE POSITIVE" and last_fp_case is None:
                last_fp_case = c

        is_new_case = False
        reopen_note = None
        previous_fp_id = None

        # Kiểm tra quy tắc Case FP: Không âm thầm gộp alert bất thường mới vào Case FP
        if active_case and str(active_case.get("verdict", "")).upper() == "FALSE POSITIVE":
            is_new_rule = bool(rule_id and rule_id not in active_case.get("seen_rule_ids", []))
            is_new_mitre = any(m not in active_case.get("seen_mitre_ids", []) for m in mitre_codes)
            is_new_hash = bool(primary_hash and primary_hash not in active_case.get("seen_hashes", []))
            is_anomalous_level = level >= 6 or level > int(active_case.get("max_level", 0) or 0)
            if is_new_rule or is_new_mitre or is_new_hash or is_anomalous_level:
                active_case["status"] = "CLOSED"
                active_case["is_analyzing"] = False
                active_case["closed_at"] = _format_ts(ts)
                active_case["close_reason"] = "Tách Case mới do xuất hiện cảnh báo bất thường mới sau phán quyết FALSE POSITIVE"
                previous_fp_id = active_case["id"]
                reopen_note = f"Tách từ Case FP cũ {previous_fp_id} do xuất hiện cảnh báo bất thường mới"
                active_case = None

        if active_case is None and last_fp_case is not None:
            previous_fp_id = last_fp_case["id"]
            reopen_note = f"Tạo Case mới (Case trước {previous_fp_id} đã đóng với verdict FALSE POSITIVE)"

        if active_case is None:
            is_new_case = True
            case_id = _next_sequence_id("CASE", cases)
            initial_victims = []
            for vip in [victim_ip, alert_summary.get("dest_ip"), agent_ip]:
                vip_s = str(vip or "").strip()
                if vip_s and vip_s.lower() not in ["unknown", "none", "n/a", ""] and vip_s not in initial_victims:
                    initial_victims.append(vip_s)

            # Bổ sung danh sách IP đã biết của agent nếu là Endpoint case
            if domain == "ENDPOINT" and agent_id not in ["000", "unknown", "none", ""]:
                for known_ip in resolve_agent_ips(agent_id):
                    if known_ip not in initial_victims:
                        initial_victims.append(known_ip)

            case_title = (
                f"[{domain}] Hoạt động tấn công từ {src_ip}"
                if domain == "NETWORK"
                else f"[{domain}] Sự cố trên Agent {agent_id} ({agent_name or victim_ip})"
            )

            active_case = {
                "id": case_id,
                "domain": domain,
                "correlation_key": corr_key,
                "src_ip": src_ip if domain == "NETWORK" else "unknown",
                "agent_id": agent_id,
                "agent_name": agent_name,
                "victim_ips": initial_victims,
                "title": case_title,
                "status": "OPEN",
                "verdict": "UNKNOWN",
                "verdict_history": [],
                "severity": "HIGH" if level >= 10 else ("MEDIUM" if level >= 7 else "LOW"),
                "escalation_reasons": [f"[{_format_ts(ts)}] {reopen_note}"] if reopen_note else [],
                "alert_count": 0,
                "slm_calls": 0,
                "is_analyzing": False,
                "max_level": level,
                "seen_rule_ids": [],
                "seen_mitre_ids": [],
                "seen_hashes": [],
                "seen_payloads": [],
                "mitre_tags": [],
                "ti_summary": None,
                "actions_taken": [],
                "summary": "",
                "related_case_ids": [],
                "parent_incident_id": None,
                "reopened_from_case_id": previous_fp_id,
                "incident_alerts": [],
                "created_at": _format_ts(ts),
                "updated_at": _format_ts(ts),
                "created_at_ts": ts,
                "last_alert_ts": ts,
                "closed_at": None,
                "close_reason": None,
            }
            cases.insert(0, active_case)
            if len(cases) > MAX_STORED_CASES:
                del cases[MAX_STORED_CASES:]

            log_event("CASE", f"🗂️ Khởi tạo {case_id} ({domain}) cho khóa '{corr_key}' — Alert đầu tiên: {alert_summary.get('title')}")

        # Kiểm tra tình tiết mới trước khi cập nhật seen_*
        seen_rules = active_case.setdefault("seen_rule_ids", [])
        seen_mitres = active_case.setdefault("seen_mitre_ids", [])
        seen_hashes = active_case.setdefault("seen_hashes", [])
        seen_payloads = active_case.setdefault("seen_payloads", [])

        has_new_rule = bool(rule_id and rule_id not in seen_rules)
        has_new_mitre = any(m not in seen_mitres for m in mitre_codes)
        has_new_hash = bool(primary_hash and primary_hash not in seen_hashes)
        has_new_payload = bool(encoded_payload and encoded_payload not in seen_payloads)
        has_higher_level = level > int(active_case.get("max_level", 0) or 0)

        # Cập nhật dữ liệu gom nhóm
        active_case["alert_count"] = int(active_case.get("alert_count", 0)) + 1
        active_case["last_alert_ts"] = ts
        active_case["updated_at"] = _format_ts(ts)
        if level > int(active_case.get("max_level", 0) or 0):
            active_case["max_level"] = level

        for vip in [victim_ip, alert_summary.get("dest_ip"), agent_ip]:
            vip_s = str(vip or "").strip()
            if vip_s and vip_s.lower() not in ["unknown", "none", "n/a", ""] and vip_s not in active_case["victim_ips"]:
                active_case["victim_ips"].append(vip_s)

        if rule_id and rule_id not in seen_rules:
            seen_rules.append(rule_id)
        for m in mitre_codes:
            if m not in seen_mitres:
                seen_mitres.append(m)
        if primary_hash and primary_hash not in seen_hashes:
            seen_hashes.append(primary_hash)
        if encoded_payload and encoded_payload not in seen_payloads:
            seen_payloads.append(encoded_payload)

        # Lưu alert gốc vào incident_alerts
        audit_rec = _build_audit_alert_record(normalized_alert, ts)
        inc_alerts = active_case.setdefault("incident_alerts", [])
        inc_alerts.append(audit_rec)
        if len(inc_alerts) > MAX_INCIDENT_ALERTS_PER_CASE:
            inc_alerts.pop(0)

        # Tự mở khóa nếu luồng SLM trước đó bị treo quá ngưỡng thời gian
        if active_case.get("is_analyzing"):
            analyzing_since = float(active_case.get("analyzing_since_ts", 0) or 0)
            if analyzing_since <= 0 or (ts - analyzing_since) >= CASE_ANALYZING_TIMEOUT_SECONDS:
                active_case["is_analyzing"] = False
                active_case.pop("analyzing_since_ts", None)

        novelty_reasons = []
        if has_new_rule:
            novelty_reasons.append(f"Rule mới ({rule_id})")
        if has_new_mitre:
            novelty_reasons.append(f"MITRE mới ({','.join(mitre_codes)})")
        if has_new_hash:
            novelty_reasons.append(f"Hash mới ({primary_hash[:12]}...)")
        if has_new_payload:
            novelty_reasons.append("Payload mã hóa mới")
        if has_higher_level:
            novelty_reasons.append(f"Mức độ tăng lên level {level}")

        # Quyết định gọi SLM (Qwen) - Chống kẹt SLM: 0 và không nuốt tình tiết mới
        should_call_slm = False
        slm_reason = "Alert trùng lặp cùng loại — chỉ tăng bộ đếm"
        pending_reason = active_case.get("pending_slm_reason")
        has_zero_slm = int(active_case.get("slm_calls", 0) or 0) == 0

        if is_new_case:
            should_call_slm = True
            slm_reason = "Alert đầu tiên mở Case"
            active_case.pop("pending_slm_reason", None)
        elif active_case.get("is_analyzing"):
            should_call_slm = False
            if novelty_reasons:
                active_case["pending_slm_reason"] = "Tình tiết mới: " + ", ".join(novelty_reasons)
            slm_reason = "Case đang được SLM phân tích ở luồng khác — gộp vào timeline"
        elif has_zero_slm:
            should_call_slm = True
            slm_reason = pending_reason or "Case chưa có kết quả SLM — kích hoạt phân tích bù"
            active_case.pop("pending_slm_reason", None)
        elif novelty_reasons:
            should_call_slm = True
            slm_reason = "Tình tiết mới: " + ", ".join(novelty_reasons)
            active_case.pop("pending_slm_reason", None)
        elif pending_reason:
            should_call_slm = True
            slm_reason = pending_reason
            active_case.pop("pending_slm_reason", None)
        elif (
            active_case["alert_count"] in SLM_ALERT_MILESTONES
            and str(active_case.get("verdict", "")).upper() != "TRUE POSITIVE"
        ):
            should_call_slm = True
            slm_reason = f"Đạt ngưỡng kiểm tra {active_case['alert_count']} alerts"

        evaluate_and_escalate_severity(active_case)
        _recompute_case_stats()

        return {
            "case": active_case,
            "is_new_case": is_new_case,
            "should_call_slm": should_call_slm,
            "reason": slm_reason,
        }


def _is_attack_network_case(net_case: Dict[str, Any]) -> bool:
    mitre_text = " ".join(net_case.get("seen_mitre_ids", []) + net_case.get("mitre_tags", [])).upper()
    if any(code in mitre_text for code in ["T1046", "T1190", "T1110", "T1210", "T1595", "T1059"]):
        return True
    if str(net_case.get("verdict", "")).upper() in ["TRUE POSITIVE", "SUSPICIOUS"]:
        return True
    if int(net_case.get("max_level", 0) or 0) >= 6:
        return True

    text_blob = (
        str(net_case.get("title", "")) + " " +
        " ".join(str(a.get("title", "")) for a in net_case.get("incident_alerts", [])[:5])
    ).lower()
    return any(k in text_blob for k in ["scan", "nmap", "exploit", "rce", "brute", "attack", "sqli", "web"])


def _is_suspicious_endpoint_case(ep_case: Dict[str, Any]) -> bool:
    if ep_case.get("seen_hashes"):
        return True
    mitre_text = " ".join(ep_case.get("seen_mitre_ids", []) + ep_case.get("mitre_tags", [])).upper()
    if any(code in mitre_text for code in ["T1059", "T1021", "T1570", "T1053", "T1505", "T1105"]):
        return True

    for a in ep_case.get("incident_alerts", []):
        if a.get("file_path") or a.get("process_name") or a.get("process_id"):
            return True
        if a.get("event_type") in ["added", "modified"]:
            return True
        src_title = (str(a.get("source", "")) + " " + str(a.get("title", ""))).lower()
        if any(k in src_title for k in ["syscheck", "sysmon", "auditd", "powershell", "shell", "eicar", "malware"]):
            return True
    return False


def correlate_cross_domain_cases(now_ts: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    Liên kết Case Mạng và Case Endpoint thành Related Cases & Incident Cha khi thỏa cả 3 điều kiện:
    1. victim_ip của Case Mạng trùng với IP của agent trong Case Endpoint (có kiểm tra NAT/DMZ).
    2. Case Endpoint bắt đầu sau (hoặc cùng thời điểm) Case Mạng trong vòng 30 phút.
    3. Chuỗi hành vi Kill-Chain hợp lý (Mạng rà quét/khai thác -> Endpoint rơi file/thực thi tiến trình).
    """
    ts = now_ts if now_ts is not None else time.time()
    linked_incidents: List[Dict[str, Any]] = []

    with _CASE_LOCK:
        cases = STATE.get("cases", [])
        parent_incidents = STATE.setdefault("parent_incidents", [])

        net_cases = [c for c in cases if isinstance(c, dict) and c.get("domain") == "NETWORK"]
        ep_cases = [c for c in cases if isinstance(c, dict) and c.get("domain") == "ENDPOINT"]

        for net_c in net_cases:
            if not _is_attack_network_case(net_c):
                continue
            net_victims = [str(v).strip() for v in net_c.get("victim_ips", []) if v and str(v).lower() not in ["unknown", "none"]]
            if not net_victims:
                continue

            for ep_c in ep_cases:
                if not _is_suspicious_endpoint_case(ep_c):
                    continue

                ep_agent = str(ep_c.get("agent_id") or "").strip()
                net_start = float(net_c.get("created_at_ts", 0) or 0)
                ep_start = float(ep_c.get("created_at_ts", 0) or 0)

                # Điều kiện 2: Case Endpoint bắt đầu sau Case Mạng và trong vòng 30 phút
                delta = ep_start - net_start
                if delta < 0 or delta > LINK_TIME_WINDOW_SECONDS:
                    continue

                # Điều kiện 1: Kiểm tra khớp IP nạn nhân với Agent Endpoint (bao gồm NAT/DMZ)
                matched_ip = None
                for nv in net_victims:
                    if is_ip_matching_agent(nv, ep_agent, ep_c) or nv in ep_c.get("victim_ips", []):
                        matched_ip = nv
                        break
                if not matched_ip:
                    continue

                # Ghi nhận quan hệ Related Cases giữa hai Case con
                if ep_c["id"] not in net_c.setdefault("related_case_ids", []):
                    net_c["related_case_ids"].append(ep_c["id"])
                if net_c["id"] not in ep_c.setdefault("related_case_ids", []):
                    ep_c["related_case_ids"].append(net_c["id"])

                # Tự nâng Severity lên CRITICAL cho cả 2 Case con kèm lý do
                evaluate_and_escalate_severity(
                    net_c,
                    extra_reason=f"Liên kết Kill-Chain với Case Endpoint {ep_c['id']} trên nạn nhân {matched_ip}"
                )
                evaluate_and_escalate_severity(
                    ep_c,
                    extra_reason=f"Liên kết Kill-Chain sau Case Mạng {net_c['id']} (Attacker {net_c.get('src_ip')} -> {matched_ip})"
                )

                # Tìm hoặc tạo Incident Cha (INC-xxxx)
                existing_inc = None
                for inc in parent_incidents:
                    if net_c["id"] in inc.get("child_case_ids", []) or ep_c["id"] in inc.get("child_case_ids", []):
                        existing_inc = inc
                        break

                if existing_inc is None:
                    inc_id = _next_sequence_id("INC", parent_incidents)
                    existing_inc = {
                        "id": inc_id,
                        "title": f"Chuỗi tấn công đa miền: {net_c.get('src_ip')} ➔ {matched_ip} (Agent {ep_agent})",
                        "severity": "CRITICAL",
                        "status": "OPEN",
                        "attacker_ips": [net_c.get("src_ip")] if net_c.get("src_ip") != "unknown" else [],
                        "victim_ips": [matched_ip],
                        "child_case_ids": [net_c["id"], ep_c["id"]],
                        "kill_chain_summary": f"Network Attack ({net_c['id']}) ➔ Endpoint Impact ({ep_c['id']})",
                        "combined_timeline": [],
                        "escalation_reasons": [
                            f"Tự động hợp nhất từ {net_c['id']} (NETWORK) và {ep_c['id']} (ENDPOINT) trong cửa sổ {int(delta)}s trên host {matched_ip}"
                        ],
                        "created_at": _format_ts(ts),
                        "updated_at": _format_ts(ts),
                    }
                    parent_incidents.insert(0, existing_inc)
                    if len(parent_incidents) > MAX_STORED_INCIDENTS:
                        del parent_incidents[MAX_STORED_INCIDENTS:]
                    log_event("CASE", f"🔗 Tạo Incident Cha {inc_id}: Liên kết {net_c['id']} (Mạng: {net_c.get('src_ip')}) ↔ {ep_c['id']} (Endpoint Agent {ep_agent}: {matched_ip}) — Nâng mức CRITICAL!")
                else:
                    if net_c["id"] not in existing_inc["child_case_ids"]:
                        existing_inc["child_case_ids"].append(net_c["id"])
                    if ep_c["id"] not in existing_inc["child_case_ids"]:
                        existing_inc["child_case_ids"].append(ep_c["id"])
                    if matched_ip not in existing_inc["victim_ips"]:
                        existing_inc["victim_ips"].append(matched_ip)
                    existing_inc["severity"] = "CRITICAL"
                    existing_inc["updated_at"] = _format_ts(ts)

                net_c["parent_incident_id"] = existing_inc["id"]
                ep_c["parent_incident_id"] = existing_inc["id"]

                # Gộp timeline từ tất cả Case con sắp xếp theo captured_at_ts
                combined = []
                for cid in existing_inc["child_case_ids"]:
                    child_obj = get_case_by_id(cid)
                    if not child_obj:
                        continue
                    for a in child_obj.get("incident_alerts", []):
                        combined.append({
                            "case_id": cid,
                            "domain": child_obj.get("domain"),
                            "time": a.get("captured_at") or child_obj.get("updated_at"),
                            "ts": float(a.get("captured_at_ts", 0) or 0),
                            "title": a.get("title", ""),
                            "rule_id": a.get("rule_id", ""),
                            "level": a.get("level", 0),
                            "src_ip": a.get("src_ip", "unknown"),
                            "victim_ip": a.get("victim_ip", "unknown"),
                            "file_path": a.get("file_path"),
                        })
                combined.sort(key=lambda item: item["ts"])
                existing_inc["combined_timeline"] = combined[-100:]
                linked_incidents.append(existing_inc)

        return linked_incidents


def finalize_case_analysis(
    case_id: str,
    verdict: str,
    mitre_tags: Optional[List[str]] = None,
    ti_summary: Optional[str] = None,
    summary_text: str = "",
    has_blocked_ip: bool = False,
    endpoint_response: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Cập nhật kết quả phân tích SLM vào Case theo quy tắc Worst-Verdict và tự liên kết Kill-Chain."""
    with _CASE_LOCK:
        case = get_case_by_id(case_id)
        if not case:
            return None

        now_ts = time.time()
        case["is_analyzing"] = False
        case.pop("analyzing_since_ts", None)
        case["slm_calls"] = int(case.get("slm_calls", 0)) + 1
        case["updated_at"] = _format_ts(now_ts)

        norm_verdict = str(verdict or "UNKNOWN").strip().upper()
        case.setdefault("verdict_history", []).append(norm_verdict)
        case["verdict"] = compute_worst_verdict(case["verdict_history"])

        if mitre_tags:
            existing_mitre = case.setdefault("mitre_tags", [])
            for tag in mitre_tags:
                if tag and tag not in existing_mitre:
                    existing_mitre.append(tag)
            for code in _extract_mitre_codes(mitre_tags):
                if code not in case.setdefault("seen_mitre_ids", []):
                    case["seen_mitre_ids"].append(code)

        if ti_summary:
            case["ti_summary"] = ti_summary

        if summary_text:
            case["summary"] = summary_text

        actions = case.setdefault("actions_taken", [])
        if has_blocked_ip and case.get("src_ip") and case["src_ip"] != "unknown":
            act_str = f"pfSense Block IP {case['src_ip']}"
            if act_str not in actions:
                actions.append(act_str)
        if endpoint_response and endpoint_response not in actions:
            actions.append(endpoint_response)

        evaluate_and_escalate_severity(case)
        correlate_cross_domain_cases(now_ts)
        from core.contingency_room import sync_case_decisions

        sync_case_decisions(case)
        _recompute_case_stats()
        save_persistent_state()
        return case


def get_case_by_id(case_id: str) -> Optional[Dict[str, Any]]:
    for c in STATE.get("cases", []):
        if isinstance(c, dict) and c.get("id") == case_id:
            return c
    return None


def update_case_status(case_id: str, new_status: str, reason: str = "") -> Tuple[bool, Optional[Dict[str, Any]], str]:
    clean_status = str(new_status or "").strip().upper()
    if clean_status not in ["OPEN", "CLOSED"]:
        return False, None, f"Trạng thái không hợp lệ: '{new_status}'. Chỉ hỗ trợ OPEN hoặc CLOSED."

    with _CASE_LOCK:
        case = get_case_by_id(case_id)
        if not case:
            return False, None, f"Không tìm thấy Case {case_id}."

        now_ts = time.time()
        case["status"] = clean_status
        case["updated_at"] = _format_ts(now_ts)
        if clean_status == "CLOSED":
            case["is_analyzing"] = False
            case["closed_at"] = _format_ts(now_ts)
            case["close_reason"] = reason or "Người vận hành SOC đóng thủ công"
            log_event("CASE", f"🔒 Đã đóng Case {case_id}: {case['close_reason']}")
        else:
            case["closed_at"] = None
            case["close_reason"] = None
            case["last_alert_ts"] = now_ts
            note = reason or "Mở lại Case thủ công"
            case.setdefault("escalation_reasons", []).append(f"[{_format_ts(now_ts)}] REOPEN: {note}")
            log_event("CASE", f"🔓 Đã mở lại Case {case_id}: {note}")

        _recompute_case_stats()
        save_persistent_state()
        return True, case, f"Đã cập nhật trạng thái {case_id} thành {clean_status}."


def build_and_save_case_graph(case_id: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Dựng Sơ đồ trực quan (Attack Path Graph) cho một Case theo yêu cầu (On-Demand)
    và lưu bền vững vào case['attack_graph'] để không phải vẽ lại real-time.
    """
    with _CASE_LOCK:
        case = get_case_by_id(case_id)
        if not case:
            return False, None, f"Không tìm thấy Case {case_id}."

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, str]] = []
        node_ids = set()
        edge_keys = set()

        def add_node(nid: str, col: int, ntype: str, label: str, sublabel: str = "") -> str:
            if nid not in node_ids:
                node_ids.add(nid)
                nodes.append({
                    "id": nid,
                    "col": col,
                    "type": ntype,
                    "label": str(label)[:42],
                    "sublabel": str(sublabel)[:54],
                })
            return nid

        def add_edge(src: str, dst: str, label: str = "") -> None:
            key = (src, dst, label)
            if src in node_ids and dst in node_ids and key not in edge_keys:
                edge_keys.add(key)
                edges.append({"source": src, "target": dst, "label": label[:26]})

        domain = case.get("domain", "NETWORK")
        src_ip = str(case.get("src_ip") or "unknown").strip()
        agent_id = str(case.get("agent_id") or "000").strip()
        agent_name = str(case.get("agent_name") or "").strip()
        related_ids = list(case.get("related_case_ids", []))
        parent_inc_id = case.get("parent_incident_id")
        inc_alerts = list(case.get("incident_alerts", []))

        # Lớp 0: Nguồn tấn công / Khởi phát
        col0_ids: List[str] = []
        linked_attacker_ip = None
        if src_ip.lower() not in ["unknown", "none", "n/a", ""]:
            linked_attacker_ip = src_ip
            col0_ids.append(add_node(f"ip:{src_ip}", 0, "attacker", src_ip, "Attacker Source IP"))
        else:
            for rel_id in related_ids:
                rel_case = get_case_by_id(rel_id)
                if rel_case and str(rel_case.get("src_ip", "unknown")).lower() not in ["unknown", "none", ""]:
                    rel_src = str(rel_case["src_ip"]).strip()
                    linked_attacker_ip = rel_src
                    col0_ids.append(add_node(f"ip:{rel_src}", 0, "attacker", rel_src, f"Attacker (Linked {rel_id})"))
            if not col0_ids:
                first_src = inc_alerts[0].get("src_ip") if inc_alerts else None
                src_label = inc_alerts[0].get("source", "Wazuh FIM/EDR") if inc_alerts else "Wazuh Endpoint"
                col0_ids.append(add_node(f"trigger:{case_id}", 0, "trigger", "Endpoint Event", str(first_src if first_src not in ["unknown", None, ""] else src_label)))

        # Lớp 1: Kỹ thuật MITRE ATT&CK / Vector tấn công
        col1_ids: List[str] = []
        mitre_sources = list(case.get("mitre_tags") or case.get("seen_mitre_ids") or [])
        for m_item in mitre_sources[:4]:
            m_str = str(m_item).strip()
            codes = _extract_mitre_codes(m_str)
            m_code = codes[0] if codes else m_str
            col1_ids.append(add_node(f"mitre:{m_code}", 1, "vector", m_code, m_str))

        if not col1_ids:
            seen_rules: List[str] = []
            for a in inc_alerts:
                rid = str(a.get("rule_id") or "?").strip()
                if rid not in seen_rules:
                    seen_rules.append(rid)
                    col1_ids.append(add_node(f"rule:{rid}", 1, "vector", f"Rule {rid}", str(a.get("title") or "Security Alert")))
                if len(seen_rules) >= 3:
                    break
            if not col1_ids:
                col1_ids.append(add_node(f"rule:case:{case_id}", 1, "vector", "Alert Vector", case.get("title", "")))

        edge_count_lbl = f"{case.get('alert_count', len(inc_alerts))} alerts"
        for s_id in col0_ids:
            for v_id in col1_ids:
                add_edge(s_id, v_id, edge_count_lbl)

        # Lớp 2: Máy đích / Endpoint bị ảnh hưởng + Related Case
        col2_target_ids: List[str] = []
        victims = [str(v).strip() for v in case.get("victim_ips", []) if v and str(v).lower() not in ["unknown", "none", "n/a"]]
        for vip in victims[:4]:
            sub = f"Agent {agent_id} ({agent_name or 'Endpoint'})" if (domain == "ENDPOINT" and agent_id not in ["000", "unknown", ""]) else "Victim Target Host"
            col2_target_ids.append(add_node(f"host:{vip}", 2, "target", vip, sub))

        if not col2_target_ids:
            ep_lbl = f"Agent {agent_id}" if agent_id not in ["000", "unknown", ""] else "Protected Host"
            col2_target_ids.append(add_node(f"agent:{agent_id}", 2, "target", ep_lbl, agent_name or "Victim Endpoint"))

        target_edge_lbl = "Compromises" if domain == "ENDPOINT" else "Targets"
        for v_id in col1_ids:
            for t_id in col2_target_ids:
                add_edge(v_id, t_id, target_edge_lbl)

        for rel_id in related_ids[:3]:
            rel_node_id = add_node(
                f"rel:{rel_id}",
                2,
                "related_case",
                f"Related {rel_id}",
                f"Parent: {parent_inc_id}" if parent_inc_id else "Kill-Chain Link",
            )
            for t_id in col2_target_ids[:1]:
                add_edge(t_id, rel_node_id, "Kill-Chain")

        # Lớp 3: Artifacts (File, Hash/TI, Process)
        col3_ids: List[str] = []
        seen_files, seen_procs = set(), set()
        primary_target = col2_target_ids[0]

        for a in inc_alerts:
            fp = str(a.get("file_path") or "").strip()
            if fp and fp not in seen_files and len(seen_files) < 3:
                seen_files.add(fp)
                short_name = os.path.basename(fp) or fp
                f_nid = add_node(f"file:{fp}", 3, "artifact_file", short_name, fp)
                col3_ids.append(f_nid)
                add_edge(primary_target, f_nid, str(a.get("event_type") or "File Impact"))

            proc = str(a.get("process_name") or "").strip()
            pid = str(a.get("process_id") or "").strip()
            if (proc or pid) and (proc, pid) not in seen_procs and len(seen_procs) < 3:
                seen_procs.add((proc, pid))
                p_lbl = os.path.basename(proc) if proc else f"PID {pid}"
                p_nid = add_node(f"proc:{proc}:{pid}", 3, "artifact_proc", f"Proc: {p_lbl}", f"PID: {pid or 'N/A'}")
                col3_ids.append(p_nid)
                add_edge(primary_target, p_nid, "Executes")

        ti_text = str(case.get("ti_summary") or "").strip()
        for h in list(case.get("seen_hashes", []))[:2]:
            h_nid = add_node(f"hash:{h}", 3, "artifact_hash", f"Hash: {h[:12]}...", ti_text or "File Hash IOC")
            col3_ids.append(h_nid)
            add_edge(primary_target, h_nid, "IOC Check")

        # Lớp 4: Hành động phòng vệ SOAR (pfSense Firewall & Wazuh AR)
        col4_ids: List[str] = []
        blocked_ips = STATE.get("stats", {}).get("blocked_ips", [])
        actions_text = " ".join(str(x) for x in case.get("actions_taken", []))

        check_block_ip = linked_attacker_ip or (src_ip if src_ip not in ["unknown", "none", ""] else None)
        if check_block_ip and (check_block_ip in blocked_ips or "pfSense Block" in actions_text):
            pf_nid = add_node(f"soar:pfsense:{check_block_ip}", 4, "soar_action", "pfSense Firewall", f"BLOCKED {check_block_ip}")
            col4_ids.append(pf_nid)
            anchor = col0_ids[0] if not col3_ids else col3_ids[0]
            add_edge(primary_target if primary_target else anchor, pf_nid, "SOAR Block")

        ep_rec = STATE.get("endpoint_containment", {}).get(agent_id)
        if isinstance(ep_rec, dict) or "Wazuh" in actions_text or "Phase 1" in actions_text or "Phase 2" in actions_text:
            iso_status = ep_rec.get("isolation_status", "CONTAINED") if isinstance(ep_rec, dict) else "CONTAINED"
            wz_nid = add_node(f"soar:wazuh:{agent_id}", 4, "soar_action", f"Wazuh AR ({agent_id})", iso_status)
            col4_ids.append(wz_nid)
            source_for_wz = col3_ids[0] if col3_ids else primary_target
            add_edge(source_for_wz, wz_nid, "Endpoint Contain")

        src_desc = linked_attacker_ip or "Endpoint Event"
        vec_desc = ", ".join(n["label"] for n in nodes if n["col"] == 1)[:60] or "Alert"
        tgt_desc = ", ".join(n["label"] for n in nodes if n["type"] == "target")[:60] or "Host"
        art_desc = ", ".join(n["label"] for n in nodes if n["col"] == 3)[:60]
        soar_desc = ", ".join(f"{n['label']} ({n['sublabel']})" for n in nodes if n["col"] == 4)[:80]

        path_parts = [f"Nguồn: {src_desc}", f"Kỹ thuật: {vec_desc}", f"Đích: {tgt_desc}"]
        if art_desc:
            path_parts.append(f"Thực thể: {art_desc}")
        if soar_desc:
            path_parts.append(f"Phản ứng SOAR: {soar_desc}")
        attack_path_summary = " ➔ ".join(path_parts)

        now_ts = time.time()
        graph_data = {
            "case_id": case_id,
            "generated_at": _format_ts(now_ts),
            "generated_at_alert_count": int(case.get("alert_count", 0) or 0),
            "nodes": nodes,
            "edges": edges,
            "attack_path_summary": attack_path_summary,
        }
        case["attack_graph"] = graph_data
        case["updated_at"] = _format_ts(now_ts)
        save_persistent_state()

        log_event(
            "CASE",
            f"🕸️ Đã dựng và lưu Sơ đồ tấn công (Graph Visualization) cho {case_id} "
            f"({len(nodes)} thực thể, {len(edges)} liên kết)."
        )
        return True, graph_data, f"Đã tạo và lưu sơ đồ trực quan cho {case_id}."
