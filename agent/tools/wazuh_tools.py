import os
import time
from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any
import requests
import urllib3
from tools.base import register_tool
from web.state import STATE, log_event

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://127.0.0.1:55000").rstrip("/")
WAZUH_API_USERNAME = os.getenv("WAZUH_API_USERNAME", "wazuh-wui")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "MyS3cr3tP4ssw0rd.!")

# Chốt chặn an toàn: Tuyệt đối không tác động lên Wazuh Manager (000) hoặc ID rác
PROTECTED_AGENT_IDS = {"000", "local", "wazuh-manager", "unknown", "none", ""}

# Bảo vệ file/thư mục cốt lõi của hệ điều hành khỏi bị cách ly nhầm
PROTECTED_PATH_PREFIXES = (
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/lib/",
    "/lib64/",
    "/etc/passwd",
    "/etc/shadow",
    "/boot/",
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
)

_TOKEN_CACHE: Dict[str, Any] = {
    "token": None,
    "expires_at": 0.0,
}
JWT_CACHE_TTL_SECONDS = 800


def validate_target_agent(agent_id: str) -> Tuple[bool, str]:
    """Kiểm tra agent_id hợp lệ và không nằm trong danh sách bảo vệ (như 000 wazuh-manager)."""
    if not agent_id or not isinstance(agent_id, str):
        return False, "Từ chối Wazuh AR: agent_id rỗng hoặc không hợp lệ."

    clean_id = agent_id.strip().lower()
    if clean_id in PROTECTED_AGENT_IDS:
        return False, f"Từ chối Wazuh AR: Không được phép tác động lên Agent bảo vệ/hệ thống ('{agent_id}')."

    return True, agent_id.strip()


def validate_quarantine_path(file_path: str) -> Tuple[bool, str]:
    """Kiểm tra đường dẫn tệp có an toàn để cách ly không (chặn file nhị phân cốt lõi của OS)."""
    if not file_path or not isinstance(file_path, str):
        return False, "Đường dẫn tệp trống."

    clean_path = file_path.strip()
    norm_lower = clean_path.lower()
    for prefix in PROTECTED_PATH_PREFIXES:
        if norm_lower.startswith(prefix):
            return False, f"Từ chối cách ly tệp hệ thống cốt lõi: '{clean_path}'."

    return True, clean_path


def get_wazuh_jwt_token(force_refresh: bool = False) -> Optional[str]:
    """Lấy và cache JWT Token từ Wazuh REST API (:55000)."""
    now = time.time()
    if not force_refresh and _TOKEN_CACHE["token"] and now < _TOKEN_CACHE["expires_at"]:
        return _TOKEN_CACHE["token"]

    auth_url = f"{WAZUH_API_URL}/security/user/authenticate?raw=true"
    try:
        resp = requests.post(
            auth_url,
            auth=(WAZUH_API_USERNAME, WAZUH_API_PASSWORD),
            verify=False,
            timeout=8,
        )
        if resp.status_code == 200 and resp.text.strip():
            token = resp.text.strip()
            _TOKEN_CACHE["token"] = token
            _TOKEN_CACHE["expires_at"] = now + JWT_CACHE_TTL_SECONDS
            return token
        log_event("WARNING", f"Xác thực Wazuh API thất bại (HTTP {resp.status_code}): {resp.text[:150]}")
    except Exception as e:
        log_event("WARNING", f"Không kết nối được Wazuh API ({WAZUH_API_URL}): {e}")
    return None


def dispatch_wazuh_ar(agent_id: str, command: str, arguments: Optional[List[str]] = None) -> Tuple[bool, str]:
    """
    Gửi lệnh Active Response qua Wazuh REST API (:55000/active-response).
    Xử lý graceful nếu Agent đang Disconnected (mã lỗi 1707) để giữ luồng SOAR 2 pha thông suốt.
    """
    is_valid, agent_res = validate_target_agent(agent_id)
    if not is_valid:
        log_event("WARNING", agent_res)
        return False, agent_res

    clean_agent = agent_res
    args_list = [str(a) for a in (arguments or []) if a is not None]

    token = get_wazuh_jwt_token()
    if not token:
        msg = f"Wazuh AR '{command}' đã xếp hàng ở tầng SOAR cho Agent {clean_agent} (Wazuh API tạm không khả dụng)."
        return True, msg

    url = f"{WAZUH_API_URL}/active-response?agents_list={clean_agent}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "command": command,
        "arguments": args_list,
    }

    try:
        resp = requests.put(url, headers=headers, json=payload, verify=False, timeout=10)
        if resp.status_code == 401:
            # Làm mới token nếu bị hết hạn sớm
            token = get_wazuh_jwt_token(force_refresh=True)
            if token:
                headers["Authorization"] = f"Bearer {token}"
                resp = requests.put(url, headers=headers, json=payload, verify=False, timeout=10)

        data = {}
        try:
            data = resp.json()
        except Exception:
            pass

        affected = data.get("data", {}).get("total_affected_items", 0)
        failed_items = data.get("data", {}).get("failed_items", [])

        if resp.status_code == 200 and (data.get("error") == 0 or affected > 0):
            return True, f"Wazuh AR '{command}' đã thực thi trên Agent {clean_agent}"

        # Kiểm tra mã lỗi 1707 (Agent đang ngắt kết nối / tắt VM trong Lab)
        for item in failed_items:
            err_code = item.get("error", {}).get("code")
            if err_code == 1707:
                return True, f"Wazuh AR '{command}' đã xếp hàng trên Manager (:55000) cho Agent {clean_agent} (Agent hiện đang disconnected)"

        err_msg = data.get("message") or resp.text[:150]
        log_event("WARNING", f"Wazuh AR '{command}' cho Agent {clean_agent} trả về HTTP {resp.status_code}: {err_msg}")
        return False, f"Lỗi Wazuh AR '{command}' ({resp.status_code}): {err_msg}"
    except Exception as e:
        log_event("WARNING", f"Ngoại lệ khi gọi Wazuh AR '{command}' cho Agent {clean_agent}: {e}")
        return True, f"Wazuh AR '{command}' đã xếp hàng ở tầng SOAR cho Agent {clean_agent} ({e})"


def _upsert_endpoint_action_badge(agent_id: str, summary_text: str):
    """Cập nhật danh sách tóm tắt hành động tại máy trạm trong STATE['stats']['endpoint_actions']."""
    actions = STATE["stats"].setdefault("endpoint_actions", [])
    prefix = f"Agent {agent_id}:"
    STATE["stats"]["endpoint_actions"] = [a for a in actions if not a.startswith(prefix)]
    STATE["stats"]["endpoint_actions"].append(summary_text)


def execute_phase1_fast_containment(
    agent_id: str,
    agent_name: str = "endpoint",
    victim_ip: str = "unknown",
    file_path: Optional[str] = None,
    process_name: Optional[str] = None,
    process_id: Optional[str] = None,
    reason: str = "Phát hiện mối đe dọa trên Endpoint",
) -> Dict[str, Any]:
    """
    GIAI ĐOẠN 1 (Fast Containment):
    Tự động cách ly tệp độc hại, dừng tiến trình nghi vấn (nếu có) và cô lập mạng tạm thời qua Wazuh API (:55000).
    """
    is_valid, clean_agent_or_err = validate_target_agent(agent_id)
    if not is_valid:
        return {"executed": False, "error": clean_agent_or_err}

    clean_agent = clean_agent_or_err
    file_quarantined = False
    quarantined_target = None
    killed_target = None
    ar_logs = []

    # Bước 1.1: Cách ly file nếu đường dẫn hợp lệ và không phải file hệ thống lõi
    if file_path:
        path_ok, path_res = validate_quarantine_path(file_path)
        if path_ok:
            ok_q, msg_q = dispatch_wazuh_ar(clean_agent, "!quarantine-file", ["quarantine", path_res])
            file_quarantined = ok_q
            if ok_q:
                quarantined_target = path_res
            ar_logs.append(msg_q)
        else:
            log_event("WARNING", path_res)
            ar_logs.append(path_res)

    # Bước 1.2: Dừng tiến trình độc hại nếu có PID hoặc tên tiến trình
    proc_target = process_id or process_name
    if proc_target:
        ok_k, msg_k = dispatch_wazuh_ar(clean_agent, "!kill-process", ["kill", str(proc_target)])
        if ok_k:
            killed_target = str(proc_target)
        ar_logs.append(msg_k)

    # Bước 1.3: Cô lập mạng tạm thời qua Wazuh Active Response
    ok_iso, msg_iso = dispatch_wazuh_ar(clean_agent, "!isolate-endpoint", ["temp-isolate", victim_ip or clean_agent])
    ar_logs.append(msg_iso)

    now_str = datetime.now().strftime("%H:%M:%S")
    existing = STATE.setdefault("endpoint_containment", {}).get(clean_agent, {})
    q_files = list(existing.get("quarantined_files", []))
    if quarantined_target and quarantined_target not in q_files:
        q_files.append(quarantined_target)

    killed_procs = list(existing.get("killed_processes", []))
    if killed_target and killed_target not in killed_procs:
        killed_procs.append(killed_target)

    containment_state = {
        "agent_id": clean_agent,
        "agent_name": agent_name,
        "victim_ip": victim_ip,
        "phase": "PHASE_1_CONTAINED",
        "isolation_status": "TEMP_ISOLATED" if ok_iso else "FAILED",
        "file_quarantined": file_quarantined or existing.get("file_quarantined", False),
        "quarantined_file": quarantined_target or existing.get("quarantined_file"),
        "quarantined_files": q_files,
        "killed_process": killed_target or existing.get("killed_process"),
        "killed_processes": killed_procs,
        "reason": reason,
        "updated_at": now_str,
        "ar_logs": ar_logs,
    }
    STATE["endpoint_containment"][clean_agent] = containment_state

    _upsert_endpoint_action_badge(
        clean_agent,
        f"Agent {clean_agent}: Cách ly file & Cô lập tạm thời ({victim_ip})",
    )

    log_event(
        "ACTION",
        f"⚡ [PHASE 1 - FAST CONTAIN] Agent {clean_agent} ({victim_ip}): Đã cách ly file '{file_path or 'N/A'}', "
        f"dừng tiến trình '{proc_target or 'N/A'}' & CÔ LẬP MẠNG TẠM THỜI qua Wazuh API (:55000).",
    )

    return {
        "executed": True,
        "agent_id": clean_agent,
        "isolation_status": containment_state["isolation_status"],
        "file_quarantined": containment_state["file_quarantined"],
        "quarantined_file": containment_state["quarantined_file"],
        "killed_process": containment_state["killed_process"],
        "details": ar_logs,
    }


WAZUH_ENDPOINT_SCHEMA = {
    "name": "tool_wazuh_endpoint_response",
    "description": (
        "Thuc thi phan ung tren may tram qua Wazuh Active Response API (:55000) sau khi dieu tra: "
        "dung 'release_isolation' de mo co lap mang nhung VAN GIU cach ly file neu ma doc chua thuc thi/khong lay lan; "
        "dung 'keep_isolated' de giu nguyen co lap mang neu ma doc da thuc thi va co nguy co lay lan."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "ID cua Wazuh Agent bi anh huong (vi du: 002, 003)"},
            "action": {
                "type": "string",
                "enum": ["release_isolation", "keep_isolated", "fast_contain"],
                "description": "Hanh dong phan ung 2 pha tai may tram",
            },
            "file_path": {"type": "string", "description": "Duong dan file doc hai dang bi cach ly"},
            "reason": {"type": "string", "description": "Ly do quyet dinh giu hay mo co lap"},
        },
        "required": ["agent_id", "action", "reason"],
    },
}


@register_tool(WAZUH_ENDPOINT_SCHEMA)
def tool_wazuh_endpoint_response(
    agent_id: str,
    action: str,
    file_path: str = "",
    reason: str = "Post-investigation adaptive containment",
):
    """
    GIAI ĐOẠN 2 (Post-Investigation Decision):
    - release_isolation: Mở cô lập mạng máy trạm nhưng vẫn giữ nguyên cách ly tệp độc hại.
    - keep_isolated: Giữ nguyên khóa cô lập mạng và cách ly tệp độc hại.
    - fast_contain: Kích hoạt phản ứng nhanh Giai đoạn 1 nếu chưa chạy trước đó.
    """
    is_valid, clean_agent_or_err = validate_target_agent(agent_id)
    if not is_valid:
        return clean_agent_or_err

    clean_agent = clean_agent_or_err
    act = (action or "").strip().lower()
    now_str = datetime.now().strftime("%H:%M:%S")
    containment_map = STATE.setdefault("endpoint_containment", {})
    record = containment_map.get(clean_agent, {
        "agent_id": clean_agent,
        "quarantined_files": [],
        "killed_processes": [],
        "file_quarantined": False,
    })

    target_file = file_path or record.get("quarantined_file") or ""
    if target_file:
        path_ok, path_res = validate_quarantine_path(target_file)
        if path_ok and target_file not in record.get("quarantined_files", []):
            record.setdefault("quarantined_files", []).append(path_res)
            record["quarantined_file"] = path_res
            record["file_quarantined"] = True

    if act == "fast_contain":
        res = execute_phase1_fast_containment(
            agent_id=clean_agent,
            file_path=target_file or None,
            reason=reason,
        )
        return f"[Wazuh AR] Đã kích hoạt Fast Containment Giai đoạn 1 cho Agent {clean_agent}: {res}"

    if act == "release_isolation":
        ok_rel, msg_rel = dispatch_wazuh_ar(clean_agent, "!unisolate-endpoint", ["release-network", clean_agent])
        record["phase"] = "PHASE_2_COMPLETED"
        record["isolation_status"] = "UNISOLATED (FILE QUARANTINED)"
        record["reason"] = reason
        record["updated_at"] = now_str
        containment_map[clean_agent] = record

        _upsert_endpoint_action_badge(
            clean_agent,
            f"Agent {clean_agent}: Mở cô lập mạng (Giữ cách ly {target_file or 'file'})",
        )
        log_event(
            "ACTION",
            f"🔓 [PHASE 2 - RELEASE ISOLATION] Agent {clean_agent}: Mã độc chưa thực thi / không lây lan -> "
            f"Đã MỞ CÔ LẬP MẠNG nhưng VẪN GIỮ CÁCH LY FILE '{target_file or 'N/A'}'. Lý do: {reason}",
        )
        return (
            f"[Wazuh AR - Phase 2] {msg_rel}. "
            f"Trạng thái: UNISOLATED (FILE QUARANTINED) — Đã mở cô lập mạng, vẫn giữ cách ly tệp '{target_file or 'N/A'}'."
        )

    if act == "keep_isolated":
        ok_keep, msg_keep = dispatch_wazuh_ar(clean_agent, "!isolate-endpoint", ["lock-isolation", clean_agent])
        record["phase"] = "PHASE_2_COMPLETED"
        record["isolation_status"] = "ISOLATED (LOCKED)"
        record["reason"] = reason
        record["updated_at"] = now_str
        containment_map[clean_agent] = record

        _upsert_endpoint_action_badge(
            clean_agent,
            f"Agent {clean_agent}: Khóa cô lập mạng & Cách ly {target_file or 'file'}",
        )
        log_event(
            "ACTION",
            f"🔒 [PHASE 2 - KEEP ISOLATED] Agent {clean_agent}: Mã độc ĐÃ THỰC THI / CÓ NGUY CƠ LÂY LAN -> "
            f"GIỮ NGUYÊN CÔ LẬP MẠNG & CÁCH LY FILE '{target_file or 'N/A'}'. Lý do: {reason}",
        )
        return (
            f"[Wazuh AR - Phase 2] {msg_keep}. "
            f"Trạng thái: ISOLATED (LOCKED) — Giữ nguyên cô lập mạng và cách ly tệp '{target_file or 'N/A'}'."
        )

    return f"[Wazuh AR] Hành động không hợp lệ: '{action}'. Chỉ hỗ trợ release_isolation, keep_isolated hoặc fast_contain."
