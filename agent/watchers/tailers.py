import os
import json
import time
import re
import ipaddress
import threading
from collections import deque
from typing import Optional, List, Tuple, Dict
from core.controller import run_agent_loop
from core.models import AlertEvent, safe_get, normalize_hash
from core.network_utils import is_valid_ip
from web.state import log_event

WAZUH_ALERT_FILE = os.getenv("WAZUH_ALERT_FILE", "/var/ossec/logs/alerts/alerts.json")
WAZUH_MIN_ALERT_LEVEL = int(os.getenv("WAZUH_MIN_ALERT_LEVEL", "5"))
ALERT_COOLDOWN_SECONDS = 60

# Bảng theo dõi Cooldown / Deduplication
last_alert_time = {}

def is_broadcast_or_ignored(ip_str: str) -> bool:
    """Kiểm tra IP có phải địa chỉ Broadcast, Multicast hoặc Host GPU cần bỏ qua không"""
    if not ip_str or ip_str == "unknown":
        return False
    ip_str = ip_str.strip()

    # 1. Bỏ qua Windows Host GPU
    if ip_str == "192.168.63.1":
        return True

    # 2. Bỏ qua Broadcast
    if ip_str.endswith(".255") or ip_str == "255.255.255.255":
        return True

    # 3. Bỏ qua Multicast phổ biến (SSDP, mDNS, etc.)
    if ip_str.startswith("224.0.0.") or ip_str.startswith("239.") or ip_str == "239.255.255.250":
        return True

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_multicast or ip_obj.is_loopback:
            return True
    except ValueError:
        pass
    return False

def should_ignore_alert(src_ip: str, dest_ip: str, full_log: str) -> bool:
    """Bộ lọc bỏ qua toàn diện các cảnh báo Broadcast, Multicast gây nhiễu vòng lặp"""
    if is_broadcast_or_ignored(src_ip) or is_broadcast_or_ignored(dest_ip):
        return True

    log_lower = (full_log or "").lower()
    broadcast_patterns = ["192.168.63.255", "255.255.255.255", "239.255.255.250", "224.0.0."]
    if any(p in log_lower for p in broadcast_patterns):
        return True

    return False

def extract_ip(data: dict) -> str:
    """
    Trích xuất IP nguồn mạng thực sự (QUY TẮC 2):
    Tuyệt đối không lấy agent.ip làm src_ip. Với sự kiện FIM nội bộ trả về 'unknown'.
    """
    if safe_get(data, "syscheck") is not None:
        return "unknown"

    src_ip = safe_get(data, "data", "srcip") or safe_get(data, "data", "src_ip") or data.get("srcip") or data.get("src_ip")
    if src_ip and str(src_ip).strip() not in ["unknown", ""]:
        clean = str(src_ip).strip()
        if is_valid_ip(clean):
            return clean

    # Nếu là sự kiện mạng nhưng không có trong data, tìm trong full_log
    full_log = data.get("full_log", "")
    ips = re.findall(r'\b(?:192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b', full_log)
    if ips:
        return ips[0]
    return "unknown"

def extract_mitre_info(rule: dict, full_log: str) -> list:
    """Bóc tách mã và kỹ thuật MITRE ATT&CK từ rule hoặc log (QUY TẮC 5)"""
    mitre_data = rule.get("mitre", {})
    mitre_list = []
    if mitre_data:
        ids = mitre_data.get("id", [])
        if isinstance(ids, str):
            ids = [ids]
        techniques = mitre_data.get("technique", [])
        if isinstance(techniques, str):
            techniques = [techniques]
        for i, tid in enumerate(ids):
            tname = techniques[i] if i < len(techniques) else ""
            mitre_list.append(f"{tid} - {tname}".strip(" -"))

    if not mitre_list and full_log:
        found_t = re.findall(r'\b(T1\d{3}(?:\.\d{3})?)\b', full_log)
        for t in set(found_t):
            mitre_list.append(t)
    return mitre_list

def extract_sysmon_hashes(win_hashes: str) -> Dict[str, str]:
    """
    Bóc tách từng cặp ALGO=HASH từ chuỗi ghép của Sysmon Windows (QUY TẮC 3):
    Ví dụ: 'MD5=69630e...,SHA256=131f95...,IMPHASH=...'
    """
    results = {}
    if not win_hashes or not isinstance(win_hashes, str):
        return results

    pairs = re.findall(r'([a-zA-Z0-9]+)=([a-fA-F0-9]+)', win_hashes)
    for algo, val in pairs:
        valid_h = normalize_hash(val)
        if valid_h:
            algo_upper = algo.upper()
            if algo_upper == "SHA256" or len(valid_h) == 64:
                results["sha256"] = valid_h
            elif algo_upper == "SHA1" or len(valid_h) == 40:
                results["sha1"] = valid_h
            elif algo_upper == "MD5" or len(valid_h) == 32:
                results["md5"] = valid_h
    return results

def extract_hashes_and_metadata(data: dict, full_log: str = "") -> Tuple[Optional[str], List[str], Optional[str], Optional[str]]:
    """
    Bóc tách mã hash, đường dẫn file và loại sự kiện theo Rule 3:
    - FIM: syscheck.path, syscheck.event, sha256_after, sha1_after, md5_after
    - Sysmon: data.win.eventdata.hashes
    - Thứ tự ưu tiên primary_hash: SHA256 -> SHA1 -> MD5
    Trả về (primary_hash, file_hashes, file_path, event_type)
    """
    hashes_dict = {}
    file_path = None
    event_type = None

    syscheck = safe_get(data, "syscheck")
    if syscheck and isinstance(syscheck, dict):
        file_path = syscheck.get("path")
        event_type = syscheck.get("event")
        for k in ["sha256_after", "sha256_before"]:
            h = normalize_hash(syscheck.get(k))
            if h and "sha256" not in hashes_dict:
                hashes_dict["sha256"] = h
        for k in ["sha1_after", "sha1_before"]:
            h = normalize_hash(syscheck.get(k))
            if h and "sha1" not in hashes_dict:
                hashes_dict["sha1"] = h
        for k in ["md5_after", "md5_before"]:
            h = normalize_hash(syscheck.get(k))
            if h and "md5" not in hashes_dict:
                hashes_dict["md5"] = h

    win_hashes = safe_get(data, "data", "win", "eventdata", "hashes")
    if win_hashes:
        sysmon_parsed = extract_sysmon_hashes(win_hashes)
        for k, v in sysmon_parsed.items():
            if k not in hashes_dict:
                hashes_dict[k] = v

    data_payload = safe_get(data, "data", default={})
    if isinstance(data_payload, dict):
        for k in ["sha256", "file_hash", "hash", "md5"]:
            h = normalize_hash(data_payload.get(k))
            if h:
                if len(h) == 64 and "sha256" not in hashes_dict:
                    hashes_dict["sha256"] = h
                elif len(h) == 40 and "sha1" not in hashes_dict:
                    hashes_dict["sha1"] = h
                elif len(h) == 32 and "md5" not in hashes_dict:
                    hashes_dict["md5"] = h

    if not hashes_dict and full_log:
        sha256_matches = re.findall(r'\b[a-fA-F0-9]{64}\b', full_log)
        for m in sha256_matches:
            h = normalize_hash(m)
            if h and "sha256" not in hashes_dict:
                hashes_dict["sha256"] = h
                break
        if "sha256" not in hashes_dict:
            md5_matches = re.findall(r'\b[a-fA-F0-9]{32}\b', full_log)
            for m in md5_matches:
                h = normalize_hash(m)
                if h and "md5" not in hashes_dict:
                    hashes_dict["md5"] = h
                    break

    # Thứ tự ưu tiên: SHA256 -> SHA1 -> MD5
    primary_hash = hashes_dict.get("sha256") or hashes_dict.get("sha1") or hashes_dict.get("md5")
    file_hashes = [hashes_dict[k] for k in ["sha256", "sha1", "md5"] if k in hashes_dict]

    return primary_hash, file_hashes, file_path, event_type

def process_alert_event(data: dict, is_historical: bool = False, seen_ids: deque = None) -> Optional[AlertEvent]:
    """
    Xử lý chuẩn hóa và điều phối một cảnh báo Wazuh/pfSense/Suricata:
    - Deduplication: kiểm tra seen_ids
    - Bóc tách IP theo đúng ngữ nghĩa (Rule 2)
    - Chuẩn hóa hash (Rule 3)
    - Lọc sự kiện và FIM deleted (Rule 7)
    - Kiểm tra Analysis Cooldown (Rule 7)
    - Kích hoạt run_agent_loop (nếu không phải historical)
    """
    if not data or not isinstance(data, dict):
        return None

    alert_id = data.get("id")
    if alert_id:
        if seen_ids is not None and alert_id in seen_ids:
            return None
        if seen_ids is not None:
            seen_ids.append(alert_id)

    # Nếu là cảnh báo nạp lịch sử lúc khởi động, chỉ ghi nhận seen_id, KHÔNG gọi LLM / Firewall (Rule 7)
    if is_historical:
        return None

    rule = data.get("rule", {})
    rule_id = str(rule.get("id", ""))
    level = int(rule.get("level", 0))
    rule_groups = rule.get("groups", [])
    full_log = data.get("full_log", "")

    # Bóc tách Hash & File Metadata (Rule 3)
    primary_hash, file_hashes, file_path, event_type = extract_hashes_and_metadata(data, full_log)

    agent_name = str(safe_get(data, "agent", "name") or "unknown")
    agent_ip = str(safe_get(data, "agent", "ip") or "unknown")
    syscheck = safe_get(data, "syscheck")

    is_fim = (syscheck is not None) or any(g in rule_groups for g in ["syscheck", "ossec"]) or (rule_id in ["550", "553", "554"])

    # Xử lý FIM DELETED (Rule 553 hoặc event == deleted) (Rule 7)
    if rule_id == "553" or event_type == "deleted":
        log_event("FIM", f"File đã bị xóa trên {agent_name}: {file_path or 'unknown'}")
        return None

    # Điều kiện kích hoạt phân tích (Rule 7):
    # level >= 6 HOẶC là sự kiện FIM added/modified có chứa hash (bao gồm Rule 554 ở level 5)
    # HOẶC các nhóm security alert
    is_fim_add_or_mod = is_fim and (event_type in ["added", "modified"] or rule_id in ["550", "554"]) and bool(primary_hash)
    is_security_alert = (
        any(g in rule_groups for g in ["firewall_block", "attack", "ids"]) or
        (level >= 6) or
        is_fim_add_or_mod
    )

    if not is_security_alert:
        return None

    # Bóc tách IP theo đúng ngữ nghĩa (Rule 2)
    if is_fim:
        src_ip = "unknown"
        dest_ip = "unknown"
        victim_ip = agent_ip if is_valid_ip(agent_ip) else "unknown"
    else:
        src_ip = extract_ip(data)
        dest_ip = str(safe_get(data, "data", "dstip") or safe_get(data, "data", "dst_ip") or data.get("dstip") or "unknown")
        victim_ip = dest_ip if is_valid_ip(dest_ip) else (agent_ip if is_valid_ip(agent_ip) else "unknown")

    # Bộ lọc bỏ qua Broadcast / Multicast / Host GPU
    if should_ignore_alert(src_ip, dest_ip, full_log):
        return None

    # Cơ chế Analysis Cooldown (Rule 7)
    now = time.time()
    if is_fim:
        cooldown_key = ("fim", agent_name, file_path or "unknown", primary_hash or "none")
    else:
        cooldown_key = ("net", rule_id, src_ip, dest_ip)

    last_time = last_alert_time.get(cooldown_key, 0)
    if now - last_time < ALERT_COOLDOWN_SECONDS:
        return None
    last_alert_time[cooldown_key] = now

    if len(last_alert_time) > 1000:
        last_alert_time.clear()

    mitre_info = extract_mitre_info(rule, full_log)

    source_label = "Wazuh FIM (syscheck)" if is_fim else (
        "pfSense / Suricata Syslog" if any(g in rule_groups for g in ["pfsense", "suricata", "firewall_block"]) else "Wazuh SIEM"
    )

    event = AlertEvent(
        source=source_label,
        rule_id=rule_id,
        level=level,
        title=rule.get("description", "Cảnh báo an ninh"),
        agent=agent_name,
        src_ip=src_ip,
        dest_ip=dest_ip,
        agent_ip=agent_ip,
        victim_ip=victim_ip,
        full_log=full_log,
        primary_hash=primary_hash,
        file_hashes=file_hashes,
        mitre_ids=mitre_info,
        file_path=file_path,
        event_type=event_type
    )

    # Chạy vòng lặp phân tích AI trên thread riêng
    threading.Thread(target=run_agent_loop, args=(event.to_dict(),), daemon=True).start()
    return event

def tail_wazuh():
    while not os.path.exists(WAZUH_ALERT_FILE):
        time.sleep(2)

    log_event("SYSTEM", f"Đã kết nối luồng cảnh báo SIEM Wazuh: {WAZUH_ALERT_FILE}")
    seen_ids = deque(maxlen=500)

    try:
        with open(WAZUH_ALERT_FILE, "r", encoding="utf-8", errors="ignore") as f:
            # Đọc lại tối đa 20 dòng gần nhất khi khởi động để ghi nhận ID đã xử lý (historical)
            lines = f.readlines()
            recent_lines = lines[-20:] if len(lines) > 20 else lines
            for line in recent_lines:
                try:
                    data = json.loads(line)
                    process_alert_event(data, is_historical=True, seen_ids=seen_ids)
                except Exception:
                    pass

            # Di chuyển con trỏ tới cuối file để theo dõi thời gian thực
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue

                try:
                    data = json.loads(line)
                    process_alert_event(data, is_historical=False, seen_ids=seen_ids)
                except Exception:
                    pass
    except Exception as e:
        log_event("ERROR", f"Lỗi luồng đọc Wazuh: {e}")
