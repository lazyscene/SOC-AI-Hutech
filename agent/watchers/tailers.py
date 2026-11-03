import os
import json
import time
import re
import ipaddress
import threading
from collections import deque
from core.controller import run_agent_loop
from core.models import AlertEvent, safe_get
from web.state import log_event

WAZUH_ALERT_FILE = os.getenv("WAZUH_ALERT_FILE", "/var/ossec/logs/alerts/alerts.json")
WAZUH_MIN_ALERT_LEVEL = int(os.getenv("WAZUH_MIN_ALERT_LEVEL", "5"))
ALERT_COOLDOWN_SECONDS = 60

# Bảng theo dõi Cooldown / Deduplication: (rule_id, src_ip) -> timestamp
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

    log_lower = full_log.lower()
    broadcast_patterns = ["192.168.63.255", "255.255.255.255", "239.255.255.250", "224.0.0."]
    if any(p in log_lower for p in broadcast_patterns):
        return True

    return False

def extract_ip(data: dict) -> str:
    """Trích xuất src_ip thông minh từ các cấu trúc dữ liệu khác nhau của Wazuh bằng safe_get"""
    src_ip = safe_get(data, "data", "srcip") or safe_get(data, "data", "src_ip") or data.get("srcip") or data.get("src_ip")
    if src_ip and src_ip != "unknown":
        return str(src_ip)

    # Nếu chưa có, tìm IP qua regex trong full_log
    full_log = data.get("full_log", "")
    ips = re.findall(r'\b(?:192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b', full_log)
    if ips:
        return ips[0]
    return "unknown"

def extract_mitre_info(rule: dict, full_log: str) -> list:
    """Bóc tách mã và kỹ thuật MITRE ATT&CK từ rule hoặc log"""
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

def extract_hashes(data: dict, full_log: str) -> list:
    """Bóc tách mã hash MD5/SHA1/SHA256 an toàn không bị Message Chains"""
    hashes = []
    syscheck = safe_get(data, "syscheck", default={})
    for k in ["sha256_after", "sha1_after", "md5_after", "sha256_before"]:
        v = syscheck.get(k)
        if v and isinstance(v, str):
            hashes.append(v)

    win_hashes = safe_get(data, "data", "win", "eventdata", "hashes")
    if win_hashes and isinstance(win_hashes, str):
        h_parts = re.findall(r'(?:MD5|SHA1|SHA256)=([a-fA-F0-9]{32,64})', win_hashes)
        if h_parts:
            hashes.extend(h_parts)
        else:
            hashes.append(win_hashes)

    data_payload = safe_get(data, "data", default={})
    for k in ["file_hash", "hash", "sha256", "md5"]:
        v = data_payload.get(k)
        if v and isinstance(v, str):
            hashes.append(v)

    if not hashes and full_log:
        sha256_matches = re.findall(r'\b[a-fA-F0-9]{64}\b', full_log)
        if sha256_matches:
            hashes.extend(sha256_matches[:2])
        else:
            md5_matches = re.findall(r'\b[a-fA-F0-9]{32}\b', full_log)
            if md5_matches:
                hashes.extend(md5_matches[:2])

    return list(dict.fromkeys(hashes))

def tail_wazuh():
    while not os.path.exists(WAZUH_ALERT_FILE):
        time.sleep(2)

    log_event("SYSTEM", f"Đã kết nối luồng cảnh báo SIEM Wazuh: {WAZUH_ALERT_FILE}")
    seen_ids = deque(maxlen=300)

    try:
        with open(WAZUH_ALERT_FILE, "r", encoding="utf-8", errors="ignore") as f:
            # Đọc lại tối đa 20 dòng gần nhất khi khởi động để ghi nhận ID đã xử lý
            lines = f.readlines()
            recent_lines = lines[-20:] if len(lines) > 20 else lines
            for line in recent_lines:
                try:
                    data = json.loads(line)
                    alert_id = data.get("id")
                    if alert_id:
                        seen_ids.append(alert_id)
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
                    alert_id = data.get("id")
                    if alert_id and alert_id in seen_ids:
                        continue
                    if alert_id:
                        seen_ids.append(alert_id)

                    rule = data.get("rule", {})
                    level = int(rule.get("level", 0))
                    rule_id = str(rule.get("id", ""))
                    rule_groups = rule.get("groups", [])
                    is_security_alert = any(g in rule_groups for g in ["firewall_block", "attack", "ids"]) or (level >= WAZUH_MIN_ALERT_LEVEL)

                    # Chỉ xử lý cảnh báo an ninh thực sự
                    if not is_security_alert:
                        continue

                    src_ip = extract_ip(data)
                    dest_ip = str(safe_get(data, "data", "dstip") or safe_get(data, "data", "dst_ip") or data.get("dstip") or "unknown")
                    full_log = data.get("full_log", "")

                    # 1. BỘ LỌC BỎ QUA BROADCAST, MULTICAST VÀ HOST GPU
                    if should_ignore_alert(src_ip, dest_ip, full_log):
                        continue

                    # 2. CƠ CHẾ COOLDOWN / DEDUPLICATION (60 GIÂY CHO CÙNG RULE & SRC_IP)
                    now = time.time()
                    dedup_key = (rule_id, src_ip)
                    last_time = last_alert_time.get(dedup_key, 0)
                    if now - last_time < ALERT_COOLDOWN_SECONDS:
                        continue
                    last_alert_time[dedup_key] = now

                    # Dọn dẹp cache nếu quá nhiều phần tử
                    if len(last_alert_time) > 1000:
                        last_alert_time.clear()

                    mitre_info = extract_mitre_info(rule, full_log)
                    file_hashes = extract_hashes(data, full_log)

                    # 3. ĐÓNG GÓI BẰNG DATACLASS ALERTEVENT
                    event = AlertEvent(
                        source="pfSense / Suricata Syslog" if any(g in rule_groups for g in ["pfsense", "suricata", "firewall_block"]) else "Wazuh SIEM",
                        rule_id=rule_id,
                        level=level,
                        title=rule.get("description", "Cảnh báo an ninh"),
                        agent=safe_get(data, "agent", "name", default="pfsense-gateway"),
                        src_ip=src_ip,
                        dest_ip=dest_ip,
                        full_log=full_log,
                        mitre_ids=mitre_info,
                        file_hashes=file_hashes
                    )

                    # Chạy phân tích AI trên luồng riêng biệt để không nghẽn việc đọc log
                    threading.Thread(target=run_agent_loop, args=(event.to_dict(),), daemon=True).start()
                except Exception as ex:
                    pass
    except Exception as e:
        log_event("ERROR", f"Lỗi luồng đọc Wazuh: {e}")
