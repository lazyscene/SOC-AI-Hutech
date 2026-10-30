import os
import json
import time
from core.controller import run_agent_loop
from web.state import log_event

WAZUH_ALERT_FILE = os.getenv("WAZUH_ALERT_FILE", "/var/ossec/logs/alerts/alerts.json")
SURICATA_EVE_FILE = os.getenv("SURICATA_EVE_FILE", "/var/log/suricata/eve.json")

def tail_wazuh():
    while not os.path.exists(WAZUH_ALERT_FILE):
        time.sleep(3)
    log_event("SYSTEM", f"Đã kết nối luồng CLI Wazuh: {WAZUH_ALERT_FILE}")
    with open(WAZUH_ALERT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                data = json.loads(line)
                rule = data.get("rule", {})
                level = int(rule.get("level", 0))
                if level >= 7:
                    summary = {
                        "source": "Wazuh SIEM/EDR",
                        "rule_id": rule.get("id"),
                        "level": level,
                        "title": rule.get("description"),
                        "agent": data.get("agent", {}).get("name"),
                        "src_ip": data.get("data", {}).get("srcip", "unknown"),
                        "full_log": data.get("full_log", "")[:300]
                    }
                    run_agent_loop(summary)
            except Exception:
                pass

def tail_suricata():
    while not os.path.exists(SURICATA_EVE_FILE):
        time.sleep(3)
    log_event("SYSTEM", f"Đã kết nối luồng CLI Suricata: {SURICATA_EVE_FILE}")
    last_ip_time = {}
    with open(SURICATA_EVE_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                data = json.loads(line)
                if data.get("event_type") == "alert":
                    src_ip = data.get("src_ip", "unknown")
                    now = time.time()
                    if now - last_ip_time.get(src_ip, 0) < 15:
                        continue
                    last_ip_time[src_ip] = now
                    alert_info = data.get("alert", {})
                    summary = {
                        "source": "Suricata NIDS",
                        "severity": alert_info.get("severity"),
                        "title": alert_info.get("signature"),
                        "category": alert_info.get("category"),
                        "src_ip": src_ip,
                        "dest_ip": data.get("dest_ip")
                    }
                    run_agent_loop(summary)
            except Exception:
                pass

