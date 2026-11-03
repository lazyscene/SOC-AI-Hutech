import os
import json
import time
import re
import ipaddress
import requests
from collections import deque
from tools.base import register_tool
from web.state import log_event
from core.network_utils import classify_subnet, is_valid_ip, is_private_ip
from core.misp_vault import query_ioc_vault, fetch_open_misp_feeds

# 1. API Keys & Cấu hình (Lấy từ biến môi trường, không để hardcode key thật)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

MISP_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "misp_iocs.json")
MITRE_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "mitre_attack_kb.json")
CACHE_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ti_cache.json")

CACHE_TTL_SECONDS = 3600  # Lưu cache 1 giờ

# 2. Bộ nhớ đệm TI_CACHE (In-memory + File)
TI_CACHE = {}
_vt_call_history = deque(maxlen=10)

def load_ti_cache():
    global TI_CACHE
    if os.path.exists(CACHE_FILE_PATH):
        try:
            with open(CACHE_FILE_PATH, "r", encoding="utf-8") as f:
                TI_CACHE = json.load(f)
        except Exception:
            TI_CACHE = {}

def save_ti_cache():
    try:
        with open(CACHE_FILE_PATH, "w", encoding="utf-8") as f:
            json.dump(TI_CACHE, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

load_ti_cache()

def get_cached(key: str):
    item = TI_CACHE.get(key)
    if item:
        if time.time() - item.get("time", 0) < CACHE_TTL_SECONDS:
            return item.get("result")
    return None

def set_cached(key: str, result: str):
    TI_CACHE[key] = {
        "time": time.time(),
        "result": result
    }
    save_ti_cache()

def rate_limit_vt():
    """Bảo vệ Rate Limit VirusTotal Free Tier: tối đa 4 requests / phút"""
    now = time.time()
    while _vt_call_history and (now - _vt_call_history[0] > 60):
        _vt_call_history.popleft()

    if len(_vt_call_history) >= 4:
        wait_seconds = 60 - (now - _vt_call_history[0]) + 0.5
        if wait_seconds > 0 and wait_seconds <= 5:
            time.sleep(wait_seconds)
        elif wait_seconds > 5:
            return False
    _vt_call_history.append(time.time())
    return True

# 3. Helper kiểm tra MISP nội bộ (Truy vấn trực tiếp kho SQLite misp_vault.db)
def query_misp_internal(indicator: str):
    return query_ioc_vault(indicator)

# ==========================================
# TOOL 1: CHECK IP REPUTATION
# ==========================================
IP_REPUTATION_SCHEMA = {
    "name": "tool_check_ip_reputation",
    "description": "Tra cuu danh tieng IP qua AbuseIPDB & VirusTotal (cho Public IP) hoac doi chieu MISP IOC & subnet phong Lab (cho Private IP).",
    "parameters": {
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Dia chi IP can kiem tra (vi du: 192.168.63.250 hoac 8.8.8.8)"}
        },
        "required": ["ip"]
    }
}

@register_tool(IP_REPUTATION_SCHEMA)
def tool_check_ip_reputation(ip: str):
    clean_ip = (ip or "").strip()
    log_event("TOOL", f"Tra cứu Threat Intel danh tiếng IP: {clean_ip}")

    # 1. Chặn ngay lập tức chuỗi rác không phải IP ("unknown", "local", rỗng...)
    if not is_valid_ip(clean_ip):
        return f"[Bỏ qua] Giá trị '{clean_ip}' không phải là địa chỉ IP hợp lệ."

    # 2. Xử lý Private IP (Không gọi ra Internet AbuseIPDB/VirusTotal)
    if is_private_ip(clean_ip):
        subnet_desc = classify_subnet(clean_ip)
        misp_match = query_misp_internal(clean_ip)
        if misp_match:
            res = (f"[TI Private IP] {clean_ip} ({subnet_desc}). "
                   f"Khớp MISP IOC nội bộ: {misp_match.get('threat_level')} - {misp_match.get('comment')} "
                   f"| Verdict: MALICIOUS (Attacker)")
        else:
            res = f"[TI Private IP] {clean_ip} ({subnet_desc}). Không có trong danh mục MISP IOC nội bộ. Verdict: CLEAN (Nội bộ)"
        return res[:300]

    # 3. Public IP -> Kiểm tra Cache
    cache_key = f"ip:{clean_ip}"
    cached_val = get_cached(cache_key)
    if cached_val:
        return cached_val

    # 4. Gọi AbuseIPDB API v2
    abuse_score = 0
    total_reports = 0
    country = "Unknown"
    isp = "Unknown"
    abuse_success = False

    if ABUSEIPDB_API_KEY:
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            params = {"ipAddress": clean_ip, "maxAgeInDays": 90}
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
            resp = requests.get(url, params=params, headers=headers, timeout=8)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)
                country = data.get("countryCode", "XX")
                isp = data.get("isp", "Unknown")
                abuse_success = True
            elif resp.status_code == 429:
                log_event("WARNING", "AbuseIPDB Rate Limit (HTTP 429)")
        except Exception as e:
            log_event("ERROR", f"Lỗi gọi AbuseIPDB: {e}")

    # 5. Gọi VirusTotal IP API v3
    vt_malicious = 0
    vt_success = False

    if VIRUSTOTAL_API_KEY and rate_limit_vt():
        try:
            vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{clean_ip}"
            vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY, "accept": "application/json"}
            vt_resp = requests.get(vt_url, headers=vt_headers, timeout=8)
            if vt_resp.status_code == 200:
                vt_data = vt_resp.json().get("data", {})
                stats = vt_data.get("attributes", {}).get("last_analysis_stats", {})
                vt_malicious = stats.get("malicious", 0)
                vt_success = True
            elif vt_resp.status_code == 429:
                log_event("WARNING", "VirusTotal IP Rate Limit (HTTP 429)")
        except Exception as e:
            log_event("ERROR", f"Lỗi gọi VirusTotal IP: {e}")

    # 6. Đánh giá kết luận
    if abuse_score >= 50 or vt_malicious >= 3:
        verdict = "MALICIOUS"
    elif abuse_score > 0 or vt_malicious > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    result = (f"[TI Public IP] {clean_ip} ({country}, {isp[:25]}). "
              f"AbuseScore: {abuse_score}%, Reports: {total_reports}, VT Malicious: {vt_malicious}. "
              f"Verdict: {verdict}")
    result = result[:300]

    # Chỉ lưu vào Cache khi có ít nhất một dịch vụ phản hồi thành công (tránh đầu độc cache khi 429)
    if abuse_success or vt_success:
        set_cached(cache_key, result)

    return result

# ==========================================
# TOOL 2: CHECK FILE HASH
# ==========================================
FILE_HASH_SCHEMA = {
    "name": "tool_check_file_hash",
    "description": "Kiem tra ma hash file (MD5, SHA1, SHA256) tren VirusTotal API v3 va kho MISP noi bo.",
    "parameters": {
        "type": "object",
        "properties": {
            "file_hash": {"type": "string", "description": "Chuoi ma hash MD5/SHA1/SHA256 (vi du: 44d88612fea8a8f36de82e1278abb02f)"}
        },
        "required": ["file_hash"]
    }
}

@register_tool(FILE_HASH_SCHEMA)
def tool_check_file_hash(file_hash: str):
    clean_hash = (file_hash or "").strip().lower()
    log_event("TOOL", f"Tra cứu Threat Intel mã Hash: {clean_hash[:16]}...")

    cache_key = f"hash:{clean_hash}"
    cached_val = get_cached(cache_key)
    if cached_val:
        return cached_val

    # Kiểm tra kho MISP nội bộ trước
    misp_match = query_misp_internal(clean_hash)

    # Gọi VirusTotal v3 files API
    vt_res = None
    should_cache = False

    if VIRUSTOTAL_API_KEY and rate_limit_vt():
        try:
            vt_url = f"https://www.virustotal.com/api/v3/files/{clean_hash}"
            vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY, "accept": "application/json"}
            resp = requests.get(vt_url, headers=vt_headers, timeout=10)
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())
                label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown")
                verdict = "MALICIOUS" if malicious >= 3 else ("SUSPICIOUS" if (malicious > 0 or suspicious > 0) else "CLEAN")
                vt_res = {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total": total,
                    "label": label,
                    "verdict": verdict
                }
                should_cache = True
            elif resp.status_code == 404:
                vt_res = "404_NOT_FOUND"
                should_cache = True
            elif resp.status_code == 429:
                log_event("WARNING", "VirusTotal Hash Rate Limit (HTTP 429)")
        except Exception as e:
            log_event("ERROR", f"Lỗi gọi VirusTotal File: {e}")

    # Tổng hợp kết quả
    if isinstance(vt_res, dict):
        misp_extra = f", MISP: {misp_match.get('threat_level')}" if misp_match else ""
        result = (f"[TI Hash] VT: {vt_res['malicious']}/{vt_res['total']} engines, "
                  f"Suspicious: {vt_res['suspicious']}, Threat: {vt_res['label']}{misp_extra}. "
                  f"Verdict: {vt_res['verdict']}")
    elif vt_res == "404_NOT_FOUND":
        if misp_match:
            result = f"[TI Hash] VT chua ghi nhan hash. Tim thay trong MISP: {misp_match.get('threat_level')} - {misp_match.get('comment')}. Verdict: MALICIOUS"
        else:
            result = f"[TI Hash] Hash chua tung xuat hien tren VirusTotal va MISP. Verdict: UNKNOWN / CLEAN"
    else:
        if misp_match:
            result = f"[TI Hash] MISP Khop: {misp_match.get('threat_level')} - {misp_match.get('comment')}. Verdict: MALICIOUS"
            should_cache = True
        else:
            result = f"[TI Hash] Khong the ket noi VirusTotal (Rate Limit hoac loi mang) va khong co trong MISP."

    result = result[:300]
    # Chỉ cache khi có kết quả hợp lệ, tuyệt đối không cache lỗi 429
    if should_cache:
        set_cached(cache_key, result)

    return result

# ==========================================
# TOOL 3: QUERY MISP IOC
# ==========================================
MISP_QUERY_SCHEMA = {
    "name": "tool_query_misp_ioc",
    "description": "Tra cuu chi so xam pham IOC (IP, Hash, Domain, URL, CVE) trong kho du lieu MISP noi bo.",
    "parameters": {
        "type": "object",
        "properties": {
            "indicator": {"type": "string", "description": "Chi so IOC can tra cuu (IP, hash, domain, url, CVE)"}
        },
        "required": ["indicator"]
    }
}

@register_tool(MISP_QUERY_SCHEMA)
def tool_query_misp_ioc(indicator: str):
    clean_ind = (indicator or "").strip()
    log_event("TOOL", f"Tra cứu kho IOC MISP Vault: {clean_ind}")
    match = query_misp_internal(clean_ind)
    if match:
        return (f"[MISP IOC] Khớp {match.get('id')}: [{match.get('type')}] {match.get('value')} | "
                f"Threat: {match.get('threat_level')} | Nguồn: {match.get('source', 'MISP')} | "
                f"Mô tả: {match.get('comment')}")[:300]
    return f"[MISP IOC] Không tìm thấy chỉ số '{clean_ind}' trong kho MISP Vault."

# ==========================================
# TOOL 4: LOOKUP MITRE ATT&CK
# ==========================================
MITRE_LOOKUP_SCHEMA = {
    "name": "tool_lookup_mitre_attack",
    "description": "Tra cuu ky thuat MITRE ATT&CK (nhu T1046, T1110, T1059.001, T1190, T1505.003, T1021) de lay Tactic, Mo ta va Cach khac phuc.",
    "parameters": {
        "type": "object",
        "properties": {
            "technique_id_or_keyword": {"type": "string", "description": "Ma ky thuat (vi du T1046, T1110) hoac tu khoa (scan, brute force, powershell, rce, webshell)"}
        },
        "required": ["technique_id_or_keyword"]
    }
}

@register_tool(MITRE_LOOKUP_SCHEMA)
def tool_lookup_mitre_attack(technique_id_or_keyword: str):
    query = (technique_id_or_keyword or "").strip()
    log_event("TOOL", f"Tra cứu MITRE ATT&CK KB: {query}")
    if not os.path.exists(MITRE_FILE_PATH):
        return f"[MITRE ATT&CK] Chưa tìm thấy tệp cơ sở tri thức {MITRE_FILE_PATH}."

    try:
        with open(MITRE_FILE_PATH, "r", encoding="utf-8") as f:
            kb = json.load(f)

        norm_key = query.upper()
        if norm_key in kb:
            t = kb[norm_key]
            return (f"[MITRE ATT&CK] [{t.get('id')} - {t.get('name')}] | "
                    f"Tactic: {t.get('tactic')} | Mô tả: {t.get('description')} | "
                    f"Khắc phục: {t.get('mitigation')}")[:400]

        q_lower = query.lower()
        for tid, t in kb.items():
            if (q_lower in tid.lower() or 
                q_lower in t.get("name", "").lower() or 
                q_lower in t.get("tactic", "").lower() or
                q_lower in t.get("description", "").lower()):
                return (f"[MITRE ATT&CK] [{t.get('id')} - {t.get('name')}] | "
                        f"Tactic: {t.get('tactic')} | Mô tả: {t.get('description')} | "
                        f"Khắc phục: {t.get('mitigation')}")[:400]

    except Exception as e:
        log_event("ERROR", f"Lỗi tra cứu MITRE ATT&CK: {e}")

    return f"[MITRE ATT&CK] Không tìm thấy kỹ thuật phù hợp với từ khóa '{query}'."
