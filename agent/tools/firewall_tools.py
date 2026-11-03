import os
import ipaddress
import requests
import urllib3
from tools.base import register_tool
from web.state import STATE, log_event

# Disable InsecureRequestWarning because pfSense uses a self-signed certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PFSENSE_API_URL = os.getenv("PFSENSE_API_URL", "https://192.168.171.2/api/v2")
PFSENSE_API_KEY = os.getenv("PFSENSE_API_KEY", "")
PFSENSE_ALIAS_NAME = os.getenv("PFSENSE_ALIAS_NAME", "SOC_BLOCKLIST")

DEFAULT_PROTECTED_IPS = [
    "127.0.0.1",
    "192.168.63.1",    # Host GPU
    "192.168.63.138",  # SOC WAN
    "192.168.171.1",   # pfSense Transit Gateway
    "192.168.171.2",   # pfSense Firewall Management
    "192.168.171.34",  # Wazuh Manager SOC
    "192.168.214.1",   # Victim LAN 1 Gateway
    "192.168.214.10",  # Victim Linux Server
    "192.168.45.1",    # Victim LAN 2 Gateway
    "192.168.45.10"    # Victim Windows
]

def get_protected_ips() -> list:
    """Lấy toàn bộ IP được bảo vệ từ cấu hình mặc định và biến môi trường SOC_PROTECTED_IPS"""
    env_ips = os.getenv("SOC_PROTECTED_IPS", "")
    extra = [ip.strip() for ip in env_ips.split(",") if ip.strip()]
    combined = list(DEFAULT_PROTECTED_IPS)
    for ip in extra:
        if ip not in combined:
            combined.append(ip)
    return combined

PROTECTED_IPS = get_protected_ips()

def validate_blockable_ip(ip: str):
    """Kiểm tra tính an toàn của IP: chặn loopback, multicast, broadcast, whitelist"""
    if not ip or not isinstance(ip, str):
        return False, "Từ chối chặn: IP không hợp lệ hoặc rỗng."

    clean_ip = ip.strip()
    if clean_ip.lower() in ["unknown", "none", "local", "localhost", "n/a", ""]:
        return False, "Từ chối chặn: IP không xác định hoặc nội bộ (unknown/local)."

    # 1. Kiểm tra danh sách trắng hệ thống (Protected IPs)
    protected_list = get_protected_ips()
    if clean_ip in protected_list:
        return False, f"Từ chối chặn IP hệ thống quan trọng (Protected IP/Whitelist): {clean_ip}"

    # 2. Kiểm tra địa chỉ Broadcast phổ biến
    if clean_ip.endswith(".255") or clean_ip == "255.255.255.255":
        return False, f"Từ chối chặn địa chỉ Broadcast: {clean_ip}"

    # 3. Phân tích chính xác bằng thư viện ipaddress
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_loopback:
            return False, f"Từ chối chặn địa chỉ Loopback: {clean_ip}"
        if ip_obj.is_multicast:
            return False, f"Từ chối chặn địa chỉ Multicast: {clean_ip}"
        if ip_obj.is_reserved:
            return False, f"Từ chối chặn địa chỉ Reserved: {clean_ip}"
    except ValueError:
        return False, f"Từ chối chặn: Địa chỉ IP không đúng định dạng ({clean_ip})"

    return True, clean_ip

def _get_headers():
    return {
        "X-API-Key": PFSENSE_API_KEY,
        "Content-Type": "application/json"
    }

def get_or_create_soc_alias():
    """Tra cứu hoặc khởi tạo Alias SOC_BLOCKLIST trên pfSense qua REST API v2"""
    headers = _get_headers()
    try:
        resp = requests.get(f"{PFSENSE_API_URL}/firewall/aliases", headers=headers, verify=False, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            for alias in data:
                if alias.get("name") == PFSENSE_ALIAS_NAME:
                    return alias

        create_payload = {
            "name": PFSENSE_ALIAS_NAME,
            "type": "host",
            "descr": "Managed by Mini SOC AI Agent",
            "address": [],
            "detail": []
        }
        create_resp = requests.post(f"{PFSENSE_API_URL}/firewall/alias", headers=headers, json=create_payload, verify=False, timeout=10)
        if create_resp.status_code in [200, 201]:
            return create_resp.json().get("data", {})
        else:
            log_event("ERROR", f"Không tạo được Alias trên pfSense: {create_resp.text}")
            return None
    except Exception as e:
        log_event("ERROR", f"Lỗi kết nối pfSense REST API: {e}")
        return None

def apply_firewall_changes():
    """Kích hoạt áp dụng thay đổi (Apply Changes) tức thì trên pfSense"""
    try:
        resp = requests.post(
            f"{PFSENSE_API_URL}/firewall/apply",
            headers=_get_headers(),
            json={"async": False},
            verify=False,
            timeout=15
        )
        return resp.status_code == 200
    except Exception as e:
        log_event("ERROR", f"Lỗi gọi pfSense firewall/apply: {e}")
        return False

def _modify_blocklist_alias(clean_ip: str, action: str, reason: str = "") -> tuple[bool, str]:
    """
    Hàm nội bộ duy nhất xử lý thêm hoặc gỡ IP trong Alias SOC_BLOCKLIST trên pfSense:
    Xóa bỏ code smell Duplicated Code giữa block và unblock.
    """
    alias = get_or_create_soc_alias()
    if not alias:
        return False, "Không thể kết nối hoặc tìm thấy Alias SOC_BLOCKLIST trên pfSense."

    alias_id = alias.get("id")
    addresses = list(alias.get("address", []))
    details = list(alias.get("detail", []))

    if action == "add":
        if clean_ip in addresses:
            return True, f"IP {clean_ip} đã nằm trong danh sách chặn SOC_BLOCKLIST từ trước."
        addresses.append(clean_ip)
        details.append(f"AI SOC blocked: {reason[:40]}")
    elif action == "remove":
        if clean_ip not in addresses:
            return True, f"IP {clean_ip} không có trong danh sách chặn SOC_BLOCKLIST."
        idx = addresses.index(clean_ip)
        addresses.pop(idx)
        if idx < len(details):
            details.pop(idx)
    else:
        return False, f"Hành động không hợp lệ: {action}"

    patch_payload = {
        "id": alias_id,
        "address": addresses,
        "detail": details
    }

    try:
        patch_resp = requests.patch(
            f"{PFSENSE_API_URL}/firewall/alias",
            headers=_get_headers(),
            json=patch_payload,
            verify=False,
            timeout=10
        )
        if patch_resp.status_code == 200:
            apply_firewall_changes()
            if action == "add":
                if clean_ip not in STATE["stats"]["blocked_ips"]:
                    STATE["stats"]["blocked_ips"].append(clean_ip)
                log_event("ACTION", f"🔥 ĐÃ CHẶN IP {clean_ip} TRÊN PFSENSE (Alias: SOC_BLOCKLIST)! Lý do: {reason}")
                return True, f"Thành công: Đã thêm IP {clean_ip} vào SOC_BLOCKLIST trên pfSense và đã Apply thay đổi."
            else:
                if clean_ip in STATE["stats"]["blocked_ips"]:
                    STATE["stats"]["blocked_ips"].remove(clean_ip)
                log_event("ACTION", f"✅ ĐÃ GỠ CHẶN IP {clean_ip} TRÊN PFSENSE!")
                return True, f"Thành công: Đã gỡ bỏ IP {clean_ip} khỏi SOC_BLOCKLIST."
        else:
            return False, f"Lỗi pfSense REST API ({patch_resp.status_code}): {patch_resp.text}"
    except Exception as e:
        return False, f"Ngoại lệ khi gọi pfSense REST API: {str(e)}"

FIREWALL_SCHEMA = {
    "name": "tool_block_firewall_ip",
    "description": "Chan IP tan cong ngay lap tuc tren pfSense Firewall (qua REST API v2, them vao Alias SOC_BLOCKLIST) khi xac dinh la True Positive.",
    "parameters": {
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Dia chi IP cua ke tan cong can chan"},
            "reason": {"type": "string", "description": "Ly do chan IP"}
        },
        "required": ["ip", "reason"]
    }
}

@register_tool(FIREWALL_SCHEMA)
def tool_block_firewall_ip(ip: str, reason: str = "Malicious activity"):
    """Thêm IP vào Alias SOC_BLOCKLIST trên pfSense Firewall sau khi qua bộ lọc an toàn"""
    is_valid, check_result = validate_blockable_ip(ip)
    if not is_valid:
        return check_result
    success, msg = _modify_blocklist_alias(check_result, "add", reason)
    return msg

# LƯU Ý: Không đăng ký @register_tool cho tool_unblock_firewall_ip để thu hồi quyền tự gỡ chặn của LLM,
# chỉ giữ hàm phục vụ API Web/Admin an toàn.
def tool_unblock_firewall_ip(ip: str):
    """Gỡ bỏ IP khỏi Alias SOC_BLOCKLIST trên pfSense (Chỉ dành cho Admin / Demo)"""
    if not ip or ip == "unknown":
        return "IP không hợp lệ."
    clean_ip = ip.strip()
    success, msg = _modify_blocklist_alias(clean_ip, "remove")
    return msg

def clear_all_pfsense_blocks():
    """Xóa sạch toàn bộ IP trong SOC_BLOCKLIST (dành cho test demo)"""
    alias = get_or_create_soc_alias()
    if not alias:
        return False, "Không tìm thấy Alias"
    alias_id = alias.get("id")
    patch_payload = {
        "id": alias_id,
        "address": [],
        "detail": []
    }
    try:
        requests.patch(
            f"{PFSENSE_API_URL}/firewall/alias",
            headers=_get_headers(),
            json=patch_payload,
            verify=False,
            timeout=10
        )
        apply_firewall_changes()
        STATE["stats"]["blocked_ips"] = []
        log_event("ACTION", "🧹 ĐÃ XÓA SẠCH TOÀN BỘ IP TRONG SOC_BLOCKLIST TRÊN PFSENSE!")
        return True, "Đã xóa sạch SOC_BLOCKLIST"
    except Exception as e:
        return False, str(e)
