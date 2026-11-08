import ipaddress

def is_valid_ip(ip_str: str) -> bool:
    """Kiểm tra chuỗi có phải là địa chỉ IPv4/IPv6 hợp lệ hay không"""
    if not ip_str or not isinstance(ip_str, str):
        return False
    clean = ip_str.strip()
    if clean.lower() in ["unknown", "local", "localhost", "none", ""]:
        return False
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False

def is_private_ip(ip_str: str) -> bool:
    """Kiểm tra IP có thuộc dải Private/Loopback/Link-local hay không"""
    if not is_valid_ip(ip_str):
        return False
    try:
        obj = ipaddress.ip_address(ip_str.strip())
        return obj.is_private or obj.is_loopback or obj.is_link_local
    except ValueError:
        return False

WAN_INFRA_IPS = {
    "192.168.63.1",    # Host GPU
    "192.168.63.134",  # pfSense WAN Interface
    "192.168.63.138",  # SOC Server WAN Interface
    "192.168.63.255"   # Broadcast
}

def is_external_wan_ip(ip_str: str) -> bool:
    """
    Kiểm tra xem IP có thuộc vùng mạng WAN bên ngoài (192.168.63.0/24 trừ các IP hạ tầng bảo vệ)
    hoặc là Public IP ngoài Internet hay không.
    """
    if not is_valid_ip(ip_str):
        return False
    clean_ip = ip_str.strip()
    if clean_ip in WAN_INFRA_IPS:
        return False
    if clean_ip.startswith("192.168.63."):
        return True
    if not is_private_ip(clean_ip):
        return True
    return False

def classify_subnet(ip_str: str) -> str:
    """
    Hàm phân loại Subnet dùng chung duy nhất cho toàn bộ hệ thống SOC:
    Xóa bỏ code smell Repeated Switches giữa analysis_tools và threat_intel_tools.
    """
    if not ip_str or not isinstance(ip_str, str):
        return "Địa chỉ không xác định"

    clean_ip = ip_str.strip()
    if not is_valid_ip(clean_ip):
        return "Địa chỉ IP không hợp lệ"

    if clean_ip == "192.168.171.2" or clean_ip == "192.168.63.134":
        return "pfSense Firewall Gateway (Protected Infrastructure)"
    elif clean_ip in WAN_INFRA_IPS:
        return "Hạ tầng Quản trị SOC / Host Gateway (Protected Infrastructure)"
    elif clean_ip.startswith("192.168.63."):
        return "Mạng WAN bên ngoài (External Attacker Subnet)"
    elif clean_ip.startswith("192.168.214."):
        return "Victim LAN 1 (Hệ thống máy chủ/máy trạm bảo vệ nội bộ)"
    elif clean_ip.startswith("192.168.45."):
        return "Victim LAN 2 (Hạ tầng máy trạm nội bộ bảo vệ)"
    elif clean_ip.startswith("192.168.171."):
        return "pfSense Transit / SOC Management Network (Protected)"
    elif clean_ip == "127.0.0.1" or clean_ip == "::1":
        return "Loopback Interface"

    if is_private_ip(clean_ip):
        return "Private Subnet nội bộ"

    return "Địa chỉ Internet bên ngoài (Public IP)"

