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

    if clean_ip == "192.168.171.2":
        return "pfSense Firewall Management Gateway"
    elif clean_ip.startswith("192.168.63."):
        return "Lab WAN / External Attacker Subnet"
    elif clean_ip.startswith("192.168.214."):
        return "Victim LAN 1 (Hệ thống máy chủ/máy trạm bảo vệ)"
    elif clean_ip.startswith("192.168.45."):
        return "Victim LAN 2 (Hạ tầng mạng nội bộ)"
    elif clean_ip.startswith("192.168.171."):
        return "pfSense Transit / SOC Management Network"
    elif clean_ip == "127.0.0.1" or clean_ip == "::1":
        return "Loopback Interface"

    if is_private_ip(clean_ip):
        return "Private Subnet nội bộ"

    return "Địa chỉ Internet bên ngoài (Public IP)"

