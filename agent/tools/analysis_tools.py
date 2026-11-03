import base64
from tools.base import register_tool
from web.state import log_event
from core.network_utils import classify_subnet

DECODE_SCHEMA = {
    "name": "tool_decode_base64",
    "description": "Giai ma chuoi ma hoa Base64 phat hien trong log lenh nghi van.",
    "parameters": {
        "type": "object",
        "properties": {
            "encoded_str": {"type": "string", "description": "Chuoi Base64 can giai ma"}
        },
        "required": ["encoded_str"]
    }
}

CONTEXT_SCHEMA = {
    "name": "tool_check_ip_context",
    "description": "Kiem tra xem IP thuoc mang WAN hay mang Victim LAN noi bo.",
    "parameters": {
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Dia chi IP can kiem tra"}
        },
        "required": ["ip"]
    }
}

@register_tool(DECODE_SCHEMA)
def tool_decode_base64(encoded_str: str):
    try:
        decoded = base64.b64decode(encoded_str).decode("utf-8", errors="ignore")
        log_event("TOOL", f"Giải mã Base64 kết quả: {decoded[:100]}")
        return f"Noi dung giai ma: {decoded}"
    except Exception as e:
        return f"Loi giai ma: {str(e)}"

@register_tool(CONTEXT_SCHEMA)
def tool_check_ip_context(ip: str):
    log_event("TOOL", f"Kiểm tra ngữ cảnh mạng IP: {ip}")
    desc = classify_subnet(ip)
    return f"IP {ip} thuộc phân vùng: {desc}"
