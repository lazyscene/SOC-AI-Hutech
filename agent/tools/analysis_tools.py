import base64
from tools.base import register_tool
from web.state import STATE, log_event
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
    clean_ip = (ip or "").strip()
    log_event("TOOL", f"Kiểm tra ngữ cảnh mạng IP: {clean_ip}")
    desc = classify_subnet(clean_ip)
    parts = [f"IP {clean_ip} thuộc phân vùng: {desc}"]

    blocked_ips = STATE.get("stats", {}).get("blocked_ips", [])
    if clean_ip and clean_ip in blocked_ips:
        block_reason = STATE.get("pfsense_block_details", {}).get(clean_ip, "SOC_BLOCKLIST")
        parts.append(f"Trạng thái pfSense: ĐÃ CHẶN trong SOC_BLOCKLIST ({block_reason})")
    else:
        parts.append("Trạng thái pfSense: Chưa nằm trong SOC_BLOCKLIST")

    tp_count = sum(
        1 for d in list(STATE.get("decisions", []))
        if isinstance(d, dict) and d.get("src_ip") == clean_ip and d.get("verdict") == "TRUE POSITIVE"
    )
    if tp_count > 0:
        parts.append(f"Lịch sử SOC: Đã từng bị kết luận TRUE POSITIVE {tp_count} lần trước đó")

    return " | ".join(parts)
