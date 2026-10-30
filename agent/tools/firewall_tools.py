import subprocess
from tools.base import register_tool
from web.state import STATE, log_event

FIREWALL_SCHEMA = {
    "name": "tool_block_firewall_ip",
    "description": "Chan IP tan cong ngay lap tuc tren Linux Firewall bang iptables khi xac dinh la True Positive.",
    "parameters": {
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Dia chi IP can chan"},
            "reason": {"type": "string", "description": "Ly do chan IP"}
        },
        "required": ["ip", "reason"]
    }
}

@register_tool(FIREWALL_SCHEMA)
def tool_block_firewall_ip(ip: str, reason: str = "Malicious activity"):
    whitelist = ["127.0.0.1", "192.168.63.1", "192.168.63.138", "192.168.214.1", "192.168.214.2", "192.168.100.1", "192.168.100.2"]
    if ip in whitelist:
        return f"Tu choi chan IP he thong quan trong: {ip}"
    try:
        subprocess.run(["iptables", "-C", "AI_AGENT_BLOCK", "-s", ip, "-j", "DROP"], check=True, stderr=subprocess.DEVNULL)
        return f"IP {ip} da bi chan tu truoc."
    except subprocess.CalledProcessError:
        subprocess.run(["iptables", "-I", "AI_AGENT_BLOCK", "1", "-s", ip, "-j", "DROP"], check=False)
        subprocess.run(["iptables", "-I", "AI_AGENT_BLOCK", "1", "-d", ip, "-j", "DROP"], check=False)
        if ip not in STATE["stats"]["blocked_ips"]:
            STATE["stats"]["blocked_ips"].append(ip)
        log_event("ACTION", f"🔥 ĐÃ CHẶN IP {ip} TRÊN FIREWALL! Lý do: {reason}")
        return f"Thanh cong: Da chan hai chieu cho IP {ip}."

