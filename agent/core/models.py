import re
from dataclasses import dataclass, field
from typing import List, Any, Optional

def safe_get(data: Any, *keys: str, default: Any = None) -> Any:
    """
    Truy xuất an toàn qua chuỗi khóa từ điển lồng nhau, loại bỏ Message Chains:
    Ví dụ: safe_get(d, "win", "eventdata", "hashes") thay cho d.get("win", {}).get(...)
    """
    curr = data
    for k in keys:
        if isinstance(curr, dict):
            curr = curr.get(k)
        else:
            return default
        if curr is None:
            return default
    return curr

def normalize_hash(h: Any) -> Optional[str]:
    """
    Chuẩn hóa và kiểm tra chặt chẽ định dạng hex chữ thường của mã băm:
    - SHA256: 64 ký tự hex
    - SHA1: 40 ký tự hex
    - MD5: 32 ký tự hex
    Trả về chuỗi lowercase hợp lệ, hoặc None nếu không hợp lệ.
    """
    if not h or not isinstance(h, str):
        return None
    clean = h.strip().lower()
    if len(clean) == 64 and re.match(r'^[a-f0-9]{64}$', clean):
        return clean
    if len(clean) == 40 and re.match(r'^[a-f0-9]{40}$', clean):
        return clean
    if len(clean) == 32 and re.match(r'^[a-f0-9]{32}$', clean):
        return clean
    return None

@dataclass
class AlertEvent:
    """
    Cấu trúc dữ liệu chuẩn cho Cảnh báo An ninh SOC:
    Tách biệt rõ ràng ngữ nghĩa IP mạng (src_ip, dest_ip) và Endpoint (agent_ip, victim_ip)
    """
    source: str
    rule_id: str
    level: int
    title: str
    agent: str
    src_ip: Optional[str] = "unknown"
    dest_ip: Optional[str] = "unknown"
    agent_ip: str = "unknown"
    victim_ip: str = "unknown"
    full_log: str = ""
    primary_hash: Optional[str] = None
    file_hashes: List[str] = field(default_factory=list)
    mitre_ids: List[str] = field(default_factory=list)
    file_path: Optional[str] = None
    event_type: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "rule_id": self.rule_id,
            "level": self.level,
            "title": self.title,
            "agent": self.agent,
            "src_ip": self.src_ip or "unknown",
            "dest_ip": self.dest_ip or "unknown",
            "agent_ip": self.agent_ip or "unknown",
            "victim_ip": self.victim_ip or "unknown",
            "primary_hash": self.primary_hash,
            "file_hashes": self.file_hashes if self.file_hashes else None,
            "mitre": self.mitre_ids if self.mitre_ids else None,
            "file_path": self.file_path,
            "event_type": self.event_type,
            "full_log": (self.full_log or "")[:350]
        }

