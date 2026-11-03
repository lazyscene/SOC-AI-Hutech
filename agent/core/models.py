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

@dataclass
class AlertEvent:
    """
    Cấu trúc dữ liệu chuẩn cho Cảnh báo An ninh SOC (Data Clump & Primitive Obsession Refactor)
    """
    source: str
    rule_id: str
    level: int
    title: str
    agent: str
    src_ip: str
    dest_ip: str
    full_log: str
    mitre_ids: List[str] = field(default_factory=list)
    file_hashes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "rule_id": self.rule_id,
            "level": self.level,
            "title": self.title,
            "agent": self.agent,
            "src_ip": self.src_ip,
            "dest_ip": self.dest_ip,
            "mitre": self.mitre_ids if self.mitre_ids else None,
            "file_hashes": self.file_hashes if self.file_hashes else None,
            "full_log": self.full_log[:350]
        }

