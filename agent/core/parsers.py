import os
import re
import json

MITRE_KB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "mitre_attack_kb.json")

def parse_verdict(text: str, has_blocked_ip: bool = False) -> str:
    """
    Bóc tách phán quyết chuẩn xác 100%:
    1. Ưu tiên dòng kết luận chính thức: 'Quyết định:', 'Phán quyết:', 'Kết luận:', 'Verdict:'
    2. Triệt tiêu các cụm phủ định tiếng Việt ('không có hành vi tấn công', 'không phải tấn công', 'không phải false positive'...)
    3. Trả về chuẩn 'TRUE POSITIVE' hoặc 'FALSE POSITIVE'.
    """
    if not text:
        return "TRUE POSITIVE" if has_blocked_ip else "FALSE POSITIVE"

    # 1. Quét từng dòng tìm dòng quyết định chính thức
    for line in text.split("\n"):
        line_clean = line.strip()
        if re.search(r'(?:quyết\s*định|ph[aáâầ]n\s*quy[eêế]t|phân\s*loại|verdict|kết\s*luận)\s*[:\-\|]', line_clean, re.IGNORECASE):
            line_upper = line_clean.upper()
            if "FALSE POSITIVE" in line_upper or "CẢNH BÁO GIẢ" in line_upper:
                return "FALSE POSITIVE"
            if "TRUE POSITIVE" in line_upper:
                return "TRUE POSITIVE"

    # 2. Tìm qua biểu thức chính quy sau các tiêu đề
    m = re.search(r'(?:ph[aáâầ]n\s*quy[eêế]t|phân\s*loại|verdict|kết\s*luận|quyết\s*định)\D{0,25}(true\s*positive|false\s*positive)', text, re.IGNORECASE)
    if m:
        matched = m.group(1).upper().replace("-", " ").strip()
        if "FALSE POSITIVE" in matched:
            return "FALSE POSITIVE"
        if "TRUE POSITIVE" in matched:
            return "TRUE POSITIVE"

    # 3. Loại bỏ triệt để các cụm phủ định tiếng Việt để không bị bắt nhầm
    clean_text = text
    negation_patterns = [
        r'kh[oô]ng\s*ph[aả]i\s*(?:l[aà]\s*)?false\s*positive',
        r'not\s*(?:a\s*)?false\s*positive',
        r'kh[oô]ng\s*ph[aả]i\s*c[aả]nh\s*b[aá]o\s*gi[aả]',
        r'kh[oô]ng\s*ph[aả]i\s*(?:l[aà]\s*)?t[aấ]n\s*c[oô]ng',
        r'kh[oô]ng\s*c[oó]\s*(?:d[aấ]u\s*hi[eệ]u|h[aà]nh\s*vi)\s*t[aấ]n\s*c[oô]ng',
        r'kh[oô]ng\s*ph[aá]t\s*hi[eệ]n\s*t[aấ]n\s*c[oô]ng',
        r'lo[aạ]i\s*b[oỏ]\s*kh[oỏ]i\s*danh\s*m[uụ]c\s*t[aấ]n\s*c[oô]ng',
        r'kh[oô]ng\s*ph[aả]i\s*h[aà]nh\s*vi\s*\u0111[oộ]c\s*h[aạ]i',
        r'kh[oô]ng\s*c[oó]\s*ho[aạ]t\s*\u0111[oộ]ng\s*\u0111[oộ]c\s*h[aạ]i'
    ]
    for pattern in negation_patterns:
        clean_text = re.sub(pattern, '', clean_text, flags=re.IGNORECASE)

    clean_upper = clean_text.upper()

    # 4. Kiểm tra các nhãn chuẩn
    if "FALSE POSITIVE" in clean_upper or "FALSE-POSITIVE" in clean_upper or "CẢNH BÁO GIẢ" in clean_upper:
        return "FALSE POSITIVE"
    if "TRUE POSITIVE" in clean_upper or "TRUE-POSITIVE" in clean_upper:
        return "TRUE POSITIVE"
    if "MALICIOUS (ATTACKER)" in clean_upper or "VERDICT: MALICIOUS" in clean_upper:
        return "TRUE POSITIVE"

    # 5. Fallback: Nếu AI đã chủ động gọi lệnh chặn Firewall, chắc chắn là TRUE POSITIVE
    if has_blocked_ip:
        return "TRUE POSITIVE"

    return "FALSE POSITIVE"

def extract_mitre_tags(text: str, alert_mitre: list = None, tool_history: list = None) -> list:
    """Trích xuất và chuẩn hóa danh sách tag MITRE ATT&CK kèm tên kỹ thuật"""
    kb = {}
    if os.path.exists(MITRE_KB_PATH):
        try:
            with open(MITRE_KB_PATH, "r", encoding="utf-8") as f:
                kb = json.load(f)
        except Exception:
            pass

    found_ids = set()
    if alert_mitre:
        for m in alert_mitre:
            for mid in re.findall(r'\b(T1\d{3}(?:\.\d{3})?)\b', str(m)):
                found_ids.add(mid.upper())

    all_content = text + " " + " ".join([str(t.get("content", "")) for t in (tool_history or [])])
    for mid in re.findall(r'\b(T1\d{3}(?:\.\d{3})?)\b', all_content):
        found_ids.add(mid.upper())

    result = []
    for mid in sorted(list(found_ids)):
        if mid in kb:
            result.append(f"{mid} - {kb[mid].get('name')}")
        else:
            result.append(mid)

    return result

def extract_ti_summary(tool_history: list) -> str:
    """
    Trích xuất tóm tắt kết quả Threat Intelligence từ các tool đã chạy:
    Bắt chuẩn 100% cả [TI Public IP], [TI Private IP], [TI Hash], [MISP IOC]
    """
    ti_findings = []
    valid_markers = ["[TI Public IP]", "[TI Private IP]", "[TI Hash]", "[MISP IOC]"]
    for item in (tool_history or []):
        content = str(item.get("content", ""))
        if any(marker in content for marker in valid_markers):
            ti_findings.append(content)
    if ti_findings:
        return " | ".join(ti_findings[:2])
    return ""

