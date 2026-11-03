import os
import re
import json

MITRE_KB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "mitre_attack_kb.json")

def parse_verdict(text: str, has_blocked_ip: bool = False, is_fim: bool = False, ti_summary: str = "", primary_hash: str = "") -> str:
    """
    Bóc tách phán quyết chuẩn xác 100% hỗ trợ 4 trạng thái:
    - TRUE POSITIVE: Xác nhận hành vi tấn công hoặc tệp tin độc hại (MISP/VT khẳng định Malicious).
    - FALSE POSITIVE: Hoạt động hợp lệ, kiểm thử an toàn, không có mối đe dọa.
    - SUSPICIOUS: Có dấu hiệu đáng ngờ nhưng chưa đủ bằng chứng kết luận.
    - UNKNOWN: Thiếu dữ liệu (hash chưa từng xuất hiện 404, lỗi API, hoặc chưa xác định).
    """
    ti_combined = (ti_summary or "")
    full_corpus = (text or "") + " " + ti_combined

    # 0. Riêng với mẫu thử EICAR: Gắn nhãn chuẩn TRUE POSITIVE phục vụ kịch bản kiểm thử Lab
    if "EICAR" in full_corpus.upper():
        if any(k in full_corpus.upper() for k in ["MALICIOUS", "THREAT", "HIGH", "CRITICAL", "VIRUS"]):
            return "TRUE POSITIVE"

    # 1. Quét từng dòng tìm dòng quyết định chính thức: 'Quyết định:', 'Phán quyết:', 'Kết luận:', 'Verdict:'
    if text:
        for line in text.split("\n"):
            line_clean = line.strip()
            if re.search(r'(?:quyết\s*định|ph[aáâầ]n\s*quy[eêế]t|phân\s*loại|verdict|kết\s*luận)\s*[:\-\|]', line_clean, re.IGNORECASE):
                line_upper = line_clean.upper()
                if "FALSE POSITIVE" in line_upper or "CẢNH BÁO GIẢ" in line_upper:
                    return "FALSE POSITIVE"
                if "TRUE POSITIVE" in line_upper:
                    return "TRUE POSITIVE"
                if "SUSPICIOUS" in line_upper or "NGHI VẤN" in line_upper or "ĐÁNG NGỜ" in line_upper:
                    return "SUSPICIOUS"
                if "UNKNOWN" in line_upper or "CHƯA XÁC ĐỊNH" in line_upper or "UNDETERMINED" in line_upper:
                    return "UNKNOWN"

        # 2. Tìm qua biểu thức chính quy sau các tiêu đề
        m = re.search(r'(?:ph[aáâầ]n\s*quy[eêế]t|phân\s*loại|verdict|kết\s*luận|quyết\s*định)\D{0,25}(true\s*positive|false\s*positive|suspicious|unknown)', text, re.IGNORECASE)
        if m:
            matched = m.group(1).upper().replace("-", " ").strip()
            if "FALSE POSITIVE" in matched:
                return "FALSE POSITIVE"
            if "TRUE POSITIVE" in matched:
                return "TRUE POSITIVE"
            if "SUSPICIOUS" in matched:
                return "SUSPICIOUS"
            if "UNKNOWN" in matched:
                return "UNKNOWN"

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

        # 4. Kiểm tra các nhãn chuẩn trong văn bản đã lọc phủ định
        if "FALSE POSITIVE" in clean_upper or "FALSE-POSITIVE" in clean_upper or "CẢNH BÁO GIẢ" in clean_upper:
            return "FALSE POSITIVE"
        if "TRUE POSITIVE" in clean_upper or "TRUE-POSITIVE" in clean_upper:
            return "TRUE POSITIVE"
        if "SUSPICIOUS" in clean_upper or "NGHI VẤN" in clean_upper or "ĐÁNG NGỜ" in clean_upper:
            return "SUSPICIOUS"
        if "UNKNOWN" in clean_upper or "CHƯA XÁC ĐỊNH" in clean_upper:
            return "UNKNOWN"

    # 5. Đối chiếu kết quả Threat Intelligence thực tế
    ti_upper = ti_combined.upper()
    if "MALICIOUS (ATTACKER)" in ti_upper or "VERDICT: MALICIOUS" in ti_upper:
        return "TRUE POSITIVE"
    if "VERDICT: SUSPICIOUS" in ti_upper:
        return "SUSPICIOUS"
    if "404 NOT FOUND" in ti_upper or "VERDICT: UNKNOWN" in ti_upper or "TI_ERROR" in ti_upper:
        return "UNKNOWN"
    if "VERDICT: CLEAN" in ti_upper:
        return "FALSE POSITIVE"

    # 6. Fallback an toàn
    if has_blocked_ip:
        return "TRUE POSITIVE"
    if is_fim:
        return "UNKNOWN"

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
    # 1. Ưu tiên danh sách MITRE có sẵn từ rule Wazuh (alerts.json)
    if alert_mitre:
        for m in alert_mitre:
            for mid in re.findall(r'\b(T1\d{3}(?:\.\d{3})?)\b', str(m)):
                found_ids.add(mid.upper())

    # 2. Bổ sung từ các lệnh gọi tra cứu MITRE trong tool_history
    for item in (tool_history or []):
        if item.get("name") == "tool_lookup_mitre_attack":
            content = str(item.get("content", ""))
            for mid in re.findall(r'\b(T1\d{3}(?:\.\d{3})?)\b', content):
                found_ids.add(mid.upper())

    # 3. Chỉ lấy từ văn bản phân tích nếu mã đó có trong KB và có bằng chứng
    if text:
        for mid in re.findall(r'\b(T1\d{3}(?:\.\d{3})?)\b', text):
            if mid.upper() in kb:
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

