import os
import json
from datetime import datetime
from core.llm import call_ollama
from core.parsers import parse_verdict, extract_mitre_tags, extract_ti_summary
from tools.base import TOOLS_SCHEMA, TOOLS_MAP
from web.state import STATE, log_event

def run_agent_loop(alert_summary: dict):
    STATE["stats"]["total_alerts"] += 1
    log_event("ALERT", f"Nhận cảnh báo mới: {alert_summary.get('title')} (SRC: {alert_summary.get('src_ip')})")

    system_prompt = (
        "Ban la AI SOC Analyst tu hanh cap cao. Khi nhan canh bao JSON tu pfSense/Suricata/Wazuh SIEM:\n"
        "1. Kiem tra danh tieng IP bang tool_check_ip_reputation (hoac tool_query_misp_ioc voi IP/Domain/CVE lab).\n"
        "2. Neu canh bao co chua ma hash, chuoi file, hoac duong dan URL/file nghi van, BAT BUOC goi tool_check_file_hash de tra cuu VirusTotal & MISP.\n"
        "3. Neu co chuoi Base64 hoac command ma hoa, goi tool_decode_base64 de giai ma.\n"
        "4. Chu dong tra cuu ky thuat MITRE ATT&CK bang tool_lookup_mitre_attack (vi du: T1046 cho Scan, T1110 cho Brute Force, T1059.001 cho PowerShell, T1190 cho Web Exploit/RCE, T1505.003 cho Web Shell, T1021 cho Lateral Movement) de lay Tactic va bien phap khac phuc.\n"
        "5. Neu phat hien tan cong mang tu IP ben ngoai (True Positive), BAT BUOC goi tool_block_firewall_ip de chan ngay tren pfSense (Alias SOC_BLOCKLIST).\n"
        "6. Cuoi cung, ket luan bang tieng Viet theo dinh dang ro rang:\n"
        "   - Phan quyet: [TRUE POSITIVE hoac FALSE POSITIVE]\n"
        "   - MITRE ATT&CK: [Ma & Ten ky thuat]\n"
        "   - Threat Intelligence: [Tien trinh & Diem danh tieng IP/Hash]\n"
        "   - Nguyen nhan: ...\n"
        "   - Bien phap phong ve: ..."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Phan tich canh bao SOC sau: {json.dumps(alert_summary, ensure_ascii=False)}"}
    ]

    final_text = ""
    has_blocked_ip = False
    tool_history = []

    for step in range(5):
        # Ở bước cuối cùng (step == 4), không gửi tools nữa để ép Qwen phải ra kết luận văn bản
        current_tools = TOOLS_SCHEMA if step < 4 else None
        try:
            resp = call_ollama(messages, current_tools)
        except Exception as e:
            log_event("ERROR", f"Không kết nối được Ollama: {e}")
            final_text = f"Lỗi kết nối bộ não AI Ollama ({e}). Cảnh báo đã được ghi nhận."
            break

        msg = resp.get("message", {})
        messages.append(msg)

        tool_calls = msg.get("tool_calls", [])
        if not tool_calls or step == 4:
            content_val = msg.get("content", "").strip()
            thinking_val = msg.get("thinking", "").strip()
            final_text = content_val or thinking_val

            if not content_val:
                messages.append({
                    "role": "user",
                    "content": "Hãy tổng hợp các kết quả tra cứu TI & Tool ở trên và đưa ra kết luận theo định dạng:\n- Phan quyet: [TRUE POSITIVE hoặc FALSE POSITIVE]\n- MITRE ATT&CK: [Mã & Tên]\n- Threat Intelligence: [Kết quả TI]\n- Nguyen nhan & Bien phap: ..."
                })
                try:
                    summary_resp = call_ollama(messages, None)
                    s_msg = summary_resp.get("message", {})
                    s_content = s_msg.get("content", "").strip()
                    s_thinking = s_msg.get("thinking", "").strip()
                    if s_content:
                        final_text = s_content
                    elif s_thinking:
                        final_text = s_thinking
                except Exception as ex:
                    log_event("WARNING", f"Lỗi tổng hợp kết luận: {ex}")

            if not final_text:
                final_text = "Đã hoàn tất phân tích và thực thi các biện pháp phòng vệ trên pfSense."
            break

        for call in tool_calls:
            fn_name = call["function"]["name"]
            fn_args = call["function"]["arguments"]
            if isinstance(fn_args, str):
                try:
                    fn_args = json.loads(fn_args)
                except Exception:
                    fn_args = {}
            log_event("THOUGHT", f"Qwen gọi hàm: {fn_name}({json.dumps(fn_args)})")

            if fn_name == "tool_block_firewall_ip":
                has_blocked_ip = True

            if fn_name in TOOLS_MAP:
                result = TOOLS_MAP[fn_name](**fn_args)
            else:
                result = f"Ham {fn_name} khong ton tai."

            tool_msg = {"role": "tool", "content": str(result), "name": fn_name}
            messages.append(tool_msg)
            tool_history.append(tool_msg)

    if not final_text:
        final_text = "Đã hoàn tất quá trình điều tra sự cố."

    verdict = parse_verdict(final_text, has_blocked_ip=has_blocked_ip)

    if verdict == "TRUE POSITIVE":
        STATE["stats"]["true_positives"] += 1
    else:
        STATE["stats"]["false_positives"] += 1

    mitre_tags = extract_mitre_tags(final_text, alert_summary.get("mitre"), tool_history)
    ti_summary = extract_ti_summary(tool_history)

    log_event("VERDICT", f"[{verdict}] {final_text[:120]}...")
    STATE["decisions"].appendleft({
        "time": datetime.now().strftime("%H:%M:%S"),
        "source": alert_summary.get("source", "pfSense / Wazuh SIEM"),
        "title": alert_summary.get("title", "Cảnh báo an ninh"),
        "src_ip": alert_summary.get("src_ip", "unknown"),
        "verdict": verdict,
        "mitre": mitre_tags,
        "ti_summary": ti_summary,
        "summary": final_text
    })
