import os
import json
from datetime import datetime
from core.llm import call_ollama
from core.parsers import parse_verdict, extract_mitre_tags, extract_ti_summary
from core.network_utils import is_external_wan_ip
from tools.base import TOOLS_SCHEMA, TOOLS_MAP
from tools.threat_intel_tools import tool_check_file_hash, tool_check_ip_reputation
from tools.firewall_tools import tool_block_firewall_ip
from web.state import STATE, log_event

def run_agent_loop(alert_summary: dict):
    STATE["stats"]["total_alerts"] += 1
    src_ip = alert_summary.get("src_ip", "unknown")
    agent_ip = alert_summary.get("agent_ip", "unknown")
    victim_ip = alert_summary.get("victim_ip", "unknown")
    file_path = alert_summary.get("file_path")
    primary_hash = alert_summary.get("primary_hash")
    if not primary_hash and alert_summary.get("file_hashes"):
        primary_hash = alert_summary.get("file_hashes")[0]

    is_fim = ("syscheck" in str(alert_summary.get("source", "")).lower() or
              bool(file_path) or
              str(alert_summary.get("rule_id")) in ["550", "554", "750"])

    ip_display = f"SRC: {src_ip}" if (src_ip and src_ip != "unknown") else f"Host: {victim_ip}"
    log_event("ALERT", f"Nhận cảnh báo mới: {alert_summary.get('title')} ({ip_display})")

    # =========================================================================
    # QUY TẮC 4: DETERMINISTIC ORCHESTRATION BẰNG PYTHON (TI PRE-ENRICHMENT)
    # =========================================================================
    tool_history = []
    pre_enriched_hash_result = None

    if primary_hash:
        try:
            pre_enriched_hash_result = tool_check_file_hash(primary_hash)
            tool_history.append({
                "role": "tool",
                "content": str(pre_enriched_hash_result),
                "name": "tool_check_file_hash"
            })
        except Exception as ex:
            pre_enriched_hash_result = f"[TI Hash] Lỗi khi tra cứu hash {primary_hash}: {ex}. Status: TI_ERROR / UNKNOWN"
            log_event("ERROR", pre_enriched_hash_result)

    if is_fim or src_ip in ["unknown", None, ""]:
        system_prompt = (
            "Ban la AI SOC Analyst tu hanh cap cao. Day la su kien giam sat FIM / Endpoint tren may chu noi bo:\n"
            "1. Su dung ket qua Threat Intel ma hash da duoc cung cap san (TUYET DOI KHONG tu bia dat so luong engine VirusTotal).\n"
            "2. Neu co chuoi Base64 hoac command ma hoa, goi tool_decode_base64 de giai ma.\n"
            "3. AN TOAN FIREWALL: Day la su kien FIM noi bo (src_ip la 'unknown'), TUYET DOI KHONG goi tool_block_firewall_ip.\n"
            "4. Cuoi cung, ket luan bang tieng Viet theo dinh dang ro rang:\n"
            "   - Phan quyet: [TRUE POSITIVE | FALSE POSITIVE | SUSPICIOUS | UNKNOWN]\n"
            "   - MITRE ATT&CK: [Ma & Ten ky thuat neu co bang chung ro rang]\n"
            "   - Threat Intelligence: [Ket qua TI Hash]\n"
            "   - Nguyen nhan & Bien phap: ..."
        )
    else:
        system_prompt = (
            "Ban la AI SOC Analyst tu hanh cap cao. Day la canh bao TAN CONG MANG (Network IDS / Firewall) tu pfSense/Suricata/Wazuh:\n"
            "1. Kiem tra danh tieng IP nguon tan cong (src_ip) bang tool_check_ip_reputation va tool_check_ip_context.\n"
            "2. Neu co chuoi Base64 hoac command ma hoa, goi tool_decode_base64 de giai ma.\n"
            "3. Chu dong tra cuu ky thuat MITRE ATT&CK bang tool_lookup_mitre_attack (vi du: T1046 cho Scan/Nmap, T1110 cho Brute Force, T1190 cho Web Attack/RCE).\n"
            "4. HANH DONG CHAN FIREWALL BAT BUOC: Neu canh bao la hanh vi quet mang (Nmap/Scan/RDP Probe), tan cong Web, Brute-force, hoac ket noi trai phep tu IP thuoc mang WAN ben ngoai (192.168.63.x) hoac Internet (va IP nguon co Verdict MALICIOUS hoac SUSPICIOUS / ATTACKER), BAT BUOC goi ngay tool_block_firewall_ip de chan src_ip tren pfSense va ket luan TRUE POSITIVE!\n"
            "5. AN TOAN FIREWALL: Chi chan src_ip cua ke tan cong, TUYET DOI KHONG chan victim_ip/dest_ip.\n"
            "6. Cuoi cung, ket luan bang tieng Viet theo dinh dang ro rang:\n"
            "   - Phan quyet: [TRUE POSITIVE | FALSE POSITIVE | SUSPICIOUS | UNKNOWN]\n"
            "   - MITRE ATT&CK: [Ma & Ten ky thuat]\n"
            "   - Threat Intelligence: [Ket qua TI IP/Hash]\n"
            "   - Nguyen nhan & Bien phap: ..."
        )

    # Làm gọn payload gửi cho LLM để tránh hiểu nhầm agent_ip="unknown" của Syslog là sự kiện FIM
    prompt_payload = dict(alert_summary)
    if not is_fim and src_ip not in ["unknown", None, ""]:
        prompt_payload.pop("file_path", None)
        prompt_payload.pop("event_type", None)
        if prompt_payload.get("agent_ip") == "unknown":
            prompt_payload.pop("agent_ip", None)
        if not prompt_payload.get("primary_hash"):
            prompt_payload.pop("primary_hash", None)
            prompt_payload.pop("file_hashes", None)

    user_prompt = f"Phan tich canh bao SOC sau: {json.dumps(prompt_payload, ensure_ascii=False)}"
    if pre_enriched_hash_result:
        user_prompt += f"\n[Ket qua Threat Intelligence kiem tra ma hash {primary_hash}]: {pre_enriched_hash_result}"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]

    final_text = ""
    has_blocked_ip = False

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
                    "content": "Hãy tổng hợp các kết quả tra cứu TI & Tool ở trên và đưa ra kết luận theo định dạng:\n- Phan quyet: [TRUE POSITIVE | FALSE POSITIVE | SUSPICIOUS | UNKNOWN]\n- MITRE ATT&CK: [Mã & Tên]\n- Threat Intelligence: [Kết quả TI]\n- Nguyen nhan & Bien phap: ..."
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
                final_text = "Đã hoàn tất phân tích và thực thi các biện pháp phòng vệ."
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

            # AN TOÀN FIREWALL (QUY TẮC 2 & 6):
            if fn_name == "tool_block_firewall_ip":
                target_ip = str(fn_args.get("ip", "")).strip()
                if (is_fim or src_ip in ["unknown", None, ""] or
                        target_ip in [agent_ip, victim_ip] or
                        target_ip.lower() in ["unknown", "local", "n/a", ""]):
                    result = f"Từ chối chặn: IP '{target_ip}' là máy Endpoint nội bộ (Victim/Agent) hoặc sự kiện FIM không có IP mạng kẻ tấn công."
                    log_event("WARNING", result)
                else:
                    if fn_name in TOOLS_MAP:
                        result = TOOLS_MAP[fn_name](**fn_args)
                        if "Thành công" in str(result) or "đã nằm trong danh sách chặn" in str(result):
                            has_blocked_ip = True
                    else:
                        result = f"Ham {fn_name} khong ton tai."

            # DETERMINISTIC PRE-ENRICHMENT AVOIDANCE (QUY TẮC 4):
            elif fn_name == "tool_check_file_hash" and pre_enriched_hash_result:
                arg_hash = str(fn_args.get("file_hash", "")).strip().lower()
                if primary_hash and arg_hash == primary_hash.lower():
                    result = pre_enriched_hash_result
                else:
                    result = TOOLS_MAP[fn_name](**fn_args) if fn_name in TOOLS_MAP else "Ham khong ton tai."
            else:
                if fn_name in TOOLS_MAP:
                    result = TOOLS_MAP[fn_name](**fn_args)
                else:
                    result = f"Ham {fn_name} khong ton tai."

            tool_msg = {"role": "tool", "content": str(result), "name": fn_name}
            messages.append(tool_msg)
            tool_history.append(tool_msg)

    if not final_text:
        final_text = "Đã hoàn tất quá trình điều tra sự cố."

    # Nếu là sự kiện mạng có src_ip hợp lệ mà Qwen chưa kịp gọi tool_check_ip_reputation, tự động bổ sung TI cho src_ip
    if not is_fim and src_ip and src_ip != "unknown":
        checked_src_ti = any(
            item.get("name") == "tool_check_ip_reputation" and src_ip in str(item.get("content", ""))
            for item in tool_history
        )
        if not checked_src_ti:
            try:
                ip_ti_res = tool_check_ip_reputation(src_ip)
                tool_history.insert(0, {"role": "tool", "content": str(ip_ti_res), "name": "tool_check_ip_reputation"})
            except Exception:
                pass

    mitre_tags = extract_mitre_tags(final_text, alert_summary.get("mitre"), tool_history)
    ti_summary = extract_ti_summary(tool_history, preferred_ip=src_ip if not is_fim else None)

    verdict = parse_verdict(
        final_text,
        has_blocked_ip=has_blocked_ip,
        is_fim=is_fim,
        ti_summary=ti_summary,
        primary_hash=primary_hash
    )

    # Cơ chế đảm bảo thực thi chặn tự động (Deterministic SOAR Enforcement) khi phát hiện tấn công mạng từ WAN Attacker
    if (not is_fim and not has_blocked_ip and
            src_ip and src_ip != "unknown" and
            src_ip not in [agent_ip, victim_ip] and
            is_external_wan_ip(src_ip) and
            verdict in ["TRUE POSITIVE", "SUSPICIOUS"]):
        title_lower = (str(alert_summary.get("title", "")) + " " + str(alert_summary.get("full_log", ""))).lower()
        is_attack_traffic = (
            verdict == "TRUE POSITIVE" or
            any(k in title_lower for k in ["scan", "nmap", "exploit", "attack", "blocked traffic", "brute", "sql", "rce", "shell", "terminal server"])
        )
        if is_attack_traffic:
            reason_str = alert_summary.get("title", "Network Attack from External WAN")
            log_event("THOUGHT", f"Kích hoạt SOAR tự động chặn IP tấn công ngoại vi: tool_block_firewall_ip({{\"ip\": \"{src_ip}\"}})")
            block_res = tool_block_firewall_ip(ip=src_ip, reason=reason_str)
            if "Thành công" in str(block_res) or "đã nằm trong danh sách chặn" in str(block_res):
                has_blocked_ip = True
                verdict = "TRUE POSITIVE"

    # Cập nhật thống kê STATE (QUY TẮC 8)
    if verdict == "TRUE POSITIVE":
        STATE["stats"]["true_positives"] += 1
    elif verdict == "FALSE POSITIVE":
        STATE["stats"]["false_positives"] += 1
    elif verdict == "SUSPICIOUS":
        STATE["stats"]["suspicious"] += 1
    elif verdict == "UNKNOWN":
        STATE["stats"]["unknown"] += 1

    log_event("VERDICT", f"[{verdict}] {final_text[:120]}...")
    STATE["decisions"].appendleft({
        "time": datetime.now().strftime("%H:%M:%S"),
        "source": alert_summary.get("source", "pfSense / Wazuh SIEM"),
        "title": alert_summary.get("title", "Cảnh báo an ninh"),
        "src_ip": src_ip,
        "agent_ip": agent_ip,
        "victim_ip": victim_ip,
        "primary_hash": primary_hash,
        "file_path": file_path,
        "verdict": verdict,
        "mitre": mitre_tags,
        "ti_summary": ti_summary,
        "summary": final_text
    })
