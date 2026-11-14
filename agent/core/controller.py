import os
import json
from datetime import datetime
from core.llm import call_ollama
from core.parsers import parse_verdict, extract_mitre_tags, extract_ti_summary
from core.network_utils import is_external_wan_ip
from core.case_manager import (
    ingest_alert_into_case,
    finalize_case_analysis,
    correlate_cross_domain_cases,
    get_case_by_id,
)
from tools.base import TOOLS_SCHEMA, TOOLS_MAP
from tools.threat_intel_tools import tool_check_file_hash, tool_check_ip_reputation
from tools.firewall_tools import tool_block_firewall_ip
from tools.wazuh_tools import (
    execute_phase1_fast_containment,
    tool_wazuh_endpoint_response,
    validate_target_agent,
)
from web.state import STATE, log_event, get_agent_memory_context, save_persistent_state

def run_agent_loop(alert_summary: dict):
    replay_case_id = alert_summary.get("_replay_case_id")
    if not replay_case_id:
        STATE["stats"]["total_alerts"] += 1

    src_ip = alert_summary.get("src_ip", "unknown")
    agent_id = str(alert_summary.get("agent_id") or "000")
    agent_name = str(alert_summary.get("agent") or "endpoint")
    agent_ip = alert_summary.get("agent_ip", "unknown")
    victim_ip = alert_summary.get("victim_ip", "unknown")
    file_path = alert_summary.get("file_path")
    process_name = alert_summary.get("process_name")
    process_id = alert_summary.get("process_id")
    primary_hash = alert_summary.get("primary_hash")
    if not primary_hash and alert_summary.get("file_hashes"):
        primary_hash = alert_summary.get("file_hashes")[0]

    # =========================================================================
    # QUẢN LÝ CASE & GIẢM TẢI SLM (CORRELATION & SMART RE-EVALUATION)
    # =========================================================================
    if replay_case_id and get_case_by_id(replay_case_id):
        case_obj = get_case_by_id(replay_case_id)
        should_call_slm = True
        slm_reason = f"Replay kiểm toán {replay_case_id}"
    else:
        case_info = ingest_alert_into_case(alert_summary)
        case_obj = case_info["case"]
        should_call_slm = case_info["should_call_slm"]
        slm_reason = case_info["reason"]

    if not should_call_slm:
        log_event(
            "CASE",
            f"📥 Đã gộp cảnh báo '{alert_summary.get('title')}' vào {case_obj['id']} "
            f"(Tổng: {case_obj['alert_count']} alerts) — Bỏ qua gọi lặp SLM ({slm_reason})."
        )
        correlate_cross_domain_cases()
        save_persistent_state()
        return

    case_obj["is_analyzing"] = True
    try:
        is_fim = ("syscheck" in str(alert_summary.get("source", "")).lower() or
                  bool(file_path) or
                  str(alert_summary.get("rule_id")) in ["550", "554", "750"])

        ip_display = f"SRC: {src_ip}" if (src_ip and src_ip != "unknown") else f"Host: {victim_ip}"
        log_event("ALERT", f"[{case_obj['id']}] Nhận cảnh báo mới ({slm_reason}): {alert_summary.get('title')} ({ip_display})")

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

        # =========================================================================
        # GIAI ĐOẠN 1 (FAST CONTAINMENT): PHẢN ỨNG TỨC THÌ TẠI MÁY TRẠM QUA WAZUH AR
        # =========================================================================
        is_endpoint_event = is_fim or (src_ip in ["unknown", None, ""])
        valid_agent, _ = validate_target_agent(agent_id)
        is_malicious_ti = bool(
            pre_enriched_hash_result and "VERDICT: MALICIOUS" in str(pre_enriched_hash_result).upper()
        )
        alert_level = int(alert_summary.get("level", 0) or 0)

        phase1_info = None
        if is_endpoint_event and valid_agent and (is_malicious_ti or (alert_level >= 10 and bool(file_path))):
            phase1_info = execute_phase1_fast_containment(
                agent_id=agent_id,
                agent_name=agent_name,
                victim_ip=victim_ip,
                file_path=file_path,
                process_name=process_name,
                process_id=process_id,
                reason=alert_summary.get("title", "Phát hiện tệp/tiến trình độc hại trên Endpoint"),
            )

        if is_endpoint_event:
            system_prompt = (
                "Ban la AI SOC Analyst tu hanh cap cao. Day la su kien giam sat FIM / Endpoint EDR tren may tram:\n"
                "1. Su dung ket qua Threat Intel ma hash da duoc cung cap san (TUYET DOI KHONG tu bia dat so luong engine VirusTotal).\n"
                "2. Neu co chuoi Base64 hoac command ma hoa, goi tool_decode_base64 de giai ma.\n"
                "3. AN TOAN FIREWALL: Day la su kien Endpoint noi bo (src_ip la 'unknown'), TUYET DOI KHONG goi tool_block_firewall_ip.\n"
                "4. PHAN UNG MAY TRAM 2 GIAI DOAN (Wazuh Active Response tool_wazuh_endpoint_response):\n"
                "   - O Giai doan 1 (neu da kich hoat), he thong da CACH LY FILE, DUNG TIEN TRINH va CO LAP MANG TAM THOI may tram.\n"
                "   - Sau khi dieu tra log: Neu tep doc hai CHUA DUOC THUC THI (chi la FIM syscheck added/modified nam tren dia) HOAC KHONG CO KHA NANG LAY LAN NGANG, hay goi tool_wazuh_endpoint_response(action='release_isolation') de MO CO LAP MANG nhung VAN GIU CACH LY FILE.\n"
                "   - Neu ma doc DA DUOC THUC THI (co tien trinh Sysmon/Auditd/PowerShell/Reverse shell) VA CO NGUY CO LAY LAN / KET NOI C2 (T1021, T1570, T1059), hay goi tool_wazuh_endpoint_response(action='keep_isolated') de GIU CO LAP MANG.\n"
                "5. Cuoi cung, ket luan bang tieng Viet theo dinh dang ro rang:\n"
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
        prompt_payload.pop("_replay_case_id", None)
        if not is_fim and src_ip not in ["unknown", None, ""]:
            prompt_payload.pop("file_path", None)
            prompt_payload.pop("event_type", None)
            if prompt_payload.get("agent_ip") == "unknown":
                prompt_payload.pop("agent_ip", None)
            if not prompt_payload.get("primary_hash"):
                prompt_payload.pop("primary_hash", None)
                prompt_payload.pop("file_hashes", None)

        user_prompt = f"Phan tich canh bao SOC thuoc Case {case_obj['id']} ({slm_reason}): {json.dumps(prompt_payload, ensure_ascii=False)}"
        memory_ctx = get_agent_memory_context(
            src_ip=src_ip,
            agent_id=agent_id,
            file_path=file_path,
            primary_hash=primary_hash,
            case_id=case_obj["id"],
        )
        if memory_ctx:
            user_prompt += f"\n{memory_ctx}"
        if pre_enriched_hash_result:
            user_prompt += f"\n[Ket qua Threat Intelligence kiem tra ma hash {primary_hash}]: {pre_enriched_hash_result}"
        if phase1_info and phase1_info.get("executed"):
            user_prompt += (
                f"\n[Phan ung nhanh Giai doan 1 da thuc thi tren Agent {agent_id}]: "
                f"Da cach ly file '{phase1_info.get('quarantined_file') or 'N/A'}', "
                f"dung tien trinh '{phase1_info.get('killed_process') or 'N/A'}' va CO LAP MANG TAM THOI. "
                f"Hay dieu tra xem ma doc da thuc thi va co nguy co lay lan khong de goi tool_wazuh_endpoint_response (release_isolation hoac keep_isolated)."
            )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        final_text = ""
        has_blocked_ip = (
            not is_fim and
            bool(src_ip) and
            src_ip != "unknown" and
            src_ip not in [agent_ip, victim_ip] and
            src_ip in STATE.get("stats", {}).get("blocked_ips", [])
        )
        phase2_action_taken = None

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
                        if fn_name == "tool_wazuh_endpoint_response":
                            chosen_act = str(fn_args.get("action", "")).strip().lower()
                            if chosen_act in ["release_isolation", "keep_isolated"]:
                                phase2_action_taken = chosen_act
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

        # =========================================================================
        # GIAI ĐOẠN 2 (POST-INVESTIGATION ENFORCEMENT): GIỮ HOẶC MỞ CÔ LẬP MÁY TRẠM
        # =========================================================================
        endpoint_response_summary = None
        if valid_agent and is_endpoint_event and (phase1_info or verdict == "TRUE POSITIVE"):
            if not phase1_info:
                phase1_info = execute_phase1_fast_containment(
                    agent_id=agent_id,
                    agent_name=agent_name,
                    victim_ip=victim_ip,
                    file_path=file_path,
                    process_name=process_name,
                    process_id=process_id,
                    reason=alert_summary.get("title", "Phát hiện mối đe dọa TRUE POSITIVE trên Endpoint"),
                )

            if not phase2_action_taken:
                text_corpus = (
                    str(alert_summary.get("source", "")) + " " +
                    str(alert_summary.get("title", "")) + " " +
                    str(alert_summary.get("full_log", "")) + " " +
                    " ".join(mitre_tags or [])
                ).lower()
                has_process_evidence = bool(process_name or process_id) or any(
                    k in text_corpus
                    for k in ["sysmon", "execve", "command_line", "powershell", "reverse shell", "worm", "ransomware", "lateral movement"]
                )
                has_spreading_mitre = any(
                    tid in " ".join(mitre_tags or []).upper()
                    for tid in ["T1021", "T1570", "T1059", "T1071", "T1053"]
                )
                is_pure_static_fim = (
                    is_fim and
                    (alert_summary.get("event_type") in ["added", "modified"]) and
                    not (process_name or process_id)
                )
                is_executed_and_spreading = (has_process_evidence or has_spreading_mitre) and not is_pure_static_fim

                if is_executed_and_spreading:
                    tool_wazuh_endpoint_response(
                        agent_id=agent_id,
                        action="keep_isolated",
                        file_path=file_path or "",
                        reason="Mã độc đã thực thi và có nguy cơ lây lan mạng / C2",
                    )
                    phase2_action_taken = "keep_isolated"
                else:
                    tool_wazuh_endpoint_response(
                        agent_id=agent_id,
                        action="release_isolation",
                        file_path=file_path or "",
                        reason="Tệp độc hại chưa thực thi / không có hành vi lây lan -> Mở cô lập mạng, giữ cách ly file",
                    )
                    phase2_action_taken = "release_isolation"

            if phase2_action_taken == "keep_isolated":
                endpoint_response_summary = f"⚡ Phase 1: Cách ly & Cô lập tạm thời Agent {agent_id} -> 🔒 Phase 2: Giữ khóa cô lập mạng"
            elif phase2_action_taken == "release_isolation":
                endpoint_response_summary = f"⚡ Phase 1: Cách ly & Cô lập tạm thời Agent {agent_id} -> 🔓 Phase 2: Đã mở cô lập mạng (Vẫn giữ cách ly file)"

        # Cập nhật thống kê STATE (QUY TẮC 8)
        if not replay_case_id:
            if verdict == "TRUE POSITIVE":
                STATE["stats"]["true_positives"] += 1
            elif verdict == "FALSE POSITIVE":
                STATE["stats"]["false_positives"] += 1
            elif verdict == "SUSPICIOUS":
                STATE["stats"]["suspicious"] += 1
            elif verdict == "UNKNOWN":
                STATE["stats"]["unknown"] += 1

        # Cập nhật Case Management & Liên kết đa miền
        finalize_case_analysis(
            case_obj["id"],
            verdict=verdict,
            mitre_tags=mitre_tags,
            ti_summary=ti_summary,
            summary_text=final_text,
            has_blocked_ip=has_blocked_ip,
            endpoint_response=endpoint_response_summary,
        )

        log_event("VERDICT", f"[{case_obj['id']}][{verdict}] {final_text[:120]}...")
        STATE["decisions"].appendleft({
            "case_id": case_obj["id"],
            "time": datetime.now().strftime("%H:%M:%S"),
            "source": alert_summary.get("source", "pfSense / Wazuh SIEM"),
            "title": alert_summary.get("title", "Cảnh báo an ninh"),
            "src_ip": src_ip,
            "agent_id": agent_id,
            "agent_ip": agent_ip,
            "victim_ip": victim_ip,
            "primary_hash": primary_hash,
            "file_path": file_path,
            "verdict": verdict,
            "mitre": mitre_tags,
            "ti_summary": ti_summary,
            "endpoint_response": endpoint_response_summary,
            "summary": final_text
        })
        save_persistent_state()
    finally:
        case_obj["is_analyzing"] = False


def replay_case_alerts(case_id: str) -> int:
    """Replay kiểm toán Case bằng cách phân tích lại các cảnh báo đại diện trong incident_alerts."""
    case_obj = get_case_by_id(case_id)
    if not case_obj:
        return 0

    raw_alerts = list(case_obj.get("incident_alerts", []))
    if not raw_alerts:
        return 0

    # Chọn các alert đại diện theo (rule_id, primary_hash, title), tối đa 3 lượt gần nhất
    representatives = {}
    for item in raw_alerts:
        key = (str(item.get("rule_id", "")), str(item.get("primary_hash", "")), str(item.get("title", "")))
        representatives[key] = item

    selected = list(representatives.values())[-3:]
    log_event("CASE", f"🔄 Bắt đầu Replay kiểm toán {case_id} ({len(selected)} cảnh báo đại diện từ {len(raw_alerts)} alerts gốc)...")
    for alert in selected:
        payload = dict(alert)
        payload["_replay_case_id"] = case_id
        run_agent_loop(payload)
    return len(selected)
