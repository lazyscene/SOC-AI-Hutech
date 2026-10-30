import json
from datetime import datetime
from core.llm import call_ollama
from tools.base import TOOLS_SCHEMA, TOOLS_MAP
from web.state import STATE, log_event

def run_agent_loop(alert_summary: dict):
    STATE["stats"]["total_alerts"] += 1
    log_event("ALERT", f"Nhận cảnh báo mới: {alert_summary.get('title')} (SRC: {alert_summary.get('src_ip')})")

    system_prompt = (
        "Ban la AI SOC Analyst tu hanh. Khi nhan canh bao JSON tu SIEM/NIDS:\n"
        "1. Phan tich xem day la tan cong that (True Positive) hay hoat dong hop le (False Positive).\n"
        "2. Neu co chuoi Base64, goi tool_decode_base64.\n"
        "3. Neu phat hien tan cong mang tu IP ngoai, BAT BUOC goi tool_block_firewall_ip de chan IP.\n"
        "4. Cuoi cung, ket luan bang tieng Viet gom: Phan quyet (True Positive / False Positive), Nguyen nhan, va Hanh dong da thuc thi."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Phan tich canh bao SOC sau: {json.dumps(alert_summary, ensure_ascii=False)}"}
    ]

    for step in range(4):
        try:
            resp = call_ollama(messages, TOOLS_SCHEMA)
        except Exception as e:
            log_event("ERROR", f"Không kết nối được Ollama: {e}")
            return

        msg = resp.get("message", {})
        messages.append(msg)

        tool_calls = msg.get("tool_calls", [])
        if not tool_calls:
            final_text = msg.get("content", "Đã hoàn tất phân tích.")
            verdict = "TRUE POSITIVE" if "true positive" in final_text.lower() else "FALSE POSITIVE"
            if verdict == "TRUE POSITIVE":
                STATE["stats"]["true_positives"] += 1
            else:
                STATE["stats"]["false_positives"] += 1

            log_event("VERDICT", f"[{verdict}] {final_text}")
            STATE["decisions"].appendleft({
                "time": datetime.now().strftime("%H:%M:%S"),
                "source": alert_summary.get("source"),
                "title": alert_summary.get("title"),
                "src_ip": alert_summary.get("src_ip"),
                "verdict": verdict,
                "summary": final_text
            })
            return

        for call in tool_calls:
            fn_name = call["function"]["name"]
            fn_args = call["function"]["arguments"]
            if isinstance(fn_args, str):
                fn_args = json.loads(fn_args)
            log_event("THOUGHT", f"Qwen gọi hàm: {fn_name}({json.dumps(fn_args)})")
            
            if fn_name in TOOLS_MAP:
                result = TOOLS_MAP[fn_name](**fn_args)
            else:
                result = f"Ham {fn_name} khong ton tai."
            messages.append({"role": "tool", "content": str(result)})

