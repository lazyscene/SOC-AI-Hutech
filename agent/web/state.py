from collections import deque
from datetime import datetime

STATE = {
    "stats": {"total_alerts": 0, "true_positives": 0, "false_positives": 0, "blocked_ips": []},
    "reasoning_stream": deque(maxlen=50),
    "decisions": deque(maxlen=30)
}

def log_event(step_type: str, message: str):
    entry = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": step_type,
        "message": message
    }
    STATE["reasoning_stream"].appendleft(entry)
    print(f"[{entry['time']}][{step_type}] {message}", flush=True)

