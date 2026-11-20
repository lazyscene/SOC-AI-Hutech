"""Shared stdlib utilities for the Alert Triage Evaluation (Benchmark) suite."""

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BENCHMARK_DIR)
AGENT_DIR = os.path.join(PROJECT_ROOT, "agent")

VN_TZ = timezone(timedelta(hours=7))


def load_dotenv_if_present(env_path: Optional[str] = None) -> Dict[str, str]:
    """Load key=value pairs from .env without overriding already-set env vars."""
    target = env_path or os.path.join(PROJECT_ROOT, ".env")
    loaded: Dict[str, str] = {}
    if not os.path.exists(target):
        return loaded

    with open(target, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if not key:
                continue
            if (val.startswith('"') and val.endswith('"')) or (
                val.startswith("'") and val.endswith("'")
            ):
                val = val[1:-1]
            os.environ.setdefault(key, val)
            loaded[key] = val
    return loaded


def setup_agent_imports() -> None:
    """Configure environment for safe offline import of `agent/` modules."""
    os.environ["SOC_DISABLE_STATE_PERSISTENCE"] = "1"
    load_dotenv_if_present()
    if AGENT_DIR not in sys.path:
        sys.path.insert(0, AGENT_DIR)


def parse_timestamp(value: Any) -> Optional[datetime]:
    """
    Parse Wazuh ISO8601 timestamps (including +0700 / Z) or CLI date strings
    into timezone-aware datetime (defaulting naive values to UTC+7 / Asia/Ho_Chi_Minh).
    """
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None

    normalized = raw
    if normalized.endswith(("Z", "z")):
        normalized = normalized[:-1] + "+00:00"
    else:
        normalized = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", normalized)

    # Try ISO format first (supports fractional seconds and offsets)
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=VN_TZ)
        return dt
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.replace(tzinfo=VN_TZ)
        except ValueError:
            continue

    return None


def normalize_verdict(verdict: Any) -> str:
    """Normalize agent/ground-truth verdict labels into benchmark canonical enums."""
    if verdict is None:
        return "UNKNOWN"
    clean = str(verdict).strip().upper().replace("-", " ")
    clean_spaces = " ".join(clean.split())
    if clean_spaces in ("TRUE POSITIVE", "TRUE_POSITIVE", "TP"):
        return "TRUE_POSITIVE"
    if clean_spaces in ("FALSE POSITIVE", "FALSE_POSITIVE", "FP"):
        return "FALSE_POSITIVE"
    if clean_spaces in ("SUSPICIOUS",):
        return "SUSPICIOUS"
    if clean_spaces in ("ERROR",):
        return "ERROR"
    if clean_spaces in ("UNKNOWN",):
        return "UNKNOWN"
    if "TRUE POSITIVE" in clean_spaces or "TRUE_POSITIVE" in clean_spaces:
        return "TRUE_POSITIVE"
    if "FALSE POSITIVE" in clean_spaces or "FALSE_POSITIVE" in clean_spaces:
        return "FALSE_POSITIVE"
    if "SUSPICIOUS" in clean_spaces:
        return "SUSPICIOUS"
    if "ERROR" in clean_spaces:
        return "ERROR"
    return "UNKNOWN"


def read_jsonl(path: str) -> List[Dict[str, Any]]:
    """Read a JSONL file safely, skipping blank or truncated/corrupted lines."""
    records: List[Dict[str, Any]] = []
    if not os.path.exists(path):
        return records
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                records.append(obj)
    return records


def append_jsonl_line(fh: Any, obj: Dict[str, Any]) -> None:
    """Append a single JSON object as one line and durability-flush immediately."""
    fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
    fh.flush()
    try:
        os.fsync(fh.fileno())
    except OSError:
        pass
