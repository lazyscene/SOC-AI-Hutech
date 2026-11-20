"""Script 1: Extract & diversity-sample Wazuh alerts from alerts.json into benchmark JSONL."""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BENCHMARK_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmark.common import (  # noqa: E402
    append_jsonl_line,
    parse_timestamp,
    read_jsonl,
    setup_agent_imports,
)

setup_agent_imports()

from core.models import safe_get  # noqa: E402
from watchers.tailers import (  # noqa: E402
    IGNORED_FIM_PATHS,
    extract_hashes_and_metadata,
    extract_ip,
    should_ignore_alert,
)


@dataclass
class _Candidate:
    order_idx: int
    rule_id: str
    rule_level: int
    rule_description: str
    bucket_key: Tuple[str, str, str]
    log_sig: str
    raw_alert: Dict[str, Any]


def _normalize_log_signature(full_log: str) -> str:
    collapsed = re.sub(r"\s+", " ", (full_log or "").strip())
    return collapsed[:180]


def _parse_sample_num(sample_id: Any) -> int:
    m = re.match(r"^BM-(\d+)$", str(sample_id or "").strip(), re.IGNORECASE)
    return int(m.group(1)) if m else 0


def iter_raw_alerts(input_path: str) -> Iterable[Dict[str, Any]]:
    """Load raw alerts from NDJSON (.json/.jsonl) or a JSON array file."""
    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        first_non_ws = ""
        while True:
            ch = f.read(1)
            if not ch:
                break
            if not ch.isspace():
                first_non_ws = ch
                break
        f.seek(0)

        if first_non_ws == "[":
            try:
                items = json.load(f)
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            yield item
            except json.JSONDecodeError:
                return
            return

        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
                if isinstance(obj, dict):
                    yield obj
            except json.JSONDecodeError:
                continue


def is_alert_eligible(
    data: Dict[str, Any],
    *,
    min_level: int = 6,
    include_ignored: bool = False,
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Apply tailers.py trigger and noise-filter rules to determine whether a raw Wazuh
    alert would enter the SOC Agent triage pipeline.
    Returns `(eligible, skip_reason, metadata_dict)`.
    """
    if not isinstance(data, dict):
        return False, "invalid_object", None

    rule = data.get("rule") or {}
    if not isinstance(rule, dict):
        return False, "invalid_rule", None

    rule_id = str(rule.get("id", "") or "").strip()
    try:
        level = int(rule.get("level", 0) or 0)
    except (TypeError, ValueError):
        level = 0
    rule_groups = rule.get("groups") or []
    if not isinstance(rule_groups, list):
        rule_groups = []
    rule_desc = str(rule.get("description", "Cảnh báo an ninh") or "Cảnh báo an ninh")
    full_log = str(data.get("full_log", "") or "")

    primary_hash, _, file_path, event_type = extract_hashes_and_metadata(data, full_log)
    syscheck = safe_get(data, "syscheck")
    is_fim = (
        (syscheck is not None)
        or ("syscheck" in rule_groups)
        or (rule_id in ["550", "553", "554", "750"])
    )

    if is_fim and file_path:
        fp_lower = file_path.lower()
        if any(ignored in fp_lower for ignored in IGNORED_FIM_PATHS):
            return False, "ignored_fim_path", None

    if rule_id == "553" or event_type == "deleted":
        return False, "fim_deleted", None

    is_fim_add_or_mod = (
        is_fim
        and ("syscheck_registry" not in rule_groups)
        and (event_type in ["added", "modified"] or rule_id in ["550", "554"])
        and bool(primary_hash)
    )
    is_security_alert = (
        any(g in rule_groups for g in ["firewall_block", "attack", "ids"])
        or (level >= min_level)
        or is_fim_add_or_mod
    )
    if not is_security_alert:
        return False, "below_min_level", None

    if is_fim:
        src_ip = "unknown"
        dest_ip = "unknown"
    else:
        src_ip = extract_ip(data)
        dest_ip = str(
            safe_get(data, "data", "dstip")
            or safe_get(data, "data", "dst_ip")
            or data.get("dstip")
            or "unknown"
        )

    if not include_ignored and should_ignore_alert(src_ip, dest_ip, f"{rule_desc} {full_log}"):
        return False, "tailer_noise_ignored", None

    agent_name = str(safe_get(data, "agent", "name") or "unknown")
    bucket_src = (
        str(
            safe_get(data, "data", "srcip")
            or safe_get(data, "data", "src_ip")
            or data.get("srcip")
            or data.get("src_ip")
            or src_ip
            or "unknown"
        ).strip()
        or "unknown"
    )
    bucket_path = str(safe_get(data, "syscheck", "path") or file_path or "")

    meta = {
        "rule_id": rule_id,
        "rule_level": level,
        "rule_description": rule_desc,
        "bucket_key": (bucket_src, bucket_path, agent_name),
        "log_sig": _normalize_log_signature(full_log),
    }
    return True, "ok", meta


def sample_diverse_per_rule(
    candidates: List[_Candidate],
    max_per_rule: int,
) -> List[_Candidate]:
    """
    Cap alerts per `(rule_id, rule_description)` using bucketed round-robin sampling so
    distinct `(srcip, syscheck.path, agent.name)` and `full_log` variants are preserved.
    """
    grouped: Dict[Tuple[str, str], List[_Candidate]] = defaultdict(list)
    for item in candidates:
        grouped[(item.rule_id, item.rule_description)].append(item)

    chosen: List[_Candidate] = []
    for _rule_key, group_items in grouped.items():
        if max_per_rule <= 0 or len(group_items) <= max_per_rule:
            chosen.extend(group_items)
            continue

        buckets: Dict[Tuple[str, str, str], List[_Candidate]] = defaultdict(list)
        for c in group_items:
            buckets[c.bucket_key].append(c)

        bucket_keys = list(buckets.keys())
        bucket_picked_ids = set()
        seen_logs_global = set()
        rule_selected: List[_Candidate] = []

        # Pass A: maximize cross-bucket diversity + distinct log signatures
        progressed = True
        while progressed and len(rule_selected) < max_per_rule:
            progressed = False
            for bk in bucket_keys:
                if len(rule_selected) >= max_per_rule:
                    break
                for cand in buckets[bk]:
                    if id(cand) in bucket_picked_ids:
                        continue
                    if cand.log_sig not in seen_logs_global:
                        bucket_picked_ids.add(id(cand))
                        seen_logs_global.add(cand.log_sig)
                        rule_selected.append(cand)
                        progressed = True
                        break

        # Pass B: fill remaining quota evenly round-robin across buckets
        progressed = True
        while progressed and len(rule_selected) < max_per_rule:
            progressed = False
            for bk in bucket_keys:
                if len(rule_selected) >= max_per_rule:
                    break
                for cand in buckets[bk]:
                    if id(cand) in bucket_picked_ids:
                        continue
                    bucket_picked_ids.add(id(cand))
                    rule_selected.append(cand)
                    progressed = True
                    break

        chosen.extend(rule_selected)

    chosen.sort(key=lambda c: c.order_idx)
    return chosen


def extract_alerts(
    *,
    input_path: str,
    output_path: str,
    default_label: str,
    scenario: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
    max_per_rule: int = 12,
    min_level: int = 6,
    include_ignored: bool = False,
    append: bool = False,
) -> Dict[str, Any]:
    """Run extraction, filtering, diversity sampling, and JSONL output generation."""
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Không tìm thấy file alerts input: {input_path}")

    start_dt: Optional[datetime] = parse_timestamp(start) if start else None
    end_dt: Optional[datetime] = parse_timestamp(end) if end else None
    if start and start_dt is None:
        raise ValueError(f"Không parse được --start timestamp: {start}")
    if end and end_dt is None:
        raise ValueError(f"Không parse được --end timestamp: {end}")

    existing_records: List[Dict[str, Any]] = []
    seen_alert_ids = set()
    next_num = 1
    if append and os.path.exists(output_path):
        existing_records = read_jsonl(output_path)
        for rec in existing_records:
            next_num = max(next_num, _parse_sample_num(rec.get("sample_id")) + 1)
            raw_obj = rec.get("raw_alert")
            if isinstance(raw_obj, dict) and raw_obj.get("id"):
                seen_alert_ids.add(str(raw_obj["id"]))

    stats_skipped: Dict[str, int] = defaultdict(int)
    total_scanned = 0
    candidates: List[_Candidate] = []

    for idx, raw_alert in enumerate(iter_raw_alerts(input_path)):
        total_scanned += 1
        if start_dt or end_dt:
            ts_dt = parse_timestamp(raw_alert.get("timestamp"))
            if ts_dt is None:
                stats_skipped["missing_timestamp"] += 1
                continue
            if start_dt and ts_dt < start_dt:
                stats_skipped["outside_time_range"] += 1
                continue
            if end_dt and ts_dt > end_dt:
                stats_skipped["outside_time_range"] += 1
                continue

        raw_id = raw_alert.get("id")
        if raw_id:
            sid = str(raw_id)
            if sid in seen_alert_ids:
                stats_skipped["duplicate_alert_id"] += 1
                continue
            seen_alert_ids.add(sid)

        eligible, reason, meta = is_alert_eligible(
            raw_alert, min_level=min_level, include_ignored=include_ignored
        )
        if not eligible or meta is None:
            stats_skipped[reason] += 1
            continue

        candidates.append(
            _Candidate(
                order_idx=idx,
                rule_id=meta["rule_id"],
                rule_level=meta["rule_level"],
                rule_description=meta["rule_description"],
                bucket_key=meta["bucket_key"],
                log_sig=meta["log_sig"],
                raw_alert=raw_alert,
            )
        )

    selected = sample_diverse_per_rule(candidates, max_per_rule=max_per_rule)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    mode = "a" if (append and os.path.exists(output_path)) else "w"
    written_rows: List[Dict[str, Any]] = []
    rule_counts: Dict[Tuple[str, int, str], int] = defaultdict(int)

    with open(output_path, mode, encoding="utf-8") as fh:
        for cand in selected:
            sample_id = f"BM-{next_num:04d}"
            next_num += 1
            row = {
                "sample_id": sample_id,
                "ground_truth": default_label,
                "label_verified": False,
                "scenario_group": scenario,
                "rule_id": cand.rule_id,
                "rule_level": cand.rule_level,
                "rule_description": cand.rule_description,
                "raw_alert": cand.raw_alert,
            }
            append_jsonl_line(fh, row)
            written_rows.append(row)
            rule_counts[(cand.rule_id, cand.rule_level, cand.rule_description)] += 1

    return {
        "input_path": input_path,
        "output_path": output_path,
        "scenario": scenario,
        "default_label": default_label,
        "total_scanned": total_scanned,
        "eligible_before_cap": len(candidates),
        "written_count": len(written_rows),
        "total_after_write": (len(existing_records) if mode == "a" else 0) + len(written_rows),
        "skipped": dict(stats_skipped),
        "rule_counts": [
            {"rule_id": r[0], "rule_level": r[1], "rule_description": r[2], "count": cnt}
            for r, cnt in sorted(rule_counts.items(), key=lambda x: (-x[1], x[0][0]))
        ],
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Trích xuất & lọc đa dạng cảnh báo Wazuh (alerts.json) phục vụ benchmark."
    )
    parser.add_argument(
        "--input",
        default=os.path.join(BENCHMARK_DIR, "data", "alerts.json"),
        help="Đường dẫn file alerts.json copy từ volume Wazuh",
    )
    parser.add_argument("--start", default=None, help="Mốc bắt đầu (ISO hoặc YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--end", default=None, help="Mốc kết thúc (ISO hoặc YYYY-MM-DD HH:MM:SS)")
    parser.add_argument(
        "--default-label",
        required=True,
        choices=["FALSE_POSITIVE", "TRUE_POSITIVE"],
        help="Nhãn mặc định cho đợt trích xuất",
    )
    parser.add_argument(
        "--scenario",
        required=True,
        help="Tên nhóm kịch bản (vd: benign_cis, benign_admin, attack_nmap, attack_fim_eicar)",
    )
    parser.add_argument(
        "--max-per-rule",
        type=int,
        default=12,
        help="Số mẫu tối đa cho mỗi cặp (rule.id, rule.description), <=0 là không giới hạn (mặc định: 12)",
    )
    parser.add_argument(
        "--min-level",
        type=int,
        default=6,
        help="Ngưỡng rule.level tối thiểu giống tailers.py (vẫn giữ FIM có hash & nhóm attack/ids/firewall_block)",
    )
    parser.add_argument(
        "--include-ignored",
        action="store_true",
        help="Bao gồm cả cảnh báo broadcast/multicast/noise bị should_ignore_alert lọc trong tailers.py",
    )
    parser.add_argument(
        "--output",
        default=os.path.join(BENCHMARK_DIR, "data", "dataset_raw.jsonl"),
        help="File .jsonl đầu ra",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Nối tiếp vào file --output hiện có và tự tăng sample_id BM-XXXX",
    )

    args = parser.parse_args(argv)
    summary = extract_alerts(
        input_path=args.input,
        output_path=args.output,
        default_label=args.default_label,
        scenario=args.scenario,
        start=args.start,
        end=args.end,
        max_per_rule=args.max_per_rule,
        min_level=args.min_level,
        include_ignored=args.include_ignored,
        append=args.append,
    )

    print(f"[EXTRACT] Input        : {summary['input_path']}")
    print(f"[EXTRACT] Output       : {summary['output_path']} (append={args.append})")
    print(f"[EXTRACT] Scenario     : {summary['scenario']} | Default Label: {summary['default_label']}")
    print(f"[EXTRACT] Scanned      : {summary['total_scanned']} alerts")
    print(f"[EXTRACT] Eligible     : {summary['eligible_before_cap']} alerts")
    print(f"[EXTRACT] Written      : {summary['written_count']} alerts (Total in file: {summary['total_after_write']})")
    if summary["skipped"]:
        print(f"[EXTRACT] Skipped      : {summary['skipped']}")
    print("[EXTRACT] Phân bố Rule đã giữ lại:")
    for item in summary["rule_counts"]:
        print(
            f"  - Rule {item['rule_id']} (Lv.{item['rule_level']}): "
            f"{item['count']} mẫu — {item['rule_description']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
