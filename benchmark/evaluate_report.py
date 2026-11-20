"""Script 3: Aggregate Confusion Matrix, 3 Core Metrics, Baseline Comparisons, and Error CSV."""

import argparse
import csv
import math
import os
import re
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BENCHMARK_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmark.common import normalize_verdict, read_jsonl  # noqa: E402


def percentile(values: List[float], pct: float) -> float:
    """Linear-interpolation percentile matching standard statistical definitions."""
    if not values:
        return 0.0
    ordered = sorted(float(v) for v in values)
    if len(ordered) == 1:
        return ordered[0]
    k = (len(ordered) - 1) * (pct / 100.0)
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return ordered[int(k)]
    return ordered[lo] * (hi - k) + ordered[hi] * (k - lo)


def latency_stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"count": 0, "mean": 0.0, "p50": 0.0, "p95": 0.0, "min": 0.0, "max": 0.0}
    ordered = sorted(float(v) for v in values)
    return {
        "count": len(ordered),
        "mean": sum(ordered) / len(ordered),
        "p50": percentile(ordered, 50.0),
        "p95": percentile(ordered, 95.0),
        "min": ordered[0],
        "max": ordered[-1],
    }


def _map_prediction_to_binary(pred: str, suspicious_as: str) -> str:
    norm = normalize_verdict(pred)
    if norm == "TRUE_POSITIVE":
        return "POSITIVE"
    if norm == "FALSE_POSITIVE":
        return "NEGATIVE"
    if norm == "SUSPICIOUS":
        if suspicious_as == "positive":
            return "POSITIVE"
        if suspicious_as == "negative":
            return "NEGATIVE"
        return "ABSTAIN"
    return "ABSTAIN"


def compute_classification_metrics(
    records: List[Dict[str, Any]],
    *,
    pred_getter,
    suspicious_as: str = "positive",
) -> Dict[str, Any]:
    """Compute confusion matrix, 3 primary KPIs, and standard metrics."""
    tp = fp = tn = fn = 0
    unknown_tp = unknown_fp = error_tp = error_fp = 0
    suspicious_tp = suspicious_fp = 0
    total_gt_tp = total_gt_fp = 0

    for rec in records:
        gt = normalize_verdict(rec.get("ground_truth"))
        pred_raw = normalize_verdict(pred_getter(rec))
        pred_bin = _map_prediction_to_binary(pred_raw, suspicious_as)

        if gt == "TRUE_POSITIVE":
            total_gt_tp += 1
            if pred_raw == "SUSPICIOUS":
                suspicious_tp += 1
            if pred_bin == "POSITIVE":
                tp += 1
            elif pred_bin == "NEGATIVE":
                fn += 1
            elif pred_raw == "ERROR":
                error_tp += 1
            else:
                unknown_tp += 1
        elif gt == "FALSE_POSITIVE":
            total_gt_fp += 1
            if pred_raw == "SUSPICIOUS":
                suspicious_fp += 1
            if pred_bin == "POSITIVE":
                fp += 1
            elif pred_bin == "NEGATIVE":
                tn += 1
            elif pred_raw == "ERROR":
                error_fp += 1
            else:
                unknown_fp += 1

    decided_pos = tp + fn
    decided_neg = tn + fp
    decided_total = tp + fp + tn + fn

    fp_reduction_pct = (tn / decided_neg * 100.0) if decided_neg > 0 else 0.0
    fnr_pct = (fn / decided_pos * 100.0) if decided_pos > 0 else 0.0
    accuracy_pct = ((tp + tn) / decided_total * 100.0) if decided_total > 0 else 0.0
    precision_pct = (tp / (tp + fp) * 100.0) if (tp + fp) > 0 else 0.0
    recall_pct = (tp / (tp + fn) * 100.0) if (tp + fn) > 0 else 0.0
    f1_pct = (
        (2.0 * precision_pct * recall_pct / (precision_pct + recall_pct))
        if (precision_pct + recall_pct) > 0
        else 0.0
    )

    overall_fp_reduction_pct = (tn / total_gt_fp * 100.0) if total_gt_fp > 0 else 0.0
    effective_missed_tp = fn + unknown_tp + error_tp
    effective_fnr_pct = (effective_missed_tp / total_gt_tp * 100.0) if total_gt_tp > 0 else 0.0

    return {
        "total": len(records),
        "total_gt_tp": total_gt_tp,
        "total_gt_fp": total_gt_fp,
        "decided_total": decided_total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "unknown_total": unknown_tp + unknown_fp,
        "unknown_tp": unknown_tp,
        "unknown_fp": unknown_fp,
        "error_total": error_tp + error_fp,
        "error_tp": error_tp,
        "error_fp": error_fp,
        "suspicious_tp": suspicious_tp,
        "suspicious_fp": suspicious_fp,
        "fp_reduction_pct": fp_reduction_pct,
        "overall_fp_reduction_pct": overall_fp_reduction_pct,
        "missed_tp_count": fn,
        "fnr_pct": fnr_pct,
        "effective_missed_tp": effective_missed_tp,
        "effective_fnr_pct": effective_fnr_pct,
        "accuracy_pct": accuracy_pct,
        "precision_pct": precision_pct,
        "recall_pct": recall_pct,
        "f1_pct": f1_pct,
    }


def _infer_run_name(input_path: str, run_name: Optional[str]) -> str:
    if run_name:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", run_name.strip()) or "default"
    base = os.path.basename(input_path)
    m = re.match(r"^predictions_(.+?)\.jsonl$", base, re.IGNORECASE)
    if m:
        return m.group(1)
    stem, _ = os.path.splitext(base)
    return stem or "default"


def load_deduplicated_predictions(
    input_path: str, dataset_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Load predictions JSONL, keeping the latest record per sample_id."""
    dataset_by_id: Dict[str, Dict[str, Any]] = {}
    if dataset_path and os.path.exists(dataset_path):
        for row in read_jsonl(dataset_path):
            sid = str(row.get("sample_id", "") or "").strip()
            if sid:
                dataset_by_id[sid] = row

    ordered_ids: List[str] = []
    latest_by_id: Dict[str, Dict[str, Any]] = {}
    for row in read_jsonl(input_path):
        sid = str(row.get("sample_id", "") or "").strip()
        if not sid:
            continue
        if sid not in latest_by_id:
            ordered_ids.append(sid)
        merged = dict(row)
        ds_row = dataset_by_id.get(sid)
        if ds_row:
            if not merged.get("rule_description"):
                merged["rule_description"] = ds_row.get("rule_description", "")
            if not merged.get("scenario_group"):
                merged["scenario_group"] = ds_row.get("scenario_group", "unknown")
            if not merged.get("rule_id"):
                merged["rule_id"] = ds_row.get("rule_id", "")
            if merged.get("rule_level") is None:
                merged["rule_level"] = ds_row.get("rule_level", 0)
            merged["ground_truth"] = ds_row.get("ground_truth", merged.get("ground_truth"))
        latest_by_id[sid] = merged

    return [latest_by_id[sid] for sid in ordered_ids]


def evaluate_predictions(
    *,
    input_path: str,
    run_name: Optional[str] = None,
    dataset_path: Optional[str] = None,
    output_dir: Optional[str] = None,
    baseline1_level: int = 6,
    baseline2_level: int = 10,
    suspicious_as: str = "positive",
) -> Dict[str, Any]:
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Không tìm thấy file predictions: {input_path}")

    resolved_run = _infer_run_name(input_path, run_name)
    out_dir = output_dir or os.path.join(BENCHMARK_DIR, "results")
    os.makedirs(out_dir, exist_ok=True)

    records = load_deduplicated_predictions(input_path, dataset_path=dataset_path)
    if not records:
        raise ValueError(f"File predictions rỗng hoặc không có bản ghi hợp lệ: {input_path}")

    # 1. Proposed AI Agent Metrics
    agent_metrics = compute_classification_metrics(
        records,
        pred_getter=lambda r: r.get("predicted_verdict"),
        suspicious_as=suspicious_as,
    )

    # 2. Baseline 1 (Wazuh mặc định: mọi cảnh báo đều bị coi là cần xử lý)
    baseline1_metrics = compute_classification_metrics(
        records,
        pred_getter=lambda _r: "TRUE_POSITIVE",
        suspicious_as=suspicious_as,
    )

    # 3. Baseline 2 (Wazuh siết ngưỡng cứng: level >= baseline2_level -> TP, dưới -> FP)
    baseline2_metrics = compute_classification_metrics(
        records,
        pred_getter=lambda r: (
            "TRUE_POSITIVE" if int(r.get("rule_level", 0) or 0) >= baseline2_level else "FALSE_POSITIVE"
        ),
        suspicious_as=suspicious_as,
    )

    # 4. Latency statistics
    valid_latencies = [
        float(r.get("latency_sec", 0.0) or 0.0)
        for r in records
        if normalize_verdict(r.get("predicted_verdict")) != "ERROR"
    ]
    llm_latencies = [
        float(r.get("latency_sec", 0.0) or 0.0)
        for r in records
        if normalize_verdict(r.get("predicted_verdict")) != "ERROR"
        and not bool(r.get("filtered_by_tailer"))
    ]
    all_lat_stats = latency_stats(valid_latencies)
    llm_lat_stats = latency_stats(llm_latencies)

    ti_rate_limited_total = sum(1 for r in records if bool(r.get("ti_rate_limited")))
    tailer_filtered_total = sum(1 for r in records if bool(r.get("filtered_by_tailer")))

    # 5. Breakdown by scenario_group
    by_scenario: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        by_scenario[str(r.get("scenario_group", "unknown") or "unknown")].append(r)

    scenario_rows = []
    for scen_name in sorted(by_scenario.keys()):
        items = by_scenario[scen_name]
        m = compute_classification_metrics(
            items,
            pred_getter=lambda r: r.get("predicted_verdict"),
            suspicious_as=suspicious_as,
        )
        s_lats = [
            float(r.get("latency_sec", 0.0) or 0.0)
            for r in items
            if normalize_verdict(r.get("predicted_verdict")) != "ERROR"
        ]
        scenario_rows.append(
            {
                "scenario_group": scen_name,
                "metrics": m,
                "latency": latency_stats(s_lats),
            }
        )

    # 6. Collect Error Cases (FN, FP, plus UNKNOWN/ERROR for analysis)
    error_rows: List[Dict[str, Any]] = []
    priority_order = {"FN": 0, "FP": 1, "UNKNOWN": 2, "ERROR": 3}
    for r in records:
        gt = normalize_verdict(r.get("ground_truth"))
        pred_raw = normalize_verdict(r.get("predicted_verdict"))
        pred_bin = _map_prediction_to_binary(pred_raw, suspicious_as)

        err_type = None
        if gt == "TRUE_POSITIVE" and pred_bin == "NEGATIVE":
            err_type = "FN"
        elif gt == "FALSE_POSITIVE" and pred_bin == "POSITIVE":
            err_type = "FP"
        elif pred_raw == "UNKNOWN":
            err_type = "UNKNOWN"
        elif pred_raw == "ERROR":
            err_type = "ERROR"

        if err_type:
            tools_val = r.get("tools_called") or []
            error_rows.append(
                {
                    "sample_id": r.get("sample_id", ""),
                    "error_type": err_type,
                    "scenario_group": r.get("scenario_group", ""),
                    "ground_truth": gt,
                    "predicted_verdict": pred_raw,
                    "rule_id": r.get("rule_id", ""),
                    "rule_level": r.get("rule_level", 0),
                    "rule_description": r.get("rule_description", ""),
                    "latency_sec": r.get("latency_sec", 0.0),
                    "ti_rate_limited": bool(r.get("ti_rate_limited", False)),
                    "tools_called": ";".join(str(t) for t in tools_val),
                    "reasoning_excerpt": r.get("reasoning_excerpt", ""),
                }
            )
    error_rows.sort(key=lambda row: (priority_order.get(row["error_type"], 9), str(row["sample_id"])))

    # 7. Write errors_<run_name>.csv (UTF-8-SIG for Excel compatibility)
    errors_csv_path = os.path.join(out_dir, f"errors_{resolved_run}.csv")
    csv_fields = [
        "sample_id",
        "error_type",
        "scenario_group",
        "ground_truth",
        "predicted_verdict",
        "rule_id",
        "rule_level",
        "rule_description",
        "latency_sec",
        "ti_rate_limited",
        "tools_called",
        "reasoning_excerpt",
    ]
    with open(errors_csv_path, "w", encoding="utf-8-sig", newline="") as cf:
        writer = csv.DictWriter(cf, fieldnames=csv_fields)
        writer.writeheader()
        for row in error_rows:
            writer.writerow(row)

    # 8. Write report_<run_name>.md
    report_md_path = os.path.join(out_dir, f"report_{resolved_run}.md")
    md_text = render_markdown_report(
        run_name=resolved_run,
        input_path=input_path,
        agent=agent_metrics,
        baseline1=baseline1_metrics,
        baseline2=baseline2_metrics,
        baseline1_level=baseline1_level,
        baseline2_level=baseline2_level,
        suspicious_as=suspicious_as,
        all_lat=all_lat_stats,
        llm_lat=llm_lat_stats,
        ti_rate_limited_total=ti_rate_limited_total,
        tailer_filtered_total=tailer_filtered_total,
        scenario_rows=scenario_rows,
        error_rows=error_rows,
        errors_csv_path=errors_csv_path,
    )
    with open(report_md_path, "w", encoding="utf-8") as mf:
        mf.write(md_text)

    return {
        "run_name": resolved_run,
        "report_md_path": report_md_path,
        "errors_csv_path": errors_csv_path,
        "agent": agent_metrics,
        "baseline1": baseline1_metrics,
        "baseline2": baseline2_metrics,
        "latency": all_lat_stats,
        "llm_latency": llm_lat_stats,
        "ti_rate_limited_total": ti_rate_limited_total,
        "tailer_filtered_total": tailer_filtered_total,
        "scenario_rows": scenario_rows,
        "error_count_csv": len(error_rows),
    }


def render_markdown_report(
    *,
    run_name: str,
    input_path: str,
    agent: Dict[str, Any],
    baseline1: Dict[str, Any],
    baseline2: Dict[str, Any],
    baseline1_level: int,
    baseline2_level: int,
    suspicious_as: str,
    all_lat: Dict[str, float],
    llm_lat: Dict[str, float],
    ti_rate_limited_total: int,
    tailer_filtered_total: int,
    scenario_rows: List[Dict[str, Any]],
    error_rows: List[Dict[str, Any]],
    errors_csv_path: str,
) -> str:
    lines: List[str] = []
    lines.append(f"# BÁO CÁO ĐÁNH GIÁ PHÂN LOẠI CẢNH BÁO SOC AI AGENT (`{run_name}`)")
    lines.append("")
    lines.append(f"- **File kết quả:** `{input_path}`")
    lines.append(f"- **Tổng số mẫu đánh giá:** `{agent['total']}` (Ground Truth: `{agent['total_gt_tp']}` TRUE_POSITIVE, `{agent['total_gt_fp']}` FALSE_POSITIVE)")
    lines.append(f"- **Quy ước nhãn SUSPICIOUS:** `{suspicious_as}`")
    if agent["unknown_total"] or agent["error_total"]:
        lines.append(
            f"- **Ca chưa kết luận / Lỗi:** `UNKNOWN = {agent['unknown_total']}` "
            f"(trên TP: {agent['unknown_tp']}, trên FP: {agent['unknown_fp']}), "
            f"`ERROR = {agent['error_total']}` (trên TP: {agent['error_tp']}, trên FP: {agent['error_fp']})"
        )
    if ti_rate_limited_total or tailer_filtered_total:
        lines.append(
            f"- **Vận hành pipeline:** Lọc nhiễu ở `tailers.py` = `{tailer_filtered_total}` mẫu | "
            f"Gặp Rate-limit/Timeout Threat Intel = `{ti_rate_limited_total}` mẫu"
        )
    lines.append("")

    # Section 1: 3 Core KPIs
    lines.append("## 1. Tóm tắt 3 chỉ số cốt lõi")
    lines.append("")
    lines.append("| Chỉ số | Giá trị đạt được | Công thức & Ghi chú |")
    lines.append("| :--- | :---: | :--- |")
    lines.append(
        f"| **1. Tỷ lệ giảm cảnh báo giả (FP Reduction Rate)** | **{agent['fp_reduction_pct']:.2f}%** ({agent['tn']}/{agent['tn'] + agent['fp']}) | `TN / (TN + FP)`"
        + (f" — Tính trên tổng FP kể cả UNKNOWN/ERROR: `{agent['overall_fp_reduction_pct']:.2f}%` ({agent['tn']}/{agent['total_gt_fp']})" if (agent['unknown_fp'] + agent['error_fp']) > 0 else "")
        + " |"
    )
    lines.append(
        f"| **2. Bỏ sót cảnh báo thật (Missed True Alerts / FNR)** | **{agent['missed_tp_count']} ca ({agent['fnr_pct']:.2f}%)** | `FN / (TP + FN)`"
        + (f" — Tính cả ca TP rơi vào UNKNOWN/ERROR: `{agent['effective_missed_tp']}` ca ({agent['effective_fnr_pct']:.2f}%)" if (agent['unknown_tp'] + agent['error_tp']) > 0 else "")
        + " |"
    )
    lines.append(
        f"| **3. Thời gian xử lý mỗi cảnh báo (Latency)** | Mean: **{all_lat['mean']:.3f}s** · P50: **{all_lat['p50']:.3f}s** · P95: **{all_lat['p95']:.3f}s** | "
        f"Đo qua `time.perf_counter()` trên {all_lat['count']} mẫu hoàn tất (LLM-invoked {llm_lat['count']} mẫu: Mean {llm_lat['mean']:.3f}s) |"
    )
    lines.append("")

    # Section 2: Baseline Comparison Table
    lines.append("## 2. So sánh với Luật Wazuh mặc định (Baseline)")
    lines.append("")
    lines.append(
        "| Phương pháp | FP Reduction `TN/(TN+FP)` | Missed TP (`FN`) | FNR `FN/(TP+FN)` | Accuracy | Precision | Recall | F1-Score | Latency (Mean / P50 / P95) |"
    )
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")

    def _row(name: str, m: Dict[str, Any], lat_txt: str) -> str:
        return (
            f"| {name} | **{m['fp_reduction_pct']:.2f}%** | {m['missed_tp_count']} | **{m['fnr_pct']:.2f}%** | "
            f"{m['accuracy_pct']:.2f}% | {m['precision_pct']:.2f}% | {m['recall_pct']:.2f}% | {m['f1_pct']:.2f}% | {lat_txt} |"
        )

    lines.append(
        _row(
            f"Baseline 1: Wazuh mặc định (level >= {baseline1_level})",
            baseline1,
            "~0.000s (Static)",
        )
    )
    lines.append(
        _row(
            f"Baseline 2: Wazuh siết ngưỡng (level >= {baseline2_level})",
            baseline2,
            "~0.000s (Static)",
        )
    )
    lines.append(
        _row(
            "**Hệ thống đề xuất: Wazuh + AI Agent (`qwen3.5:4b`)**",
            agent,
            f"{all_lat['mean']:.3f}s / {all_lat['p50']:.3f}s / {all_lat['p95']:.3f}s",
        )
    )
    lines.append("")

    # Section 3: Confusion Matrix
    lines.append("## 3. Ma trận nhầm lẫn (Confusion Matrix) & Chỉ số tham khảo")
    lines.append("")
    lines.append("| Ground Truth \\ Dự đoán | Predicted POSITIVE | Predicted NEGATIVE | UNKNOWN | ERROR | Tổng GT |")
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: |")
    lines.append(
        f"| **TRUE_POSITIVE (Tấn công thật)** | **TP = {agent['tp']}** | **FN = {agent['fn']}** | {agent['unknown_tp']} | {agent['error_tp']} | {agent['total_gt_tp']} |"
    )
    lines.append(
        f"| **FALSE_POSITIVE (Cảnh báo giả)** | **FP = {agent['fp']}** | **TN = {agent['tn']}** | {agent['unknown_fp']} | {agent['error_fp']} | {agent['total_gt_fp']} |"
    )
    lines.append("")
    lines.append(
        f"- **Accuracy:** `{agent['accuracy_pct']:.2f}%` | **Precision:** `{agent['precision_pct']:.2f}%` | "
        f"**Recall:** `{agent['recall_pct']:.2f}%` | **F1-Score:** `{agent['f1_pct']:.2f}%`"
    )
    lines.append("")

    # Section 4: Per-scenario Breakdown
    lines.append("## 4. Thống kê chi tiết theo từng nhóm kịch bản (`scenario_group`)")
    lines.append("")
    lines.append("| Kịch bản (`scenario_group`) | Tổng | TP | FP | TN | FN | UNK/ERR | Accuracy | FP Reduction | FNR | Mean Latency |")
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
    for s in scenario_rows:
        m = s["metrics"]
        lat = s["latency"]
        unk_err = m["unknown_total"] + m["error_total"]
        fp_red_str = f"{m['fp_reduction_pct']:.1f}%" if (m["tn"] + m["fp"]) > 0 else "N/A"
        fnr_str = f"{m['fnr_pct']:.1f}%" if (m["tp"] + m["fn"]) > 0 else "N/A"
        acc_str = f"{m['accuracy_pct']:.1f}%" if m["decided_total"] > 0 else "N/A"
        lines.append(
            f"| `{s['scenario_group']}` | {m['total']} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | {unk_err} | "
            f"{acc_str} | {fp_red_str} | {fnr_str} | {lat['mean']:.3f}s |"
        )
    lines.append("")

    # Section 5: Error Analysis Summary
    lines.append("## 5. Danh sách lỗi phục vụ phân tích Vòng 2")
    lines.append("")
    lines.append(f"- Đã xuất `{len(error_rows)}` mẫu cần rà soát (`FN`, `FP`, `UNKNOWN`, `ERROR`) ra file: `{errors_csv_path}`")
    if error_rows:
        lines.append("")
        lines.append("| Sample ID | Loại lỗi | Scenario | Rule ID (Lv) | Ground Truth -> Pred | Tools | Trích đoạn lý do |")
        lines.append("| :--- | :---: | :--- | :---: | :--- | :--- | :--- |")
        for er in error_rows[:25]:
            excerpt = str(er["reasoning_excerpt"] or "").replace("|", "/").replace("\n", " ")[:120]
            lines.append(
                f"| `{er['sample_id']}` | **{er['error_type']}** | `{er['scenario_group']}` | "
                f"`{er['rule_id']}` (Lv.{er['rule_level']}) | `{er['ground_truth']}` -> `{er['predicted_verdict']}` | "
                f"`{er['tools_called'] or '-'}` | {excerpt} |"
            )
        if len(error_rows) > 25:
            lines.append(f"| ... | ... | ... | ... | Còn `{len(error_rows) - 25}` dòng trong CSV | ... | ... |")
    lines.append("")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Tổng hợp Confusion Matrix, 3 chỉ số chính và so sánh Baseline cho Benchmark."
    )
    parser.add_argument("--input", required=True, help="File predictions_<run_name>.jsonl")
    parser.add_argument("--run-name", default=None, help="Tên đợt chạy (mặc định suy ra từ tên file)")
    parser.add_argument("--dataset", default=None, help="File dataset JSONL gốc (tùy chọn để bổ sung rule_description)")
    parser.add_argument(
        "--output-dir",
        default=os.path.join(BENCHMARK_DIR, "results"),
        help="Thư mục lưu report_<run_name>.md và errors_<run_name>.csv",
    )
    parser.add_argument("--baseline1-level", type=int, default=6, help="Ngưỡng Wazuh mặc định (mặc định: 6)")
    parser.add_argument("--baseline2-level", type=int, default=10, help="Ngưỡng siết cứng so sánh Baseline 2 (mặc định: 10)")
    parser.add_argument(
        "--suspicious-as",
        choices=["positive", "unknown", "negative"],
        default="positive",
        help="Cách quy đổi nhãn SUSPICIOUS khi tính Confusion Matrix (mặc định: positive)",
    )

    args = parser.parse_args(argv)
    res = evaluate_predictions(
        input_path=args.input,
        run_name=args.run_name,
        dataset_path=args.dataset,
        output_dir=args.output_dir,
        baseline1_level=args.baseline1_level,
        baseline2_level=args.baseline2_level,
        suspicious_as=args.suspicious_as,
    )

    ag = res["agent"]
    b1 = res["baseline1"]
    b2 = res["baseline2"]
    lat = res["latency"]

    print(f"=== BENCHMARK REPORT: {res['run_name']} ===")
    print(f"Samples     : {ag['total']} (GT TP={ag['total_gt_tp']}, GT FP={ag['total_gt_fp']}, UNK={ag['unknown_total']}, ERR={ag['error_total']})")
    print(f"1) FP Reduction Rate : {ag['fp_reduction_pct']:.2f}% (TN={ag['tn']}, FP={ag['fp']})")
    print(f"2) Missed True Alerts: {ag['missed_tp_count']} ({ag['fnr_pct']:.2f}%) (FN={ag['fn']}, TP={ag['tp']})")
    print(f"3) Latency (sec)     : Mean={lat['mean']:.3f}s | P50={lat['p50']:.3f}s | P95={lat['p95']:.3f}s")
    print(f"Ref Metrics          : Acc={ag['accuracy_pct']:.2f}% | Prec={ag['precision_pct']:.2f}% | Rec={ag['recall_pct']:.2f}% | F1={ag['f1_pct']:.2f}%")
    print("--- Baseline Comparison ---")
    print(f"  Baseline 1 (Wazuh default >= {args.baseline1_level}) : FP Reduction={b1['fp_reduction_pct']:.2f}% | Missed TP={b1['missed_tp_count']} ({b1['fnr_pct']:.2f}%) | F1={b1['f1_pct']:.2f}%")
    print(f"  Baseline 2 (Static >= {args.baseline2_level})        : FP Reduction={b2['fp_reduction_pct']:.2f}% | Missed TP={b2['missed_tp_count']} ({b2['fnr_pct']:.2f}%) | F1={b2['f1_pct']:.2f}%")
    print(f"  Proposed AI Agent              : FP Reduction={ag['fp_reduction_pct']:.2f}% | Missed TP={ag['missed_tp_count']} ({ag['fnr_pct']:.2f}%) | F1={ag['f1_pct']:.2f}%")
    print(f"Saved Markdown : {res['report_md_path']}")
    print(f"Saved Errors   : {res['errors_csv_path']} ({res['error_count_csv']} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
