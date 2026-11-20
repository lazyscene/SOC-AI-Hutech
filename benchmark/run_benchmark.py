"""Script 2: Offline Replay Benchmark in strict Dry-Run mode with Checkpoint/Resume."""

import argparse
import os
import re
import sys
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BENCHMARK_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmark.common import (  # noqa: E402
    append_jsonl_line,
    normalize_verdict,
    read_jsonl,
    setup_agent_imports,
)

# Must disable persistence and load .env BEFORE importing agent/ modules.
setup_agent_imports()

import core.case_manager as case_manager  # noqa: E402
import core.controller as controller  # noqa: E402
import core.llm as llm_mod  # noqa: E402
import tools.analysis_tools  # noqa: F401, E402
import tools.base as tools_base  # noqa: E402
import tools.firewall_tools as firewall_tools  # noqa: E402
import tools.threat_intel_tools as ti_tools  # noqa: E402
import tools.wazuh_tools as wazuh_tools  # noqa: E402
import watchers.tailers as tailers  # noqa: E402
import web.state as web_state  # noqa: E402


class _NoOpThread:
    """Drop-in replacement for threading.Thread to keep benchmark single-threaded & deterministic."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None, **extra):
        self.target = target
        self.args = args
        self.kwargs = kwargs or {}
        self.daemon = daemon

    def start(self) -> None:
        return None

    def join(self, timeout=None) -> None:
        return None


def reset_in_memory_state() -> None:
    """Reset web.state.STATE and tailer cooldown cache so each sample is evaluated statelessly."""
    with web_state._STATE_LOCK:
        web_state.STATE["stats"] = {
            "total_alerts": 0,
            "true_positives": 0,
            "false_positives": 0,
            "suspicious": 0,
            "unknown": 0,
            "total_cases": 0,
            "active_cases": 0,
            "blocked_ips": [],
            "endpoint_actions": [],
        }
        web_state.STATE["pfsense_block_details"] = {}
        web_state.STATE["endpoint_containment"] = {}
        web_state.STATE["agent_ip_registry"] = {}
        web_state.STATE["cases"] = []
        web_state.STATE["parent_incidents"] = []
        web_state.STATE["assets"] = []
        web_state.STATE["dismissed_asset_agents"] = []
        web_state.STATE["contingency_rooms"] = []
        web_state.STATE["tactical_decisions"] = []
        web_state.STATE["control_audit_logs"] = []
        web_state.STATE.pop("_rooms_initialized", None)
        web_state.STATE["reasoning_stream"] = deque(maxlen=50)
        web_state.STATE["decisions"] = deque(maxlen=30)

    tailers.last_alert_time.clear()


def _load_json_dict(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        import json

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _clean_excerpt(text: Any, max_len: int = 300) -> str:
    collapsed = re.sub(r"\s+", " ", str(text or "").strip())
    if len(collapsed) <= max_len:
        return collapsed
    return collapsed[: max_len - 3].rstrip() + "..."


class DryRunSandbox:
    """
    Context manager that redirects persistence, mocks pfSense & Wazuh Active Response,
    protects Threat Intel APIs against rate limits, and instruments LLM tool calls.
    """

    def __init__(
        self,
        *,
        ti_cache_ttl: int = 86400,
        ti_offline: bool = False,
        ollama_url: Optional[str] = None,
        model: Optional[str] = None,
        ti_cache_file: Optional[str] = None,
    ):
        self.ti_cache_ttl = ti_cache_ttl
        self.ti_offline = ti_offline
        self.ollama_url = ollama_url
        self.model = model
        self.ti_cache_file = ti_cache_file or os.path.join(BENCHMARK_DIR, "data", "ti_cache_benchmark.json")
        self._saved: List[Tuple[Any, str, Any]] = []
        self._saved_tools_map: Dict[str, Any] = {}
        self.sample_ctx: Dict[str, Any] = {}
        self.reset_sample_ctx()

    def reset_sample_ctx(self) -> None:
        self.sample_ctx = {
            "tools_called": [],
            "dry_run_actions": [],
            "ti_rate_limited": False,
            "ollama_error": None,
        }

    def _patch(self, target: Any, attr: str, value: Any) -> None:
        self._saved.append((target, attr, getattr(target, attr)))
        setattr(target, attr, value)

    def __enter__(self) -> "DryRunSandbox":
        # 1. Disable real persistence everywhere
        def noop_save(*args, **kwargs) -> bool:
            return False

        def noop_load(*args, **kwargs) -> bool:
            return False

        for mod in (web_state, controller, case_manager, firewall_tools, wazuh_tools):
            if hasattr(mod, "save_persistent_state"):
                self._patch(mod, "save_persistent_state", noop_save)
        self._patch(web_state, "load_persistent_state", noop_load)

        # Ensure optional contingency_room persistence hook is also neutralized
        try:
            import core.contingency_room as contingency_room
            import core.asset_manager as asset_manager

            if hasattr(contingency_room, "save_persistent_state"):
                self._patch(contingency_room, "save_persistent_state", noop_save)
            if hasattr(asset_manager, "save_persistent_state"):
                self._patch(asset_manager, "save_persistent_state", noop_save)
        except Exception:
            pass

        # 2. Prevent background threads spawned inside tailers & controller
        self._patch(tailers.threading, "Thread", _NoOpThread)
        self._patch(controller.threading, "Thread", _NoOpThread)

        # 3. Isolate TI cache into benchmark cache file seeded from production cache
        bench_cache_path = self.ti_cache_file
        orig_cache_path = ti_tools.CACHE_FILE_PATH
        merged_cache: Dict[str, Any] = {}
        merged_cache.update(_load_json_dict(orig_cache_path))
        merged_cache.update(_load_json_dict(bench_cache_path))

        self._patch(ti_tools, "CACHE_FILE_PATH", bench_cache_path)
        self._patch(ti_tools, "CACHE_TTL_SECONDS", (86400 * 3650) if self.ti_cache_ttl <= 0 else self.ti_cache_ttl)
        self._patch(ti_tools, "TI_CACHE", merged_cache)

        if self.ti_offline:
            self._patch(ti_tools, "VIRUSTOTAL_API_KEY", "")
            self._patch(ti_tools, "ABUSEIPDB_API_KEY", "")

        # Wrap TI rate limiter & HTTP client to never crash and always record rate limits
        orig_rate_limit_vt = ti_tools.rate_limit_vt
        sandbox = self

        def safe_rate_limit_vt() -> bool:
            ok = orig_rate_limit_vt()
            if not ok:
                sandbox.sample_ctx["ti_rate_limited"] = True
            return ok

        self._patch(ti_tools, "rate_limit_vt", safe_rate_limit_vt)

        orig_requests_get = ti_tools.requests.get

        def guarded_ti_get(url: str, *args, **kwargs):
            try:
                resp = orig_requests_get(url, *args, **kwargs)
                if getattr(resp, "status_code", None) == 429 and (
                    "virustotal.com" in str(url) or "abuseipdb.com" in str(url)
                ):
                    sandbox.sample_ctx["ti_rate_limited"] = True
                return resp
            except Exception:
                if "virustotal.com" in str(url) or "abuseipdb.com" in str(url):
                    sandbox.sample_ctx["ti_rate_limited"] = True
                raise

        self._patch(ti_tools.requests, "get", guarded_ti_get)

        orig_check_ip = ti_tools.tool_check_ip_reputation
        orig_check_hash = ti_tools.tool_check_file_hash

        def safe_check_ip(ip: str) -> str:
            try:
                res = orig_check_ip(ip)
            except Exception as exc:
                sandbox.sample_ctx["ti_rate_limited"] = True
                return f"[TI IP] Rate Limit/Timeout ({exc}). Status: TI_ERROR / UNKNOWN"
            if not sandbox.ti_offline and (
                "429" in str(res) or "Rate Limit" in str(res) or "TI_ERROR" in str(res)
            ):
                sandbox.sample_ctx["ti_rate_limited"] = True
            return res

        def safe_check_hash(file_hash: str) -> str:
            try:
                res = orig_check_hash(file_hash)
            except Exception as exc:
                sandbox.sample_ctx["ti_rate_limited"] = True
                return f"[TI Hash] Rate Limit/Timeout ({exc}). Status: TI_ERROR / UNKNOWN"
            if not sandbox.ti_offline and (
                "429" in str(res) or "Rate Limit" in str(res) or "TI_ERROR" in str(res)
            ):
                sandbox.sample_ctx["ti_rate_limited"] = True
            return res

        # Preserve TOOLS_MAP references
        for name in ("tool_block_firewall_ip", "tool_wazuh_endpoint_response", "tool_check_ip_reputation", "tool_check_file_hash"):
            if name in tools_base.TOOLS_MAP:
                self._saved_tools_map[name] = tools_base.TOOLS_MAP[name]

        self._patch(ti_tools, "tool_check_ip_reputation", safe_check_ip)
        self._patch(ti_tools, "tool_check_file_hash", safe_check_hash)
        self._patch(controller, "tool_check_ip_reputation", safe_check_ip)
        self._patch(controller, "tool_check_file_hash", safe_check_hash)
        tools_base.TOOLS_MAP["tool_check_ip_reputation"] = safe_check_ip
        tools_base.TOOLS_MAP["tool_check_file_hash"] = safe_check_hash

        # 4. Dry-Run pfSense Firewall Mocks (ZERO real pfSense API calls)
        def dry_run_get_alias():
            return {"id": 0, "name": firewall_tools.PFSENSE_ALIAS_NAME, "address": [], "detail": []}

        def dry_run_apply():
            return True

        def dry_run_sync_pfsense(quiet: bool = False):
            return True, list(web_state.STATE["stats"].get("blocked_ips", []))

        def dry_run_clear_pfsense():
            web_state.STATE["stats"]["blocked_ips"] = []
            web_state.STATE["pfsense_block_details"] = {}
            return True, "[DRY-RUN] Simulated action succeeded (clear SOC_BLOCKLIST)"

        def dry_run_modify_alias(clean_ip: str, action: str, reason: str = ""):
            blocked = web_state.STATE["stats"].setdefault("blocked_ips", [])
            details = web_state.STATE.setdefault("pfsense_block_details", {})
            if action == "add":
                if clean_ip not in blocked:
                    blocked.append(clean_ip)
                details[clean_ip] = f"[DRY-RUN] {reason[:40]}"
                sandbox.sample_ctx["dry_run_actions"].append(f"pfsense_block:{clean_ip}")
                return True, f"[DRY-RUN] Simulated action succeeded — Thành công: Đã giả lập chặn IP {clean_ip} vào {firewall_tools.PFSENSE_ALIAS_NAME}."
            if action == "remove":
                if clean_ip in blocked:
                    blocked.remove(clean_ip)
                details.pop(clean_ip, None)
                sandbox.sample_ctx["dry_run_actions"].append(f"pfsense_unblock:{clean_ip}")
                return True, f"[DRY-RUN] Simulated action succeeded — Thành công: Đã giả lập gỡ IP {clean_ip}."
            return False, f"[DRY-RUN] Invalid action: {action}"

        def dry_run_block_ip(ip: str, reason: str = "Malicious activity"):
            is_valid, check_result = firewall_tools.validate_blockable_ip(ip)
            if not is_valid:
                return check_result
            _, msg = dry_run_modify_alias(check_result, "add", reason)
            return msg

        def dry_run_unblock_ip(ip: str):
            clean_ip = (ip or "").strip()
            if not clean_ip or clean_ip == "unknown":
                return "IP không hợp lệ."
            _, msg = dry_run_modify_alias(clean_ip, "remove", "")
            return msg

        self._patch(firewall_tools, "get_or_create_soc_alias", dry_run_get_alias)
        self._patch(firewall_tools, "apply_firewall_changes", dry_run_apply)
        self._patch(firewall_tools, "sync_pfsense_blocklist", dry_run_sync_pfsense)
        self._patch(firewall_tools, "clear_all_pfsense_blocks", dry_run_clear_pfsense)
        self._patch(firewall_tools, "_modify_blocklist_alias", dry_run_modify_alias)
        self._patch(firewall_tools, "tool_block_firewall_ip", dry_run_block_ip)
        self._patch(firewall_tools, "tool_unblock_firewall_ip", dry_run_unblock_ip)
        self._patch(controller, "tool_block_firewall_ip", dry_run_block_ip)
        tools_base.TOOLS_MAP["tool_block_firewall_ip"] = dry_run_block_ip

        # 5. Dry-Run Wazuh Active Response Mocks (ZERO real :55000 calls)
        def dry_run_jwt(force_refresh: bool = False) -> str:
            return "dry-run-wazuh-jwt"

        def dry_run_dispatch_wazuh(agent_id: str, command: str, arguments=None):
            is_valid, agent_res = wazuh_tools.validate_target_agent(agent_id)
            if not is_valid:
                return False, agent_res
            sandbox.sample_ctx["dry_run_actions"].append(f"wazuh_ar:{command}:{agent_res}")
            return True, f"[DRY-RUN] Simulated action succeeded (Wazuh AR '{command}' on Agent {agent_res})"

        self._patch(wazuh_tools, "get_wazuh_jwt_token", dry_run_jwt)
        self._patch(wazuh_tools, "dispatch_wazuh_ar", dry_run_dispatch_wazuh)

        # Wrap phase2 endpoint response & controller references cleanly for visibility
        orig_wazuh_ep_resp = wazuh_tools.tool_wazuh_endpoint_response

        def tracked_wazuh_ep_resp(**kwargs):
            return orig_wazuh_ep_resp(**kwargs)

        self._patch(controller, "tool_wazuh_endpoint_response", tracked_wazuh_ep_resp)
        tools_base.TOOLS_MAP["tool_wazuh_endpoint_response"] = tracked_wazuh_ep_resp

        # 6. Instrument Ollama configuration & tool-call capture
        if self.ollama_url:
            self._patch(llm_mod, "OLLAMA_API_URL", self.ollama_url)
        if self.model:
            self._patch(llm_mod, "LLM_MODEL", self.model)

        orig_call_ollama = controller.call_ollama

        def instrumented_call_ollama(messages: list, tools: list = None):
            try:
                resp = orig_call_ollama(messages, tools)
            except Exception as exc:
                sandbox.sample_ctx["ollama_error"] = str(exc)
                raise

            msg = resp.get("message") if isinstance(resp, dict) else {}
            if isinstance(msg, dict):
                for call in msg.get("tool_calls") or []:
                    if isinstance(call, dict):
                        fn_name = (call.get("function") or {}).get("name")
                        if fn_name:
                            sandbox.sample_ctx["tools_called"].append(str(fn_name))
            return resp

        self._patch(controller, "call_ollama", instrumented_call_ollama)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        for name, orig_fn in self._saved_tools_map.items():
            tools_base.TOOLS_MAP[name] = orig_fn
        for target, attr, old_val in reversed(self._saved):
            setattr(target, attr, old_val)


def evaluate_single_sample(record: Dict[str, Any], sandbox: DryRunSandbox) -> Dict[str, Any]:
    """Replay one benchmark JSONL record through tailers + controller in stateless Dry-Run mode."""
    reset_in_memory_state()
    sandbox.reset_sample_ctx()

    sample_id = str(record.get("sample_id", "") or "")
    ground_truth = normalize_verdict(record.get("ground_truth"))
    scenario_group = str(record.get("scenario_group", "unknown") or "unknown")
    rule_id = str(record.get("rule_id", "") or "")
    try:
        rule_level = int(record.get("rule_level", 0) or 0)
    except (TypeError, ValueError):
        rule_level = 0
    rule_description = str(record.get("rule_description", "") or "")
    raw_alert = record.get("raw_alert") or {}

    t0 = time.perf_counter()
    filtered_by_tailer = False
    raw_verdict = "UNKNOWN"
    reasoning_excerpt = ""

    try:
        event = tailers.process_alert_event(raw_alert, is_historical=False, seen_ids=None)
        if event is None:
            filtered_by_tailer = True
            raw_verdict = "FALSE_POSITIVE"
            reasoning_excerpt = "[PRE-FILTER] Filtered by tailers.py noise filter (ignored/deleted/below trigger threshold)"
            latency_sec = round(time.perf_counter() - t0, 4)
        else:
            controller.run_agent_loop(event.to_dict())
            latency_sec = round(time.perf_counter() - t0, 4)

            if sandbox.sample_ctx.get("ollama_error"):
                raw_verdict = "ERROR"
                reasoning_excerpt = _clean_excerpt(f"[OLLAMA_ERROR] {sandbox.sample_ctx['ollama_error']}")
            elif web_state.STATE["decisions"]:
                dec = web_state.STATE["decisions"][0]
                raw_verdict = dec.get("verdict", "UNKNOWN")
                reasoning_excerpt = _clean_excerpt(dec.get("summary", ""))
            elif web_state.STATE["cases"]:
                c_obj = web_state.STATE["cases"][0]
                raw_verdict = c_obj.get("verdict", "UNKNOWN")
                reasoning_excerpt = _clean_excerpt(c_obj.get("summary", ""))
            else:
                raw_verdict = "ERROR"
                reasoning_excerpt = "[CONTROLLER_ERROR] No decision or case produced"
    except Exception as exc:
        latency_sec = round(time.perf_counter() - t0, 4)
        raw_verdict = "ERROR"
        reasoning_excerpt = _clean_excerpt(f"[EXCEPTION] {type(exc).__name__}: {exc}")

    predicted_verdict = normalize_verdict(raw_verdict)
    if predicted_verdict not in ("TRUE_POSITIVE", "FALSE_POSITIVE", "SUSPICIOUS", "UNKNOWN", "ERROR"):
        predicted_verdict = "UNKNOWN"

    return {
        "sample_id": sample_id,
        "ground_truth": ground_truth,
        "predicted_verdict": predicted_verdict,
        "scenario_group": scenario_group,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_description": rule_description,
        "latency_sec": latency_sec,
        "tools_called": list(sandbox.sample_ctx.get("tools_called", [])),
        "ti_rate_limited": bool(sandbox.sample_ctx.get("ti_rate_limited", False)),
        "filtered_by_tailer": filtered_by_tailer,
        "reasoning_excerpt": reasoning_excerpt,
        "evaluated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def load_completed_ids(predictions_path: str, retry_errors: bool = False) -> set:
    """Inspect existing predictions file and return sample_ids already finished."""
    latest_by_id: Dict[str, str] = {}
    for rec in read_jsonl(predictions_path):
        sid = str(rec.get("sample_id", "") or "").strip()
        if not sid:
            continue
        latest_by_id[sid] = normalize_verdict(rec.get("predicted_verdict"))

    if not retry_errors:
        return set(latest_by_id.keys())
    return {sid for sid, pred in latest_by_id.items() if pred != "ERROR"}


def run_benchmark(
    *,
    input_path: str,
    run_name: str,
    output_dir: Optional[str] = None,
    only_verified: bool = False,
    limit: Optional[int] = None,
    retry_errors: bool = False,
    ti_cache_ttl: int = 86400,
    ti_offline: bool = False,
    ollama_url: Optional[str] = None,
    model: Optional[str] = None,
    ti_cache_file: Optional[str] = None,
    quiet: bool = False,
) -> Dict[str, Any]:
    """Run Offline Replay Dry-Run benchmark over a dataset with full Checkpoint/Resume."""
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Không tìm thấy dataset input: {input_path}")

    safe_run = re.sub(r"[^A-Za-z0-9._-]+", "_", run_name.strip()) or "default"
    out_dir = output_dir or os.path.join(BENCHMARK_DIR, "results")
    os.makedirs(out_dir, exist_ok=True)
    predictions_path = os.path.join(out_dir, f"predictions_{safe_run}.jsonl")

    all_records = read_jsonl(input_path)
    if only_verified:
        target_records = [r for r in all_records if bool(r.get("label_verified")) is True]
    else:
        target_records = list(all_records)

    completed_ids = load_completed_ids(predictions_path, retry_errors=retry_errors)
    pending_records = [
        r for r in target_records if str(r.get("sample_id", "") or "").strip() not in completed_ids
    ]
    if limit is not None and limit > 0:
        pending_records = pending_records[:limit]

    evaluated_now = 0
    error_count = 0
    ti_rate_limited_count = 0

    with DryRunSandbox(
        ti_cache_ttl=ti_cache_ttl,
        ti_offline=ti_offline,
        ollama_url=ollama_url,
        model=model,
        ti_cache_file=ti_cache_file,
    ) as sandbox:
        with open(predictions_path, "a", encoding="utf-8") as out_fh:
            total_pending = len(pending_records)
            for idx, rec in enumerate(pending_records, 1):
                pred_row = evaluate_single_sample(rec, sandbox)
                append_jsonl_line(out_fh, pred_row)
                evaluated_now += 1
                if pred_row["predicted_verdict"] == "ERROR":
                    error_count += 1
                if pred_row["ti_rate_limited"]:
                    ti_rate_limited_count += 1
                if not quiet:
                    print(
                        f"[{idx}/{total_pending}] {pred_row['sample_id']} "
                        f"| GT={pred_row['ground_truth']} -> Pred={pred_row['predicted_verdict']} "
                        f"| {pred_row['latency_sec']:.2f}s | tools={pred_row['tools_called']}"
                        + (" [TI_RATE_LIMITED]" if pred_row["ti_rate_limited"] else ""),
                        flush=True,
                    )

    return {
        "run_name": safe_run,
        "predictions_path": predictions_path,
        "dataset_total": len(all_records),
        "eligible_total": len(target_records),
        "resumed_skipped": len(completed_ids),
        "evaluated_now": evaluated_now,
        "errors_now": error_count,
        "ti_rate_limited_now": ti_rate_limited_count,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Chạy Offline Replay Benchmark (Dry-Run) cho SOC AI Agent với Checkpoint/Resume."
    )
    parser.add_argument("--input", required=True, help="File dataset JSONL đã gán nhãn")
    parser.add_argument("--run-name", required=True, help="Tên đợt chạy (vd: v1_qwen35)")
    parser.add_argument(
        "--output-dir",
        default=os.path.join(BENCHMARK_DIR, "results"),
        help="Thư mục lưu file predictions_<run_name>.jsonl",
    )
    parser.add_argument(
        "--only-verified",
        action="store_true",
        help="Chỉ chạy các mẫu có label_verified == true",
    )
    parser.add_argument("--limit", type=int, default=None, help="Giới hạn số mẫu chạy trong lần gọi này")
    parser.add_argument(
        "--retry-errors",
        action="store_true",
        help="Khi resume, chạy lại các mẫu trước đó bị ERROR",
    )
    parser.add_argument(
        "--ti-cache-ttl",
        type=int,
        default=86400,
        help="TTL cache Threat Intel (giây); <=0 nghĩa là cache vĩnh viễn trong lúc benchmark",
    )
    parser.add_argument(
        "--ti-offline",
        action="store_true",
        help="Tắt gọi API VirusTotal/AbuseIPDB ra ngoài, chỉ dùng TI Cache & MISP Vault nội bộ",
    )
    parser.add_argument("--ollama-url", default=None, help="Ghi đè OLLAMA_API_URL nếu cần")
    parser.add_argument("--model", default=None, help="Ghi đè LLM_MODEL nếu cần (vd: qwen3.5:4b)")

    args = parser.parse_args(argv)
    summary = run_benchmark(
        input_path=args.input,
        run_name=args.run_name,
        output_dir=args.output_dir,
        only_verified=args.only_verified,
        limit=args.limit,
        retry_errors=args.retry_errors,
        ti_cache_ttl=args.ti_cache_ttl,
        ti_offline=args.ti_offline,
        ollama_url=args.ollama_url,
        model=args.model,
    )
    print(f"[BENCHMARK] Predictions : {summary['predictions_path']}")
    print(
        f"[BENCHMARK] Dataset={summary['eligible_total']} | ResumedSkipped={summary['resumed_skipped']} "
        f"| EvaluatedNow={summary['evaluated_now']} | ErrorsNow={summary['errors_now']} "
        f"| TIRateLimitedNow={summary['ti_rate_limited_now']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
