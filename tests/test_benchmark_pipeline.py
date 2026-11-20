import csv
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

os.environ["SOC_DISABLE_STATE_PERSISTENCE"] = "1"

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmark.common import normalize_verdict, parse_timestamp, read_jsonl  # noqa: E402
from benchmark.evaluate_report import evaluate_predictions, latency_stats  # noqa: E402
from benchmark.extract_alerts import extract_alerts  # noqa: E402
import benchmark.run_benchmark as run_bench_mod  # noqa: E402
import core.controller as controller  # noqa: E402
import tools.threat_intel_tools as ti_tools  # noqa: E402


def _make_network_alert(
    alert_id: str,
    ts: str,
    rule_id: str = "100200",
    level: int = 7,
    desc: str = "Suricata alert",
    srcip: str = "192.168.63.140",
    dstip: str = "192.168.214.10",
    agent_name: str = "pfsense-gw",
    groups=None,
    full_log: str = "",
):
    return {
        "id": alert_id,
        "timestamp": ts,
        "rule": {
            "id": rule_id,
            "level": level,
            "description": desc,
            "groups": groups or ["syslog", "suricata"],
        },
        "agent": {"id": "001", "name": agent_name, "ip": "192.168.171.2"},
        "data": {"srcip": srcip, "dstip": dstip},
        "full_log": full_log or f"Suricata alert src={srcip} dst={dstip} id={alert_id}",
    }


def _make_fim_alert(
    alert_id: str,
    ts: str,
    rule_id: str = "554",
    level: int = 5,
    path: str = "/tmp/test.bin",
    event: str = "added",
    sha256: str = "a" * 64,
    desc: str = "File added to the system.",
):
    return {
        "id": alert_id,
        "timestamp": ts,
        "rule": {"id": rule_id, "level": level, "description": desc, "groups": ["ossec", "syscheck"]},
        "agent": {"id": "002", "name": "linux-victim", "ip": "192.168.214.10"},
        "syscheck": {"path": path, "event": event, "sha256_after": sha256},
        "full_log": f"File '{path}' {event}",
    }


class TestBenchmarkExtractAlerts(unittest.TestCase):
    def test_timestamp_parsing_wazuh_formats(self):
        dt1 = parse_timestamp("2026-11-20T08:15:30.123+0700")
        dt2 = parse_timestamp("2026-11-20 08:15:30")
        dt3 = parse_timestamp("2026-11-20T01:15:30.123Z")
        self.assertIsNotNone(dt1)
        self.assertEqual(dt1.replace(microsecond=0), dt2)
        self.assertEqual(dt1, dt3.astimezone(dt1.tzinfo))

    def test_filter_diversity_and_append(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            alerts_path = os.path.join(tmpdir, "alerts.json")
            out_path = os.path.join(tmpdir, "dataset_raw.jsonl")

            alerts = [
                # Below min_level (should be skipped)
                _make_network_alert("a-low", "2026-11-20T08:05:00.000+0700", rule_id="1001", level=3, desc="Low info"),
                # Broadcast noise (should be skipped)
                _make_network_alert(
                    "a-noise",
                    "2026-11-20T08:06:00.000+0700",
                    rule_id="5100",
                    level=7,
                    desc="Broadcast noise",
                    srcip="239.255.255.250",
                ),
                # FIM deleted rule 553 (should be skipped)
                _make_fim_alert(
                    "a-del",
                    "2026-11-20T08:07:00.000+0700",
                    rule_id="553",
                    level=7,
                    event="deleted",
                    path="/tmp/old.bin",
                ),
                # Outside window (11:00)
                _make_network_alert("a-late", "2026-11-20T11:00:00.000+0700", rule_id="5710", level=6, desc="SSH Attempt"),
                # Valid FIM Rule 554 at level 5 with hash (MUST be included despite min_level=6)
                _make_fim_alert("a-fim554", "2026-11-20T08:10:00.000+0700", rule_id="554", level=5, path="/tmp/eicar.php"),
            ]

            # 12 alerts of same rule across 3 distinct srcips -> cap 5 must include all 3 srcips
            for i in range(12):
                ip = f"192.168.63.{140 + (i % 3)}"
                alerts.append(
                    _make_network_alert(
                        f"a-nmap-{i}",
                        f"2026-11-20T08:{20 + i:02d}:00.000+0700",
                        rule_id="100200",
                        level=8,
                        desc="Port Scan",
                        srcip=ip,
                        full_log=f"Scan variant {i % 4} from {ip}",
                    )
                )

            with open(alerts_path, "w", encoding="utf-8") as f:
                for a in alerts:
                    f.write(json.dumps(a) + "\n")

            res1 = extract_alerts(
                input_path=alerts_path,
                output_path=out_path,
                default_label="FALSE_POSITIVE",
                scenario="benign_window",
                start="2026-11-20 08:00:00",
                end="2026-11-20 09:00:00",
                max_per_rule=5,
                min_level=6,
                append=False,
            )
            self.assertEqual(res1["written_count"], 6)  # 1 FIM + 5 capped rule 100200
            rows1 = read_jsonl(out_path)
            self.assertEqual([r["sample_id"] for r in rows1], [f"BM-{i:04d}" for i in range(1, 7)])
            self.assertTrue(all(r["label_verified"] is False for r in rows1))
            nmap_ips = {r["raw_alert"]["data"]["srcip"] for r in rows1 if r["rule_id"] == "100200"}
            self.assertEqual(nmap_ips, {"192.168.63.140", "192.168.63.141", "192.168.63.142"})

            # Second extraction appended cleanly (window 10:30-11:30 -> picks a-late)
            res2 = extract_alerts(
                input_path=alerts_path,
                output_path=out_path,
                default_label="TRUE_POSITIVE",
                scenario="attack_late",
                start="2026-11-20 10:30:00",
                end="2026-11-20 11:30:00",
                max_per_rule=12,
                min_level=6,
                append=True,
            )
            self.assertEqual(res2["written_count"], 1)
            rows_all = read_jsonl(out_path)
            self.assertEqual(len(rows_all), 7)
            self.assertEqual(rows_all[-1]["sample_id"], "BM-0007")
            self.assertEqual(rows_all[-1]["ground_truth"], "TRUE_POSITIVE")
            self.assertEqual(rows_all[-1]["scenario_group"], "attack_late")

            # Re-appending same window skips duplicate raw_alert.id
            res3 = extract_alerts(
                input_path=alerts_path,
                output_path=out_path,
                default_label="TRUE_POSITIVE",
                scenario="attack_late",
                start="2026-11-20 10:30:00",
                end="2026-11-20 11:30:00",
                max_per_rule=12,
                min_level=6,
                append=True,
            )
            self.assertEqual(res3["written_count"], 0)
            self.assertEqual(len(read_jsonl(out_path)), 7)


def _read_bytes_or_none(path: str):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return f.read()


class TestBenchmarkRunDryRunAndResume(unittest.TestCase):
    def test_dry_run_isolation_tools_rate_limit_and_resume(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dataset_path = os.path.join(tmpdir, "dataset_labeled.jsonl")
            out_dir = os.path.join(tmpdir, "results")
            ti_cache_tmp = os.path.join(tmpdir, "ti_cache_benchmark.json")

            real_state_path = os.path.join(PROJECT_ROOT, "agent", "data", "soc_state.json")
            real_ti_cache_path = os.path.join(PROJECT_ROOT, "agent", "data", "ti_cache.json")
            state_before = _read_bytes_or_none(real_state_path)
            ti_before = _read_bytes_or_none(real_ti_cache_path)

            dataset = [
                {
                    "sample_id": "BM-0001",
                    "ground_truth": "TRUE_POSITIVE",
                    "label_verified": True,
                    "scenario_group": "attack_nmap",
                    "rule_id": "100200",
                    "rule_level": 8,
                    "rule_description": "Suricata Nmap Scan",
                    "raw_alert": _make_network_alert(
                        "id-1",
                        "2026-11-20T10:00:00.000+0700",
                        srcip="192.168.63.140",
                        dstip="192.168.214.10",
                    ),
                },
                {
                    # Same IP as BM-0001 to verify stateless per-sample reset & cooldown bypass
                    "sample_id": "BM-0002",
                    "ground_truth": "FALSE_POSITIVE",
                    "label_verified": True,
                    "scenario_group": "benign_admin",
                    "rule_id": "5715",
                    "rule_level": 6,
                    "rule_description": "SSHD Auth Success from LAN",
                    "raw_alert": _make_network_alert(
                        "id-2",
                        "2026-11-20T10:01:00.000+0700",
                        rule_id="5715",
                        srcip="192.168.214.50",
                        dstip="192.168.214.10",
                    ),
                },
                {
                    # Endpoint FIM triggering VT 429 test
                    "sample_id": "BM-0003",
                    "ground_truth": "TRUE_POSITIVE",
                    "label_verified": True,
                    "scenario_group": "attack_fim",
                    "rule_id": "554",
                    "rule_level": 5,
                    "rule_description": "FIM new binary",
                    "raw_alert": _make_fim_alert(
                        "id-3",
                        "2026-11-20T10:02:00.000+0700",
                        sha256="b" * 64,
                        path="/tmp/unknown_bin",
                    ),
                },
                {
                    # Unverified row should be skipped when only_verified=True
                    "sample_id": "BM-0004",
                    "ground_truth": "FALSE_POSITIVE",
                    "label_verified": False,
                    "scenario_group": "unverified",
                    "rule_id": "5715",
                    "rule_level": 6,
                    "rule_description": "Skip unverified",
                    "raw_alert": _make_network_alert("id-4", "2026-11-20T10:03:00.000+0700"),
                },
            ]
            with open(dataset_path, "w", encoding="utf-8") as f:
                for row in dataset:
                    f.write(json.dumps(row) + "\n")

            def fake_call_ollama(messages, tools=None):
                user_text = str(messages[1].get("content", "")) if len(messages) > 1 else ""
                if tools and not any(m.get("role") == "tool" for m in messages):
                    if "192.168.63.140" in user_text:
                        return {
                            "message": {
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [
                                    {"function": {"name": "tool_check_ip_reputation", "arguments": {"ip": "192.168.63.140"}}},
                                    {"function": {"name": "tool_block_firewall_ip", "arguments": {"ip": "192.168.63.140", "reason": "Scan"}}},
                                ],
                            }
                        }
                    if "192.168.214.50" in user_text:
                        return {
                            "message": {
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [
                                    {"function": {"name": "tool_check_ip_reputation", "arguments": {"ip": "192.168.214.50"}}},
                                ],
                            }
                        }

                if "192.168.63.140" in user_text:
                    return {
                        "message": {
                            "role": "assistant",
                            "content": "- Phan quyet: TRUE POSITIVE\n- Nguyen nhan & Bien phap: Quet mang WAN.",
                        }
                    }
                if "192.168.214.50" in user_text:
                    return {
                        "message": {
                            "role": "assistant",
                            "content": "- Phan quyet: FALSE POSITIVE\n- Nguyen nhan & Bien phap: Quan tri vien LAN.",
                        }
                    }
                # Simulate Ollama timeout on BM-0003 first run
                raise RuntimeError("Ollama read timeout")

            class _Fake429Resp:
                status_code = 429
                text = "rate limit"

            def guard_requests_forbidden(*args, **kwargs):
                url = str(args[0] if args else kwargs.get("url", ""))
                if "virustotal.com" in url:
                    return _Fake429Resp()
                raise AssertionError(f"Real external HTTP call escaped Dry-Run sandbox: {url}")

            with (
                patch.object(controller, "call_ollama", side_effect=fake_call_ollama),
                patch.object(ti_tools, "VIRUSTOTAL_API_KEY", "fake-vt-key"),
                patch.object(ti_tools.requests, "get", side_effect=guard_requests_forbidden),
                patch("requests.post", side_effect=guard_requests_forbidden),
                patch("requests.patch", side_effect=guard_requests_forbidden),
                patch("requests.put", side_effect=guard_requests_forbidden),
            ):
                summary1 = run_bench_mod.run_benchmark(
                    input_path=dataset_path,
                    run_name="test_dry",
                    output_dir=out_dir,
                    only_verified=True,
                    ti_cache_file=ti_cache_tmp,
                    quiet=True,
                )

            self.assertEqual(summary1["evaluated_now"], 3)
            self.assertEqual(summary1["errors_now"], 1)
            self.assertEqual(summary1["ti_rate_limited_now"], 1)

            preds1 = read_jsonl(summary1["predictions_path"])
            self.assertEqual(len(preds1), 3)
            self.assertEqual(preds1[0]["predicted_verdict"], "TRUE_POSITIVE")
            self.assertEqual(preds1[0]["tools_called"], ["tool_check_ip_reputation", "tool_block_firewall_ip"])
            self.assertGreaterEqual(preds1[0]["latency_sec"], 0.0)

            self.assertEqual(preds1[1]["predicted_verdict"], "FALSE_POSITIVE")
            self.assertEqual(preds1[1]["tools_called"], ["tool_check_ip_reputation"])

            self.assertEqual(preds1[2]["predicted_verdict"], "ERROR")
            self.assertTrue(preds1[2]["ti_rate_limited"])
            self.assertIn("OLLAMA_ERROR", preds1[2]["reasoning_excerpt"])

            # Verify zero mutation of production files
            state_after = _read_bytes_or_none(real_state_path)
            ti_after = _read_bytes_or_none(real_ti_cache_path)
            self.assertEqual(state_before, state_after)
            self.assertEqual(ti_before, ti_after)

            # Resume without retry_errors skips all 3 already written rows
            with patch.object(controller, "call_ollama", side_effect=AssertionError("Should not re-run completed samples")):
                summary_skip = run_bench_mod.run_benchmark(
                    input_path=dataset_path,
                    run_name="test_dry",
                    output_dir=out_dir,
                    only_verified=True,
                    retry_errors=False,
                    ti_cache_file=ti_cache_tmp,
                    quiet=True,
                )
            self.assertEqual(summary_skip["resumed_skipped"], 3)
            self.assertEqual(summary_skip["evaluated_now"], 0)

            # Resume WITH retry_errors re-runs only BM-0003
            def fake_call_ollama_recovery(messages, tools=None):
                return {
                    "message": {
                        "role": "assistant",
                        "content": "- Phan quyet: UNKNOWN\n- Nguyen nhan & Bien phap: Chua ro hash.",
                    }
                }

            with (
                patch.object(controller, "call_ollama", side_effect=fake_call_ollama_recovery),
                patch.object(ti_tools, "VIRUSTOTAL_API_KEY", ""),
            ):
                summary_retry = run_bench_mod.run_benchmark(
                    input_path=dataset_path,
                    run_name="test_dry",
                    output_dir=out_dir,
                    only_verified=True,
                    retry_errors=True,
                    ti_cache_file=ti_cache_tmp,
                    quiet=True,
                )
            self.assertEqual(summary_retry["resumed_skipped"], 2)
            self.assertEqual(summary_retry["evaluated_now"], 1)
            self.assertEqual(summary_retry["errors_now"], 0)


class TestBenchmarkEvaluateReport(unittest.TestCase):
    def test_confusion_matrix_metrics_baselines_and_exports(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            preds_path = os.path.join(tmpdir, "predictions_evalrun.jsonl")
            out_dir = os.path.join(tmpdir, "results")

            # 2 TP (levels 8, 12), 1 FN (level 7), 3 TN (levels 6, 7, 10), 1 FP (level 11), 1 UNKNOWN on FP (level 6)
            rows = [
                {"sample_id": "BM-0001", "ground_truth": "TRUE_POSITIVE", "predicted_verdict": "TRUE_POSITIVE", "scenario_group": "attack_nmap", "rule_id": "100200", "rule_level": 8, "rule_description": "Nmap", "latency_sec": 1.0, "tools_called": ["tool_block_firewall_ip"], "reasoning_excerpt": "Scan"},
                {"sample_id": "BM-0002", "ground_truth": "TRUE_POSITIVE", "predicted_verdict": "TRUE_POSITIVE", "scenario_group": "attack_exploit", "rule_id": "100210", "rule_level": 12, "rule_description": "RCE", "latency_sec": 2.0, "tools_called": ["tool_block_firewall_ip"], "reasoning_excerpt": "RCE"},
                {"sample_id": "BM-0003", "ground_truth": "TRUE_POSITIVE", "predicted_verdict": "FALSE_POSITIVE", "scenario_group": "attack_nmap", "rule_id": "100201", "rule_level": 7, "rule_description": "Stealth Probe", "latency_sec": 3.0, "tools_called": ["tool_check_ip_reputation"], "reasoning_excerpt": "Missed stealth probe"},
                {"sample_id": "BM-0004", "ground_truth": "FALSE_POSITIVE", "predicted_verdict": "FALSE_POSITIVE", "scenario_group": "benign_cis", "rule_id": "19001", "rule_level": 6, "rule_description": "CIS Check 1", "latency_sec": 4.0, "tools_called": [], "reasoning_excerpt": "CIS benign"},
                {"sample_id": "BM-0005", "ground_truth": "FALSE_POSITIVE", "predicted_verdict": "FALSE_POSITIVE", "scenario_group": "benign_cis", "rule_id": "19002", "rule_level": 7, "rule_description": "CIS Check 2", "latency_sec": 5.0, "tools_called": [], "reasoning_excerpt": "CIS benign"},
                {"sample_id": "BM-0006", "ground_truth": "FALSE_POSITIVE", "predicted_verdict": "FALSE_POSITIVE", "scenario_group": "benign_admin", "rule_id": "550", "rule_level": 10, "rule_description": "Admin apt upgrade", "latency_sec": 2.0, "tools_called": ["tool_check_file_hash"], "reasoning_excerpt": "Package upgrade"},
                {"sample_id": "BM-0007", "ground_truth": "FALSE_POSITIVE", "predicted_verdict": "TRUE_POSITIVE", "scenario_group": "benign_admin", "rule_id": "61603", "rule_level": 11, "rule_description": "Admin powershell", "latency_sec": 3.0, "tools_called": ["tool_check_ip_context"], "reasoning_excerpt": "False alarm"},
                {"sample_id": "BM-0008", "ground_truth": "FALSE_POSITIVE", "predicted_verdict": "UNKNOWN", "scenario_group": "benign_admin", "rule_id": "554", "rule_level": 6, "rule_description": "Custom internal bin", "latency_sec": 4.0, "tools_called": ["tool_check_file_hash"], "reasoning_excerpt": "404 hash"},
            ]
            with open(preds_path, "w", encoding="utf-8") as f:
                for r in rows:
                    f.write(json.dumps(r) + "\n")

            res = evaluate_predictions(input_path=preds_path, output_dir=out_dir)
            self.assertEqual(res["run_name"], "evalrun")

            ag = res["agent"]
            # TP=2, FN=1, TN=3, FP=1, UNKNOWN_FP=1
            self.assertEqual((ag["tp"], ag["fn"], ag["tn"], ag["fp"], ag["unknown_total"]), (2, 1, 3, 1, 1))
            self.assertAlmostEqual(ag["fp_reduction_pct"], 75.0, places=2)  # 3 / (3 + 1)
            self.assertAlmostEqual(ag["overall_fp_reduction_pct"], 60.0, places=2)  # 3 / 5
            self.assertAlmostEqual(ag["fnr_pct"], 100.0 / 3.0, places=2)  # 1 / (2 + 1)
            self.assertAlmostEqual(ag["accuracy_pct"], (5 / 7) * 100.0, places=2)

            b1 = res["baseline1"]
            self.assertAlmostEqual(b1["fp_reduction_pct"], 0.0, places=2)
            self.assertEqual(b1["missed_tp_count"], 0)

            b2 = res["baseline2"]
            # Baseline 2 (level >= 10):
            # GT TP (levels 8, 12, 7) -> TP=1 (12), FN=2 (8, 7) -> FNR=66.67%
            # GT FP (levels 6, 7, 10, 11, 6) -> FP=2 (10, 11), TN=3 (6, 7, 6) -> FP Reduction=60.00%
            self.assertEqual((b2["tp"], b2["fn"], b2["tn"], b2["fp"]), (1, 2, 3, 2))
            self.assertAlmostEqual(b2["fp_reduction_pct"], 60.0, places=2)
            self.assertAlmostEqual(b2["fnr_pct"], (2 / 3) * 100.0, places=2)

            # Latency helper check on [1, 2, 3, 4, 5]
            ls = latency_stats([1.0, 2.0, 3.0, 4.0, 5.0])
            self.assertAlmostEqual(ls["mean"], 3.0, places=4)
            self.assertAlmostEqual(ls["p50"], 3.0, places=4)
            self.assertAlmostEqual(ls["p95"], 4.8, places=4)

            self.assertTrue(os.path.exists(res["report_md_path"]))
            self.assertTrue(os.path.exists(res["errors_csv_path"]))
            with open(res["report_md_path"], "r", encoding="utf-8") as mf:
                md = mf.read()
            self.assertIn("Tỷ lệ giảm cảnh báo giả", md)
            self.assertIn("Baseline 1", md)
            self.assertIn("Baseline 2", md)

            with open(res["errors_csv_path"], "r", encoding="utf-8-sig") as cf:
                csv_rows = list(csv.DictReader(cf))
            self.assertEqual([r["sample_id"] for r in csv_rows], ["BM-0003", "BM-0007", "BM-0008"])
            self.assertEqual([r["error_type"] for r in csv_rows], ["FN", "FP", "UNKNOWN"])


if __name__ == "__main__":
    unittest.main()
