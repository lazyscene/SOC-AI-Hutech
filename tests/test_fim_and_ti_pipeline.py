import os
import sys
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Tắt ghi đè file soc_state.json thật trong quá trình chạy unit test
os.environ["SOC_DISABLE_STATE_PERSISTENCE"] = "1"

# Add 'agent' directory to sys.path so modules import seamlessly
AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "agent"))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from core.models import AlertEvent, safe_get, normalize_hash
from core.parsers import parse_verdict, extract_mitre_tags, extract_ti_summary
from core.controller import run_agent_loop
from watchers.tailers import (
    process_alert_event,
    extract_sysmon_hashes,
    extract_hashes_and_metadata,
    last_alert_time
)
from tools.firewall_tools import (
    validate_blockable_ip,
    tool_block_firewall_ip,
    get_protected_ips,
    sync_pfsense_blocklist,
)
from tools.analysis_tools import tool_check_ip_context
from tools.threat_intel_tools import tool_check_file_hash, tool_check_ip_reputation
from tools.wazuh_tools import validate_target_agent, validate_quarantine_path, tool_wazuh_endpoint_response
from web.state import (
    STATE,
    save_persistent_state,
    load_persistent_state,
    get_agent_memory_context,
)


class TestFimAndSysmonUnit(unittest.TestCase):
    """Bộ Unit Test kiểm thử luồng chuẩn hóa FIM và Sysmon theo Quy tắc 1-8"""

    def setUp(self):
        last_alert_time.clear()

    def test_fim_added_rule_554_level_5(self):
        """Test Wazuh FIM added (Rule 554 ở level: 5) phải được kích hoạt phân tích"""
        raw_alert = {
            "id": "fim-add-554",
            "rule": {
                "id": "554",
                "level": 5,
                "description": "File added to the system.",
                "groups": ["ossec", "syscheck"]
            },
            "agent": {
                "id": "002",
                "name": "victim-server",
                "ip": "192.168.214.10"
            },
            "syscheck": {
                "path": "/var/www/html/shell.php",
                "event": "added",
                "sha256_after": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
                "md5_after": "69630e4574ec6798239b091cda43dca0"
            }
        }

        with patch("watchers.tailers.threading.Thread") as mock_thread:
            event = process_alert_event(raw_alert, is_historical=False)
            self.assertIsNotNone(event, "Rule 554 với file added có hash phải được kích hoạt")
            self.assertEqual(event.primary_hash, "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267")
            self.assertEqual(event.src_ip, "unknown", "FIM nội bộ src_ip phải là unknown")
            self.assertEqual(event.agent_ip, "192.168.214.10")
            self.assertEqual(event.victim_ip, "192.168.214.10")
            self.assertEqual(event.file_path, "/var/www/html/shell.php")
            self.assertEqual(event.event_type, "added")
            self.assertTrue(mock_thread.called, "Phải khởi tạo luồng phân tích AI")

    def test_fim_modified_rule_550_level_7(self):
        """Test Wazuh FIM modified (Rule 550 ở level: 7) với file /tmp/eicar_test.php"""
        raw_alert = {
            "id": "fim-mod-550",
            "rule": {
                "id": "550",
                "level": 7,
                "description": "Integrity checksum changed.",
                "groups": ["ossec", "syscheck"]
            },
            "agent": {
                "id": "002",
                "name": "victim-server",
                "ip": "192.168.214.10"
            },
            "syscheck": {
                "path": "/tmp/eicar_test.php",
                "event": "modified",
                "sha256_after": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "md5_after": "44d88612fea8a8f36de82e1278abb02f"
            }
        }

        with patch("watchers.tailers.threading.Thread") as mock_thread:
            event = process_alert_event(raw_alert, is_historical=False)
            self.assertIsNotNone(event)
            self.assertEqual(event.primary_hash, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            self.assertEqual(event.file_path, "/tmp/eicar_test.php")
            self.assertIn("44d88612fea8a8f36de82e1278abb02f", event.file_hashes)
            self.assertTrue(mock_thread.called)

    def test_fim_deleted_rule_553_does_not_trigger(self):
        """Test Wazuh FIM deleted (Rule 553): Không gọi LLM và không tra cứu hash"""
        raw_alert = {
            "id": "fim-del-553",
            "rule": {
                "id": "553",
                "level": 7,
                "description": "File deleted from the system.",
                "groups": ["ossec", "syscheck"]
            },
            "agent": {
                "name": "victim-server",
                "ip": "192.168.214.10"
            },
            "syscheck": {
                "path": "/tmp/cleanup.sh",
                "event": "deleted"
            }
        }

        with patch("watchers.tailers.threading.Thread") as mock_thread, \
             patch("tools.threat_intel_tools.tool_check_file_hash") as mock_vt:
            event = process_alert_event(raw_alert, is_historical=False)
            self.assertIsNone(event, "FIM deleted không được kích hoạt AlertEvent")
            self.assertFalse(mock_thread.called, "Không được gọi luồng AI loop khi file deleted")
            self.assertFalse(mock_vt.called, "Không được gọi tool_check_file_hash khi file deleted")

    def test_sysmon_windows_hash_parser(self):
        """Test parser chuỗi Sysmon Windows win.eventdata.hashes tách đúng ALGO=HASH và chuẩn hóa lowercase"""
        sysmon_str = "MD5=69630E4574EC6798239B091CDA43DCA0,SHA256=131F95C51CC819465FA1797F6CCACF9D494AAAFF46FA3EAC73AE63FFBDFD8267,IMPHASH=28A0F"
        parsed = extract_sysmon_hashes(sysmon_str)

        self.assertIn("sha256", parsed)
        self.assertEqual(parsed["sha256"], "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267")
        self.assertIn("md5", parsed)
        self.assertEqual(parsed["md5"], "69630e4574ec6798239b091cda43dca0")

        # Test trích xuất metadata với ưu tiên SHA256
        data = {"data": {"win": {"eventdata": {"hashes": sysmon_str}}}}
        primary, hashes, _, _ = extract_hashes_and_metadata(data)
        self.assertEqual(primary, "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267")
        self.assertEqual(hashes[0], "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267")

    def test_missing_agent_ip_and_srcip(self):
        """Test cảnh báo thiếu agent.ip và thiếu srcip: Hệ thống xử lý an toàn không crash"""
        raw_alert = {
            "id": "alert-no-ip",
            "rule": {"id": "100001", "level": 8, "description": "Generic Alert", "groups": ["ids"]},
            "agent": {"name": "agent-no-ip"}
        }
        with patch("watchers.tailers.threading.Thread"):
            event = process_alert_event(raw_alert, is_historical=False)
            self.assertIsNotNone(event)
            self.assertEqual(event.src_ip, "unknown")
            self.assertEqual(event.agent_ip, "unknown")
            self.assertEqual(event.victim_ip, "unknown")

    def test_missing_sha256_fallback_to_md5(self):
        """Test khi thiếu SHA256 nhưng có MD5, primary_hash fallback chuẩn xác về MD5"""
        data = {
            "syscheck": {
                "path": "/tmp/legacy_file.bin",
                "event": "added",
                "md5_after": "44D88612FEA8A8F36DE82E1278ABB02F"
            }
        }
        primary, hashes, path, event_type = extract_hashes_and_metadata(data)
        self.assertEqual(primary, "44d88612fea8a8f36de82e1278abb02f")
        self.assertEqual(hashes, ["44d88612fea8a8f36de82e1278abb02f"])

    def test_is_historical_true_does_not_trigger(self):
        """Test cảnh báo lịch sử (is_historical=True) chỉ nạp seen_ids, không gọi LLM/Firewall"""
        raw_alert = {
            "id": "hist-alert-999",
            "rule": {"id": "550", "level": 7, "description": "Historical FIM", "groups": ["syscheck"]},
            "agent": {"name": "server1", "ip": "192.168.214.10"},
            "syscheck": {
                "path": "/etc/passwd",
                "event": "modified",
                "sha256_after": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"
            }
        }
        seen = []
        with patch("watchers.tailers.threading.Thread") as mock_thread:
            event = process_alert_event(raw_alert, is_historical=True, seen_ids=seen)
            self.assertIsNone(event)
            self.assertIn("hist-alert-999", seen)
            self.assertFalse(mock_thread.called)

    def test_fim_cooldown_mechanism(self):
        """Test FIM Cooldown: Cùng (agent, file, hash_A) bị chặn, đổi sang (agent, file, hash_B) cho qua ngay"""
        hash_a = "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"
        hash_b = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

        alert1 = {
            "id": "fim-cd-1",
            "rule": {"id": "550", "level": 7, "description": "Mod", "groups": ["syscheck"]},
            "agent": {"name": "victim-srv", "ip": "192.168.214.10"},
            "syscheck": {"path": "/var/www/index.php", "event": "modified", "sha256_after": hash_a}
        }
        alert2 = {
            "id": "fim-cd-2",
            "rule": {"id": "550", "level": 7, "description": "Mod", "groups": ["syscheck"]},
            "agent": {"name": "victim-srv", "ip": "192.168.214.10"},
            "syscheck": {"path": "/var/www/index.php", "event": "modified", "sha256_after": hash_a}
        }
        alert3 = {
            "id": "fim-cd-3",
            "rule": {"id": "550", "level": 7, "description": "Mod", "groups": ["syscheck"]},
            "agent": {"name": "victim-srv", "ip": "192.168.214.10"},
            "syscheck": {"path": "/var/www/index.php", "event": "modified", "sha256_after": hash_b}
        }

        with patch("watchers.tailers.threading.Thread"):
            ev1 = process_alert_event(alert1, is_historical=False)
            self.assertIsNotNone(ev1, "Lần đầu phải được kích hoạt")

            ev2 = process_alert_event(alert2, is_historical=False)
            self.assertIsNone(ev2, "Lần 2 cùng hash_A trong cooldown phải bị chặn")

            ev3 = process_alert_event(alert3, is_historical=False)
            self.assertIsNotNone(ev3, "Đổi sang hash_B phải được kích hoạt phân tích ngay lập tức")

    def test_protected_ips_firewall(self):
        """Test danh sách PROTECTED_IPS: 192.168.214.10 (Victim) và 192.168.171.34 (Wazuh) bị từ chối chặn"""
        # Kiểm tra Victim Server
        valid_vic, msg_vic = validate_blockable_ip("192.168.214.10")
        self.assertFalse(valid_vic)
        self.assertIn("Từ chối chặn IP hệ thống quan trọng", msg_vic)

        # Kiểm tra Wazuh Manager SOC
        valid_wz, msg_wz = validate_blockable_ip("192.168.171.34")
        self.assertFalse(valid_wz)
        self.assertIn("Từ chối chặn IP hệ thống quan trọng", msg_wz)

        # Kiểm tra Host GPU
        valid_host, _ = validate_blockable_ip("192.168.63.1")
        self.assertFalse(valid_host)

        # Kiểm tra IP attacker ngoài danh sách (cho phép)
        valid_atk, _ = validate_blockable_ip("192.168.63.250")
        self.assertTrue(valid_atk)


class TestFimAndTiIntegration(unittest.TestCase):
    """Bộ Integration Test kiểm thử liên kết giữa FIM, Threat Intel, Controller và Firewall Safety"""

    def setUp(self):
        STATE["decisions"].clear()
        STATE["stats"]["total_alerts"] = 0
        STATE["stats"]["true_positives"] = 0
        STATE["stats"]["false_positives"] = 0
        STATE["stats"]["suspicious"] = 0
        STATE["stats"]["unknown"] = 0
        STATE["stats"]["blocked_ips"] = []
        STATE["stats"]["endpoint_actions"] = []
        STATE["pfsense_block_details"] = {}
        STATE["endpoint_containment"] = {}

    @patch("core.controller.call_ollama")
    def test_fim_tool_check_file_hash_executed_once_and_in_context(self, mock_llm):
        """Xác nhận khi có sự kiện FIM chứa hash, tool_check_file_hash được thực thi đúng 1 lần và nạp vào context"""
        # Mock LLM Qwen trả về kết luận TRUE POSITIVE
        mock_llm.return_value = {
            "message": {
                "role": "assistant",
                "content": "Phan quyet: TRUE POSITIVE\nNguyen nhan: Tep tin chua ma doc EICAR test.\nBien phap: Cach ly tep tin tren endpoint."
            }
        }

        eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        alert_payload = {
            "source": "Wazuh FIM (syscheck)",
            "rule_id": "550",
            "level": 7,
            "title": "Integrity checksum changed: EICAR test file",
            "src_ip": "unknown",
            "agent_ip": "192.168.214.10",
            "victim_ip": "192.168.214.10",
            "primary_hash": eicar_hash,
            "file_hashes": [eicar_hash],
            "file_path": "/tmp/eicar.com"
        }

        with patch("core.controller.tool_check_file_hash", wraps=tool_check_file_hash) as spy_tool:
            run_agent_loop(alert_payload)
            self.assertEqual(spy_tool.call_count, 1, "tool_check_file_hash phải được gọi đúng 1 lần")

        # Kiểm tra context gửi lên LLM
        call_args = mock_llm.call_args[0]
        messages = call_args[0]
        user_msg = next(m["content"] for m in messages if m["role"] == "user")
        self.assertIn(eicar_hash, user_msg)
        self.assertIn("Threat Intelligence", user_msg)

        # Kiểm tra ghi nhận vào STATE
        self.assertEqual(len(STATE["decisions"]), 1)
        decision = STATE["decisions"][0]
        self.assertEqual(decision["verdict"], "TRUE POSITIVE")
        self.assertEqual(decision["primary_hash"], eicar_hash)
        self.assertEqual(decision["victim_ip"], "192.168.214.10")

    @patch("core.controller.call_ollama")
    def test_no_firewall_block_called_on_victim_ip(self, mock_llm):
        """Xác nhận tuyệt đối không có lệnh Firewall block nào gọi lên IP của Victim (192.168.214.10)"""
        # Giả lập Qwen cố tình gọi tool_block_firewall_ip với IP của victim
        mock_llm.side_effect = [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "tool_block_firewall_ip",
                                "arguments": json.dumps({"ip": "192.168.214.10", "reason": "Accidental block"})
                            }
                        }
                    ]
                }
            },
            {
                "message": {
                    "role": "assistant",
                    "content": "Phan quyet: TRUE POSITIVE\nKet luan dieu tra."
                }
            }
        ]

        alert_payload = {
            "source": "Wazuh FIM (syscheck)",
            "rule_id": "550",
            "level": 7,
            "title": "FIM Event on Victim Host",
            "src_ip": "unknown",
            "agent_ip": "192.168.214.10",
            "victim_ip": "192.168.214.10",
            "primary_hash": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
            "file_path": "/tmp/test.sh"
        }

        with patch("tools.firewall_tools.requests.patch") as mock_pfsense_api:
            run_agent_loop(alert_payload)
            self.assertFalse(mock_pfsense_api.called, "Tuyệt đối không được gửi lệnh block lên pfSense cho victim IP")

    @patch("core.controller.call_ollama")
    @patch("tools.threat_intel_tools.requests.get")
    def test_unknown_hash_returns_unknown_verdict(self, mock_vt_get, mock_llm):
        """Xác nhận khi VirusTotal trả về 404 cho hash lạ không có hành vi độc hại, kết luận là UNKNOWN"""
        # Mock VT trả về 404
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_vt_get.return_value = mock_resp

        # Mock Qwen kết luận UNKNOWN khi không có bằng chứng
        mock_llm.return_value = {
            "message": {
                "role": "assistant",
                "content": "Phan quyet: UNKNOWN\nThreat Intelligence: Hash chua tung xuat hien tren VirusTotal (404 Not Found).\nChua du du lieu de danh gia."
            }
        }

        unknown_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        alert_payload = {
            "source": "Wazuh FIM (syscheck)",
            "rule_id": "554",
            "level": 5,
            "title": "New unknown binary created",
            "src_ip": "unknown",
            "agent_ip": "192.168.214.10",
            "victim_ip": "192.168.214.10",
            "primary_hash": unknown_hash,
            "file_path": "/usr/local/bin/custom_tool"
        }

        run_agent_loop(alert_payload)
        self.assertEqual(len(STATE["decisions"]), 1)
        decision = STATE["decisions"][0]
        self.assertEqual(decision["verdict"], "UNKNOWN")
        self.assertEqual(STATE["stats"]["unknown"], 1)

    @patch("core.controller.call_ollama")
    @patch("core.controller.tool_block_firewall_ip")
    def test_kali_wan_attack_triggers_block_and_true_positive(self, mock_block, mock_llm):
        """Xác nhận khi máy Kali (192.168.63.140) tấn công quét Nmap vào Victim, hệ thống chặn IP và gắn TRUE POSITIVE"""
        mock_block.return_value = "Thành công: Đã thêm IP 192.168.63.140 vào SOC_BLOCKLIST trên pfSense và đã Apply thay đổi."
        mock_llm.return_value = {
            "message": {
                "role": "assistant",
                "content": "Phan quyet: SUSPICIOUS\nCanh bao quet Nmap tu mang WAN."
            }
        }

        alert_payload = {
            "source": "pfSense / Suricata Syslog",
            "rule_id": "100200",
            "level": 7,
            "title": "Suricata NIDS: ET SCAN Nmap Scripting Engine User-Agent Detected [Web Application Attack] (192.168.63.140 -> 192.168.214.10)",
            "src_ip": "192.168.63.140",
            "dest_ip": "192.168.214.10",
            "agent_ip": "unknown",
            "victim_ip": "192.168.214.10"
        }

        run_agent_loop(alert_payload)
        self.assertTrue(mock_block.called, "Phải tự động gọi tool_block_firewall_ip cho IP Kali 192.168.63.140")
        self.assertEqual(len(STATE["decisions"]), 1)
        decision = STATE["decisions"][0]
        self.assertEqual(decision["verdict"], "TRUE POSITIVE")
        self.assertEqual(STATE["stats"]["true_positives"], 1)

    def test_wazuh_ar_safety_guardrails(self):
        """Kiểm tra chốt chặn an toàn: Từ chối tác động lên Agent 000 (Manager) và tệp hệ thống cốt lõi /bin/bash"""
        valid_mgr, msg_mgr = validate_target_agent("000")
        self.assertFalse(valid_mgr)
        self.assertIn("Từ chối Wazuh AR", msg_mgr)

        valid_ep, _ = validate_target_agent("002")
        self.assertTrue(valid_ep)

        res_mgr = tool_wazuh_endpoint_response(agent_id="000", action="keep_isolated", reason="Test block manager")
        self.assertIn("Từ chối Wazuh AR", res_mgr)

        valid_sys_path, msg_path = validate_quarantine_path("/bin/bash")
        self.assertFalse(valid_sys_path)
        self.assertIn("Từ chối cách ly tệp hệ thống cốt lõi", msg_path)

        valid_tmp_path, _ = validate_quarantine_path("/tmp/eicar_test.php")
        self.assertTrue(valid_tmp_path)

    @patch("core.controller.call_ollama")
    @patch("tools.wazuh_tools.dispatch_wazuh_ar")
    def test_two_phase_edr_fim_unexecuted_releases_isolation_keeps_quarantine(self, mock_ar, mock_llm):
        """FIM (Rule 550, agent_id=002, /tmp/eicar_test.php, chưa thực thi) -> Phase 1 cách ly+cô lập tạm -> Phase 2 mở cô lập mạng, giữ cách ly file"""
        mock_ar.return_value = (True, "Wazuh AR queued")
        mock_llm.return_value = {
            "message": {
                "role": "assistant",
                "content": "Phan quyet: TRUE POSITIVE\nTep EICAR nam tren dia chua thuc thi."
            }
        }

        eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        alert_payload = {
            "source": "Wazuh FIM (syscheck)",
            "rule_id": "550",
            "level": 7,
            "title": "Integrity checksum changed: EICAR test file",
            "agent": "victim-linux-server",
            "agent_id": "002",
            "src_ip": "unknown",
            "agent_ip": "192.168.214.10",
            "victim_ip": "192.168.214.10",
            "primary_hash": eicar_hash,
            "file_path": "/tmp/eicar_test.php",
            "event_type": "modified"
        }

        run_agent_loop(alert_payload)
        cmds_called = [call.args[1] for call in mock_ar.call_args_list]
        self.assertIn("!quarantine-file", cmds_called)
        self.assertIn("!isolate-endpoint", cmds_called)
        self.assertIn("!unisolate-endpoint", cmds_called)

        containment = STATE["endpoint_containment"].get("002", {})
        self.assertEqual(containment.get("isolation_status"), "UNISOLATED (FILE QUARANTINED)")
        self.assertTrue(containment.get("file_quarantined"))
        self.assertEqual(containment.get("quarantined_file"), "/tmp/eicar_test.php")
        self.assertIn("Đã mở cô lập mạng", STATE["decisions"][0]["endpoint_response"])

    @patch("core.controller.call_ollama")
    @patch("tools.wazuh_tools.dispatch_wazuh_ar")
    def test_two_phase_edr_executed_spreading_keeps_isolation(self, mock_ar, mock_llm):
        """EDR (agent_id=002, có process_name và MITRE T1021 lây lan) -> Phase 1 cách ly+kill+cô lập -> Phase 2 giữ nguyên cô lập mạng"""
        mock_ar.return_value = (True, "Wazuh AR queued")
        mock_llm.return_value = {
            "message": {
                "role": "assistant",
                "content": "Phan quyet: TRUE POSITIVE\nMITRE ATT&CK: T1021 - Remote Services\nMa doc da thuc thi va dang lay lan ngang."
            }
        }

        eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        alert_payload = {
            "source": "Wazuh SIEM",
            "rule_id": "92001",
            "level": 12,
            "title": "Suspicious Worm Process Executing Lateral Movement",
            "agent": "victim-linux-server",
            "agent_id": "002",
            "src_ip": "unknown",
            "agent_ip": "192.168.214.10",
            "victim_ip": "192.168.214.10",
            "primary_hash": eicar_hash,
            "file_path": "/tmp/worm_spreader.elf",
            "process_name": "/tmp/worm_spreader.elf",
            "process_id": "4321",
            "mitre": ["T1021 - Remote Services"],
            "full_log": "execve /tmp/worm_spreader.elf lateral movement scan"
        }

        run_agent_loop(alert_payload)
        cmds_called = [call.args[1] for call in mock_ar.call_args_list]
        self.assertIn("!quarantine-file", cmds_called)
        self.assertIn("!kill-process", cmds_called)
        self.assertIn("!isolate-endpoint", cmds_called)
        self.assertNotIn("!unisolate-endpoint", cmds_called)

        containment = STATE["endpoint_containment"].get("002", {})
        self.assertEqual(containment.get("isolation_status"), "ISOLATED (LOCKED)")
        self.assertTrue(containment.get("file_quarantined"))
        self.assertEqual(containment.get("killed_process"), "4321")
        self.assertIn("Giữ khóa cô lập mạng", STATE["decisions"][0]["endpoint_response"])

    def test_pfsense_sync_and_already_blocked_ip_updates_state(self):
        """sync_pfsense_blocklist() nạp IP từ pfSense và tool_block_firewall_ip cập nhật STATE kể cả khi IP đã có sẵn"""
        mock_alias = {
            "id": 1,
            "name": "SOC_BLOCKLIST",
            "address": ["192.168.63.140", "192.168.63.200"],
            "detail": ["AI SOC blocked: Nmap Scan", "AI SOC blocked: Brute Force"],
        }
        with patch("tools.firewall_tools.get_or_create_soc_alias", return_value=mock_alias):
            ok, synced = sync_pfsense_blocklist(quiet=False)
            self.assertTrue(ok)
            self.assertEqual(synced, ["192.168.63.140", "192.168.63.200"])
            self.assertEqual(STATE["stats"]["blocked_ips"], ["192.168.63.140", "192.168.63.200"])
            self.assertEqual(STATE["pfsense_block_details"]["192.168.63.140"], "AI SOC blocked: Nmap Scan")

            # Mô phỏng STATE bị rỗng lại (như vừa restart) nhưng pfSense đã có sẵn IP -> gọi block không bị sót STATE
            STATE["stats"]["blocked_ips"] = []
            STATE["pfsense_block_details"] = {}
            msg = tool_block_firewall_ip("192.168.63.140", "Repeated Nmap")
            self.assertIn("đã nằm trong danh sách chặn", msg)
            self.assertIn("192.168.63.140", STATE["stats"]["blocked_ips"])
            self.assertIn("192.168.63.200", STATE["stats"]["blocked_ips"])

    def test_cross_tool_memory_context_and_state_persistence(self):
        """Kiểm tra trí nhớ pfSense/Wazuh/Incident cho tool & controller và lưu/khôi phục soc_state.json"""
        STATE["stats"]["blocked_ips"] = ["192.168.63.140"]
        STATE["pfsense_block_details"] = {"192.168.63.140": "AI SOC blocked: Nmap Scan"}
        STATE["endpoint_containment"]["002"] = {
            "agent_id": "002",
            "isolation_status": "UNISOLATED (FILE QUARANTINED)",
            "quarantined_files": ["/tmp/eicar.php"],
            "killed_processes": [],
        }
        STATE["decisions"].appendleft({
            "time": "14:00:00",
            "src_ip": "192.168.63.140",
            "agent_id": "000",
            "verdict": "TRUE POSITIVE",
            "title": "Previous Nmap Scan",
        })

        # 1. Kiểm tra tool_check_ip_context và tool_check_ip_reputation có gắn nhãn trí nhớ pfSense
        ctx_out = tool_check_ip_context("192.168.63.140")
        self.assertIn("ĐÃ CHẶN trong SOC_BLOCKLIST", ctx_out)
        self.assertIn("TRUE POSITIVE 1 lần", ctx_out)

        rep_out = tool_check_ip_reputation("192.168.63.140")
        self.assertIn("[pfSense: ĐÃ CHẶN trong SOC_BLOCKLIST]", rep_out)

        # 2. Kiểm tra get_agent_memory_context tổng hợp cả 3 nguồn
        mem_net = get_agent_memory_context(src_ip="192.168.63.140")
        self.assertIn("pfSense Memory", mem_net)
        self.assertIn("Incident History Memory", mem_net)

        mem_ep = get_agent_memory_context(src_ip="unknown", agent_id="002", file_path="/tmp/eicar.php")
        self.assertIn("Wazuh AR Memory", mem_ep)
        self.assertIn("/tmp/eicar.php", mem_ep)

        # 3. Kiểm tra lưu & khôi phục persistent state với file tạm
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_state_file = os.path.join(tmpdir, "soc_state.json")
            with patch.dict(os.environ, {"SOC_DISABLE_STATE_PERSISTENCE": "0"}):
                saved = save_persistent_state(state_file=temp_state_file)
                self.assertTrue(saved)

                # Xóa sạch STATE trên RAM như vừa khởi động lại
                STATE["stats"]["blocked_ips"] = []
                STATE["pfsense_block_details"] = {}
                STATE["endpoint_containment"] = {}
                STATE["decisions"].clear()

                loaded = load_persistent_state(state_file=temp_state_file)
                self.assertTrue(loaded)
                self.assertEqual(STATE["stats"]["blocked_ips"], ["192.168.63.140"])
                self.assertEqual(STATE["pfsense_block_details"]["192.168.63.140"], "AI SOC blocked: Nmap Scan")
                self.assertEqual(STATE["endpoint_containment"]["002"]["isolation_status"], "UNISOLATED (FILE QUARANTINED)")
                self.assertEqual(len(STATE["decisions"]), 1)


if __name__ == "__main__":
    unittest.main()
