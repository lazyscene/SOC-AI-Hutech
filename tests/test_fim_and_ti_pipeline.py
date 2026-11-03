import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock

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
from tools.firewall_tools import validate_blockable_ip, tool_block_firewall_ip, get_protected_ips
from tools.threat_intel_tools import tool_check_file_hash
from web.state import STATE


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


if __name__ == "__main__":
    unittest.main()
