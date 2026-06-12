import unittest
import os
import tempfile

from ai_ssh_mcp.security import (
    DiagnosticCommand,
    add_allowlist_commands,
    delete_allowlist_commands,
    generate_plan,
    hash_commands,
    list_allowlist_commands,
    make_custom_command_id,
    truncate_output,
    validate_commands,
    verify_plan_integrity,
)
from ai_ssh_mcp.config import APP_DIR_ENV


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self._old_home = os.environ.get(APP_DIR_ENV)
        self._tmp = tempfile.TemporaryDirectory()
        os.environ[APP_DIR_ENV] = self._tmp.name

    def tearDown(self):
        if self._old_home is None:
            os.environ.pop(APP_DIR_ENV, None)
        else:
            os.environ[APP_DIR_ENV] = self._old_home
        self._tmp.cleanup()

    def test_network_task_selects_network_commands(self):
        plan = generate_plan("检查网络为什么不通")
        commands = [command.command for command in plan.commands]
        self.assertIn("ip addr show", commands)
        self.assertIn("ip route show", commands)
        self.assertIn("cat /etc/resolv.conf", commands)

    def test_log_task_selects_logs(self):
        plan = generate_plan("查看最近错误日志")
        commands = [command.command for command in plan.commands]
        self.assertIn("dmesg", commands)
        self.assertIn("logread", commands)

    def test_rejects_non_allowlisted_command(self):
        with self.assertRaises(ValueError):
            validate_commands([DiagnosticCommand("cat /etc/shadow", "not allowed")])

    def test_rejects_dangerous_pipe_to_shell(self):
        with self.assertRaises(ValueError):
            validate_commands([DiagnosticCommand("echo test | sh", "dangerous")])

    def test_rejects_redirection_write(self):
        with self.assertRaises(ValueError):
            validate_commands([DiagnosticCommand("echo test > /tmp/x", "dangerous")])

    def test_rejects_sensitive_custom_command(self):
        with self.assertRaises(ValueError):
            add_allowlist_commands([{"command": "cat /etc/shadow", "purpose": "blocked"}])

    def test_rejects_chained_custom_command(self):
        with self.assertRaises(ValueError):
            add_allowlist_commands(
                [{"command": "cat /etc/os-release; cat /etc/passwd", "purpose": "blocked"}]
            )

    def test_plan_hash_detects_tampering(self):
        plan = generate_plan("检查磁盘空间")
        tampered = plan.to_dict()
        tampered["commands"][0]["command"] = "reboot"
        from ai_ssh_mcp.security import DiagnosticPlan

        with self.assertRaises(ValueError):
            verify_plan_integrity(DiagnosticPlan.from_dict(tampered))

    def test_hash_is_stable(self):
        commands = [DiagnosticCommand("hostname", "读取设备主机名")]
        self.assertEqual(hash_commands(commands), hash_commands(commands))

    def test_truncate_output(self):
        output, truncated = truncate_output("a" * 20, limit=10)
        self.assertTrue(truncated)
        self.assertTrue(output.startswith("a" * 10))

    def test_add_custom_allowlist_command_and_plan_by_id(self):
        command = "cat /etc/os-release"
        result = add_allowlist_commands(
            [{"command": command, "purpose": "读取系统发行版本"}]
        )
        command_id = make_custom_command_id(command)
        self.assertEqual(result["added"][0]["command_id"], command_id)
        listed = list_allowlist_commands(include_disabled=False)
        self.assertIn(command, [item.command for item in listed])
        plan = generate_plan("查看系统版本", command_ids=[command_id])
        self.assertIn(command, [item.command for item in plan.commands])

    def test_delete_custom_allowlist_command(self):
        command = "cat /etc/os-release"
        add_allowlist_commands([{"command": command, "purpose": "读取系统发行版本"}])
        command_id = make_custom_command_id(command)
        result = delete_allowlist_commands(command_ids=[command_id])
        self.assertEqual(result["deleted"][0]["command_id"], command_id)
        listed = list_allowlist_commands(include_disabled=False)
        self.assertNotIn(command, [item.command for item in listed])

    def test_delete_builtin_disables_it(self):
        result = delete_allowlist_commands(command_ids=["hostname"])
        self.assertEqual(result["disabled_builtin"][0]["command_id"], "hostname")
        listed = list_allowlist_commands(include_disabled=False)
        self.assertNotIn("hostname", [item.command_id for item in listed])

    def test_unknown_requested_command_id_is_rejected(self):
        with self.assertRaises(ValueError):
            generate_plan("检查系统", command_ids=["custom:missing"])


if __name__ == "__main__":
    unittest.main()
