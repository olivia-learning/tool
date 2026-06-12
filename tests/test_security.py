import unittest

from ai_ssh_mcp.security import (
    DiagnosticCommand,
    generate_plan,
    hash_commands,
    truncate_output,
    validate_commands,
    verify_plan_integrity,
)


class SecurityTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

