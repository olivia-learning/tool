import unittest
from unittest.mock import patch

from ai_ssh_mcp.server import run_shell_commands
from ai_ssh_mcp.ssh_client import validate_shell_commands


class ShellCommandTests(unittest.TestCase):
    def test_allows_basic_shell_commands(self):
        validate_shell_commands(["pwd", "cd /tmp", "ls -l"])

    def test_rejects_empty_command_list(self):
        with self.assertRaises(ValueError):
            validate_shell_commands([])

    def test_rejects_chained_command(self):
        with self.assertRaises(ValueError):
            validate_shell_commands(["pwd; reboot"])

    def test_rejects_sensitive_path(self):
        with self.assertRaises(ValueError):
            validate_shell_commands(["cat /etc/shadow"])

    def test_run_requires_user_confirmation_before_any_connection(self):
        with patch("ai_ssh_mcp.server.EmbeddedSSHSession") as session:
            result = run_shell_commands(["pwd"], user_confirmed=False)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "needs_user_confirmation")
        session.assert_not_called()


if __name__ == "__main__":
    unittest.main()

