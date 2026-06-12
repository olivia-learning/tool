import re
import unittest

from ai_ssh_mcp.ssh_client import (
    shell_single_quote,
    strip_interactive_echo_and_prompt,
    validate_interactive_tool_request,
)


class InteractiveToolTests(unittest.TestCase):
    def test_valid_interactive_tool_request(self):
        validate_interactive_tool_request(
            work_dir="/opt/vendor/bin",
            tool_command="./maint_tool",
            inputs=["show status"],
            prompt_pattern=r"xxx>$",
            prompt_settle_seconds=0.8,
        )

    def test_rejects_relative_work_dir(self):
        with self.assertRaises(ValueError):
            validate_interactive_tool_request(
                work_dir="opt/vendor/bin",
                tool_command="./maint_tool",
                inputs=["show status"],
                prompt_pattern=r"xxx>$",
                prompt_settle_seconds=0.8,
            )

    def test_rejects_shell_chaining_tool_command(self):
        with self.assertRaises(ValueError):
            validate_interactive_tool_request(
                work_dir="/opt/vendor/bin",
                tool_command="./maint_tool; reboot",
                inputs=["show status"],
                prompt_pattern=r"xxx>$",
                prompt_settle_seconds=0.8,
            )

    def test_rejects_multiline_input(self):
        with self.assertRaises(ValueError):
            validate_interactive_tool_request(
                work_dir="/opt/vendor/bin",
                tool_command="./maint_tool",
                inputs=["show status\nquit"],
                prompt_pattern=r"xxx>$",
                prompt_settle_seconds=0.8,
            )

    def test_shell_single_quote(self):
        self.assertEqual(shell_single_quote("/opt/a b"), "'/opt/a b'")
        self.assertEqual(shell_single_quote("/opt/a'b"), "'/opt/a'\"'\"'b'")

    def test_strip_echo_and_last_prompt(self):
        output = strip_interactive_echo_and_prompt(
            "show status\r\nline 1\r\nline 2\r\nxxx>",
            "show status",
            re.compile(r"xxx>$", re.MULTILINE),
        )
        self.assertEqual(output, "line 1\nline 2")

    def test_strip_uses_last_prompt(self):
        output = strip_interactive_echo_and_prompt(
            "line before\nxxx>\nlate line\nxxx>",
            "show",
            re.compile(r"xxx>$", re.MULTILINE),
        )
        self.assertEqual(output, "line before\nxxx>\nlate line")


if __name__ == "__main__":
    unittest.main()

