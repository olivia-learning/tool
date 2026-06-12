import unittest

from ai_ssh_mcp.ssh_client import parse_marked_output


class SSHOutputParserTests(unittest.TestCase):
    def test_parse_marked_output(self):
        marker = "AI_SSH_MCP_abc"
        raw = (
            "noise\n"
            f"__{marker}_START__\n"
            "hello\n"
            "world\n"
            f"__{marker}_END__:0\n"
            "# "
        )
        stdout, status = parse_marked_output(raw, marker)
        self.assertEqual(stdout, "hello\nworld")
        self.assertEqual(status, 0)

    def test_parse_missing_marker_returns_255(self):
        stdout, status = parse_marked_output("plain output", "missing")
        self.assertEqual(stdout, "plain output")
        self.assertEqual(status, 255)


if __name__ == "__main__":
    unittest.main()

