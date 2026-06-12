import unittest

from ai_ssh_mcp.ssh_client import (
    safe_local_filename,
    unique_filename,
    validate_remote_file_path,
)


class DownloadPathTests(unittest.TestCase):
    def test_valid_remote_path(self):
        validate_remote_file_path("/var/log/messages")

    def test_rejects_relative_remote_path(self):
        with self.assertRaises(ValueError):
            validate_remote_file_path("var/log/messages")

    def test_rejects_wildcard_remote_path(self):
        with self.assertRaises(ValueError):
            validate_remote_file_path("/var/log/*.log")

    def test_rejects_sensitive_remote_path(self):
        with self.assertRaises(ValueError):
            validate_remote_file_path("/etc/shadow")

    def test_safe_local_filename(self):
        self.assertEqual(safe_local_filename("/var/log/messages"), "messages")
        self.assertEqual(safe_local_filename("/tmp/a b.txt"), "a_b.txt")

    def test_unique_filename(self):
        used = {"messages"}
        self.assertEqual(unique_filename("messages", used), "messages_2")


if __name__ == "__main__":
    unittest.main()
