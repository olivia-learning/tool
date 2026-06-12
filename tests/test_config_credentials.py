import tempfile
import unittest
from pathlib import Path

from ai_ssh_mcp.config import DeviceConfig, load_config, save_config
from ai_ssh_mcp.credentials import (
    SERVICE_NAME,
    CredentialStore,
    credential_key,
    SSH_PASSWORD_KIND,
    SU_PASSWORD_KIND,
)


class FakeKeyring:
    def __init__(self):
        self.values = {}

    def set_password(self, service, key, value):
        self.values[(service, key)] = value

    def get_password(self, service, key):
        return self.values.get((service, key))


class ConfigAndCredentialTests(unittest.TestCase):
    def test_config_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            config = DeviceConfig(host="192.0.2.10", username="root", port=2222)
            save_config(config, path)
            self.assertEqual(load_config(path), config)

    def test_credential_keys_include_device_identity(self):
        config = DeviceConfig(host="device.local", username="admin", port=22)
        self.assertEqual(
            credential_key(config, SSH_PASSWORD_KIND),
            "device.local:22:admin:ssh-password",
        )
        self.assertEqual(
            credential_key(config, SU_PASSWORD_KIND),
            "device.local:22:admin:su-password",
        )

    def test_fake_keyring_round_trip(self):
        config = DeviceConfig(host="device.local", username="admin")
        backend = FakeKeyring()
        store = CredentialStore(backend=backend)
        store.set_device_secrets(config, "ssh-secret", "su-secret")
        secrets = store.get_device_secrets(config)
        self.assertEqual(secrets.ssh_password, "ssh-secret")
        self.assertEqual(secrets.su_password, "su-secret")
        self.assertIn((SERVICE_NAME, credential_key(config, SSH_PASSWORD_KIND)), backend.values)


if __name__ == "__main__":
    unittest.main()
