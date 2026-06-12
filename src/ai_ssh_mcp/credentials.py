from __future__ import annotations

from dataclasses import dataclass

from .config import DeviceConfig


SERVICE_NAME = "ai-ssh-mcp"
SSH_PASSWORD_KIND = "ssh-password"
SU_PASSWORD_KIND = "su-password"


class CredentialError(RuntimeError):
    pass


@dataclass(frozen=True)
class DeviceSecrets:
    ssh_password: str
    su_password: str


def credential_key(config: DeviceConfig, kind: str) -> str:
    return f"{config.host}:{config.port}:{config.username}:{kind}"


class CredentialStore:
    def __init__(self, backend: object | None = None) -> None:
        self._backend = backend

    @property
    def backend(self) -> object:
        if self._backend is None:
            try:
                import keyring
            except ImportError as exc:
                raise CredentialError(
                    "keyring is not installed. Install project dependencies first."
                ) from exc
            self._backend = keyring
        return self._backend

    def set_device_secrets(
        self, config: DeviceConfig, ssh_password: str, su_password: str
    ) -> None:
        if not ssh_password:
            raise CredentialError("ssh_password is required")
        if not su_password:
            raise CredentialError("su_password is required")
        self.backend.set_password(
            SERVICE_NAME, credential_key(config, SSH_PASSWORD_KIND), ssh_password
        )
        self.backend.set_password(
            SERVICE_NAME, credential_key(config, SU_PASSWORD_KIND), su_password
        )

    def get_device_secrets(self, config: DeviceConfig) -> DeviceSecrets:
        ssh_password = self.backend.get_password(
            SERVICE_NAME, credential_key(config, SSH_PASSWORD_KIND)
        )
        su_password = self.backend.get_password(
            SERVICE_NAME, credential_key(config, SU_PASSWORD_KIND)
        )
        if not ssh_password:
            raise CredentialError("SSH password not found. Run configure_device first.")
        if not su_password:
            raise CredentialError("su password not found. Run configure_device first.")
        return DeviceSecrets(ssh_password=ssh_password, su_password=su_password)

