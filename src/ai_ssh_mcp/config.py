from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


APP_DIR_ENV = "AI_SSH_MCP_HOME"


@dataclass(frozen=True)
class DeviceConfig:
    host: str
    username: str
    port: int = 22
    connect_timeout: int = 15
    command_timeout: int = 30
    banner_timeout: int = 15
    allow_unknown_host: bool = True

    def validate(self) -> None:
        if not self.host.strip():
            raise ValueError("host is required")
        if not self.username.strip():
            raise ValueError("username is required")
        if not (1 <= int(self.port) <= 65535):
            raise ValueError("port must be between 1 and 65535")
        if self.connect_timeout <= 0:
            raise ValueError("connect_timeout must be positive")
        if self.command_timeout <= 0:
            raise ValueError("command_timeout must be positive")
        if self.banner_timeout <= 0:
            raise ValueError("banner_timeout must be positive")


def app_home() -> Path:
    configured = os.environ.get(APP_DIR_ENV)
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".ai_ssh_mcp"


def config_path() -> Path:
    return app_home() / "config.json"


def state_path() -> Path:
    return app_home() / "state.json"


def load_config(path: Path | None = None) -> DeviceConfig:
    target = path or config_path()
    if not target.exists():
        raise FileNotFoundError(
            f"No device config found at {target}. Run configure_device first."
        )
    raw = json.loads(target.read_text(encoding="utf-8"))
    config = DeviceConfig(**raw)
    config.validate()
    return config


def save_config(config: DeviceConfig, path: Path | None = None) -> Path:
    config.validate()
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    write_json_atomic(target, asdict(config))
    return target


def write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    tmp.replace(path)

