from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from .config import DeviceConfig
from .credentials import DeviceSecrets
from .security import DiagnosticCommand, truncate_output, validate_commands
from .store import CommandResult


class SSHExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class ConnectionCheck:
    ok: bool
    message: str
    username_output: str = ""
    root_check_output: str = ""


class EmbeddedSSHSession:
    def __init__(
        self,
        config: DeviceConfig,
        secrets: DeviceSecrets,
        paramiko_module: object | None = None,
    ) -> None:
        self.config = config
        self.secrets = secrets
        self._paramiko = paramiko_module
        self._client = None
        self._channel = None

    @property
    def paramiko(self) -> object:
        if self._paramiko is None:
            try:
                import paramiko
            except ImportError as exc:
                raise SSHExecutionError(
                    "paramiko is not installed. Install project dependencies first."
                ) from exc
            self._paramiko = paramiko
        return self._paramiko

    def __enter__(self) -> "EmbeddedSSHSession":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def connect(self) -> None:
        paramiko = self.paramiko
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if self.config.allow_unknown_host:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.config.host,
            port=self.config.port,
            username=self.config.username,
            password=self.secrets.ssh_password,
            look_for_keys=False,
            allow_agent=False,
            timeout=self.config.connect_timeout,
            banner_timeout=self.config.banner_timeout,
        )
        channel = client.invoke_shell()
        channel.settimeout(0.25)
        self._client = client
        self._channel = channel
        self._read_until_quiet(timeout=self.config.connect_timeout)
        self._enter_root_shell()

    def test_connection(self) -> ConnectionCheck:
        try:
            username = self.run_one(
                DiagnosticCommand("id", "确认当前执行身份")
            ).stdout.strip()
            root_check = self._run_shell_command("id -u", timeout=10).stdout.strip()
            if "0" not in root_check:
                return ConnectionCheck(
                    ok=False,
                    message="SSH succeeded, but su did not reach uid 0.",
                    username_output=username,
                    root_check_output=root_check,
                )
            return ConnectionCheck(
                ok=True,
                message="SSH login and su root check succeeded.",
                username_output=username,
                root_check_output=root_check,
            )
        except Exception as exc:
            return ConnectionCheck(ok=False, message=str(exc))

    def run_commands(self, commands: list[DiagnosticCommand]) -> list[CommandResult]:
        validate_commands(commands)
        return [self.run_one(command) for command in commands]

    def run_one(self, diagnostic: DiagnosticCommand) -> CommandResult:
        validate_commands([diagnostic])
        return self._run_shell_command(
            diagnostic.command,
            purpose=diagnostic.purpose,
            timeout=self.config.command_timeout,
        )

    def close(self) -> None:
        if self._channel is not None:
            self._channel.close()
            self._channel = None
        if self._client is not None:
            self._client.close()
            self._client = None

    def _enter_root_shell(self) -> None:
        channel = self._require_channel()
        channel.send("su -\n")
        time.sleep(0.5)
        output = self._read_until_patterns(
            patterns=[r"password", r"密码", r"#", r"\$"],
            timeout=self.config.connect_timeout,
        )
        if re.search(r"password|密码", output, re.IGNORECASE):
            channel.send(self.secrets.su_password + "\n")
            self._read_until_quiet(timeout=self.config.connect_timeout)
        root_check = self._run_shell_command("id -u", timeout=10)
        if not re.search(r"(^|\D)0(\D|$)", root_check.stdout):
            raise SSHExecutionError(
                f"su did not reach uid 0. Output was: {root_check.stdout!r}"
            )

    def _run_shell_command(
        self, command: str, purpose: str = "", timeout: int = 30
    ) -> CommandResult:
        channel = self._require_channel()
        marker = "AI_SSH_MCP_" + uuid.uuid4().hex
        started = time.monotonic()
        shell_line = (
            f"printf '\\n__{marker}_START__\\n'; "
            f"{command}; "
            f"status=$?; printf '\\n__{marker}_END__:%s\\n' \"$status\"\n"
        )
        channel.send(shell_line)
        raw = self._read_until_patterns([rf"__{marker}_END__:\d+"], timeout=timeout)
        duration_ms = int((time.monotonic() - started) * 1000)
        stdout, exit_status = parse_marked_output(raw, marker)
        stdout, truncated = truncate_output(stdout)
        return CommandResult(
            command=command,
            purpose=purpose,
            stdout=stdout,
            stderr="",
            exit_status=exit_status,
            duration_ms=duration_ms,
            truncated=truncated,
        )

    def _require_channel(self):
        if self._channel is None:
            raise SSHExecutionError("SSH channel is not connected.")
        return self._channel

    def _read_until_quiet(self, timeout: int) -> str:
        channel = self._require_channel()
        deadline = time.monotonic() + timeout
        quiet_deadline = time.monotonic() + 0.4
        chunks: list[str] = []
        while time.monotonic() < deadline:
            if channel.recv_ready():
                data = channel.recv(65535).decode("utf-8", errors="replace")
                chunks.append(data)
                quiet_deadline = time.monotonic() + 0.4
            elif time.monotonic() >= quiet_deadline:
                return "".join(chunks)
            else:
                time.sleep(0.05)
        return "".join(chunks)

    def _read_until_patterns(self, patterns: list[str], timeout: int) -> str:
        channel = self._require_channel()
        compiled = [re.compile(pattern, re.IGNORECASE | re.MULTILINE) for pattern in patterns]
        deadline = time.monotonic() + timeout
        chunks: list[str] = []
        while time.monotonic() < deadline:
            if channel.recv_ready():
                data = channel.recv(65535).decode("utf-8", errors="replace")
                chunks.append(data)
                combined = "".join(chunks)
                if any(pattern.search(combined) for pattern in compiled):
                    return combined + self._read_until_quiet(timeout=1)
            else:
                time.sleep(0.05)
        raise SSHExecutionError(f"Timed out waiting for shell output at {datetime.now(timezone.utc).isoformat()}.")


def parse_marked_output(raw: str, marker: str) -> tuple[str, int]:
    start_token = f"__{marker}_START__"
    end_pattern = re.compile(rf"__{re.escape(marker)}_END__:(\d+)")
    start_idx = raw.find(start_token)
    end_match = end_pattern.search(raw)
    if start_idx == -1 or end_match is None:
        return raw.strip(), 255
    body = raw[start_idx + len(start_token) : end_match.start()]
    body = remove_echoed_marker_command(body, marker)
    return body.strip(), int(end_match.group(1))


def remove_echoed_marker_command(body: str, marker: str) -> str:
    lines = body.splitlines()
    cleaned: list[str] = []
    for line in lines:
        if marker in line and "printf" in line:
            continue
        cleaned.append(line)
    return "\n".join(cleaned)

