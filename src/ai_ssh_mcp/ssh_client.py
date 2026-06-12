from __future__ import annotations

import re
import stat
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from posixpath import basename as posix_basename

from .config import DeviceConfig
from .credentials import DeviceSecrets
from .security import DiagnosticCommand, truncate_output, validate_command_safety, validate_commands
from .store import CommandResult


class SSHExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class ConnectionCheck:
    ok: bool
    message: str
    username_output: str = ""
    root_check_output: str = ""


@dataclass(frozen=True)
class DownloadedFile:
    remote_path: str
    local_path: str
    size_bytes: int
    ok: bool
    message: str = ""


@dataclass(frozen=True)
class InteractiveCommandResult:
    input: str
    output: str
    duration_ms: int
    truncated: bool = False


SENSITIVE_REMOTE_PATH_PATTERN = re.compile(
    r"(^|/)(shadow|gshadow|sudoers)$|(^|/)(\.ssh|ssl/private)(/|$)|(^|/)proc/kcore$",
    re.IGNORECASE,
)

SAFE_TOOL_COMMAND_PATTERN = re.compile(r"^\./[A-Za-z0-9._-]+(?:\s+[A-Za-z0-9._=:/-]+)*$")


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

    def run_shell_commands(
        self, commands: list[str], command_timeout: int = 30
    ) -> list[CommandResult]:
        validate_shell_commands(commands)
        return [
            self._run_shell_command(
                command=command,
                purpose="用户确认的普通 shell 命令",
                timeout=command_timeout,
            )
            for command in commands
        ]

    def download_files_sftp(
        self,
        remote_paths: list[str],
        local_dir: str,
        max_bytes_per_file: int = 50 * 1024 * 1024,
    ) -> list[DownloadedFile]:
        if not remote_paths:
            raise ValueError("remote_paths is required")
        if max_bytes_per_file <= 0:
            raise ValueError("max_bytes_per_file must be positive")
        client = self._require_client()
        target_dir = Path(local_dir).expanduser().resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

        results: list[DownloadedFile] = []
        sftp = client.open_sftp()
        try:
            used_names: set[str] = set()
            for remote_path in remote_paths:
                validate_remote_file_path(remote_path)
                filename = safe_local_filename(remote_path)
                filename = unique_filename(filename, used_names)
                used_names.add(filename)
                local_path = target_dir / filename
                attrs = sftp.stat(remote_path)
                if stat.S_ISDIR(attrs.st_mode):
                    raise ValueError(f"Remote path is a directory, not a file: {remote_path}")
                size = int(attrs.st_size or 0)
                if size > max_bytes_per_file:
                    raise ValueError(
                        f"Remote file is {size} bytes, above max_bytes_per_file={max_bytes_per_file}: {remote_path}"
                    )
                sftp.get(remote_path, str(local_path))
                results.append(
                    DownloadedFile(
                        remote_path=remote_path,
                        local_path=str(local_path),
                        size_bytes=size,
                        ok=True,
                    )
                )
        finally:
            sftp.close()
        return results

    def run_interactive_tool(
        self,
        work_dir: str,
        tool_command: str,
        inputs: list[str],
        prompt_pattern: str,
        startup_timeout: int = 30,
        command_timeout: int = 30,
        prompt_settle_seconds: float = 0.8,
    ) -> list[InteractiveCommandResult]:
        validate_interactive_tool_request(
            work_dir=work_dir,
            tool_command=tool_command,
            inputs=inputs,
            prompt_pattern=prompt_pattern,
            prompt_settle_seconds=prompt_settle_seconds,
        )
        channel = self._require_channel()
        prompt = re.compile(prompt_pattern, re.MULTILINE)
        self._send_line(f"cd {shell_single_quote(work_dir)}")
        self._read_until_prompt_quiet(prompt, startup_timeout, prompt_settle_seconds)
        self._send_line(tool_command)
        startup_output = self._read_until_prompt_quiet(
            prompt, startup_timeout, prompt_settle_seconds
        )
        if not prompt.search(startup_output):
            raise SSHExecutionError("Interactive tool prompt was not detected after startup.")

        results: list[InteractiveCommandResult] = []
        for user_input in inputs:
            started = time.monotonic()
            self._send_line(user_input)
            raw = self._read_until_prompt_quiet(
                prompt, command_timeout, prompt_settle_seconds
            )
            duration_ms = int((time.monotonic() - started) * 1000)
            output = strip_interactive_echo_and_prompt(raw, user_input, prompt)
            output, truncated = truncate_output(output)
            results.append(
                InteractiveCommandResult(
                    input=user_input,
                    output=output,
                    duration_ms=duration_ms,
                    truncated=truncated,
                )
            )
        channel.send("\x03")
        self._read_until_quiet(timeout=1)
        return results

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

    def _require_client(self):
        if self._client is None:
            raise SSHExecutionError("SSH client is not connected.")
        return self._client

    def _send_line(self, value: str) -> None:
        self._require_channel().send(value + "\n")

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

    def _read_until_prompt_quiet(
        self, prompt: re.Pattern[str], timeout: int, settle_seconds: float
    ) -> str:
        channel = self._require_channel()
        deadline = time.monotonic() + timeout
        prompt_seen_at: float | None = None
        chunks: list[str] = []
        while time.monotonic() < deadline:
            if channel.recv_ready():
                data = channel.recv(65535).decode("utf-8", errors="replace")
                chunks.append(data)
                combined = "".join(chunks)
                if prompt.search(combined):
                    prompt_seen_at = time.monotonic()
            elif prompt_seen_at is not None and time.monotonic() - prompt_seen_at >= settle_seconds:
                return "".join(chunks)
            else:
                time.sleep(0.05)
        raise SSHExecutionError("Timed out waiting for interactive prompt and quiet period.")


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


def validate_remote_file_path(remote_path: str) -> None:
    if not remote_path or not remote_path.strip():
        raise ValueError("remote path is required")
    if "\x00" in remote_path or "\n" in remote_path or "\r" in remote_path:
        raise ValueError("remote path must be a single path")
    if "*" in remote_path or "?" in remote_path or "[" in remote_path or "]" in remote_path:
        raise ValueError("remote path wildcards are not allowed; pass explicit file paths")
    normalized = remote_path.strip().replace("\\", "/")
    if not normalized.startswith("/"):
        raise ValueError("remote path must be absolute")
    parts = [part for part in normalized.split("/") if part]
    if any(part == ".." for part in parts):
        raise ValueError("remote path must not contain '..'")
    if SENSITIVE_REMOTE_PATH_PATTERN.search(normalized):
        raise ValueError(f"remote path is blocked as sensitive: {remote_path}")


def safe_local_filename(remote_path: str) -> str:
    filename = posix_basename(remote_path.strip().replace("\\", "/"))
    if not filename or filename in {".", ".."}:
        raise ValueError(f"remote path does not contain a file name: {remote_path}")
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", filename).strip("._")
    if not sanitized:
        raise ValueError(f"remote file name is not usable locally: {remote_path}")
    return sanitized


def unique_filename(filename: str, used_names: set[str]) -> str:
    if filename not in used_names:
        return filename
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    counter = 2
    while True:
        candidate = f"{stem}_{counter}{suffix}"
        if candidate not in used_names:
            return candidate
        counter += 1


def validate_interactive_tool_request(
    work_dir: str,
    tool_command: str,
    inputs: list[str],
    prompt_pattern: str,
    prompt_settle_seconds: float,
) -> None:
    if not work_dir or not work_dir.startswith("/"):
        raise ValueError("work_dir must be an absolute path")
    if "\x00" in work_dir or "\n" in work_dir or "\r" in work_dir or ".." in work_dir.split("/"):
        raise ValueError("work_dir must be a single safe absolute path")
    if not SAFE_TOOL_COMMAND_PATTERN.match(tool_command.strip()):
        raise ValueError("tool_command must look like './tool_name' with simple arguments")
    if not inputs:
        raise ValueError("inputs is required")
    for value in inputs:
        if "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError("each input must be one interactive line")
    if not prompt_pattern:
        raise ValueError("prompt_pattern is required")
    if prompt_settle_seconds < 0.1 or prompt_settle_seconds > 10:
        raise ValueError("prompt_settle_seconds must be between 0.1 and 10")
    re.compile(prompt_pattern)


def validate_shell_commands(commands: list[str]) -> None:
    if not commands:
        raise ValueError("commands is required")
    for command in commands:
        validate_command_safety(command.strip())


def shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def strip_interactive_echo_and_prompt(
    raw: str, user_input: str, prompt: re.Pattern[str]
) -> str:
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.splitlines()
    if lines and lines[0].strip() == user_input.strip():
        lines = lines[1:]
    text = "\n".join(lines)
    matches = list(prompt.finditer(text))
    if matches:
        text = text[: matches[-1].start()]
    return text.strip()
