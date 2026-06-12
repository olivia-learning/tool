from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .config import app_home, write_json_atomic


OUTPUT_LIMIT_CHARS = 12000
CUSTOM_COMMAND_PREFIX = "custom:"


@dataclass(frozen=True)
class DiagnosticCommand:
    command: str
    purpose: str


@dataclass(frozen=True)
class AllowlistCommand:
    command_id: str
    command: str
    purpose: str
    source: str
    enabled: bool = True

    def to_diagnostic_command(self) -> DiagnosticCommand:
        return DiagnosticCommand(command=self.command, purpose=self.purpose)


@dataclass(frozen=True)
class DiagnosticPlan:
    approval_id: str
    task: str
    created_at: str
    risk_level: str
    risk_note: str
    expected_reads: list[str]
    commands: list[DiagnosticCommand]
    command_hash: str
    status: str = "planned"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["commands"] = [asdict(command) for command in self.commands]
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "DiagnosticPlan":
        commands = [DiagnosticCommand(**command) for command in data["commands"]]
        return cls(
            approval_id=data["approval_id"],
            task=data["task"],
            created_at=data["created_at"],
            risk_level=data["risk_level"],
            risk_note=data["risk_note"],
            expected_reads=list(data["expected_reads"]),
            commands=commands,
            command_hash=data["command_hash"],
            status=data.get("status", "planned"),
        )


COMMAND_CATALOG: dict[str, DiagnosticCommand] = {
    "hostname": DiagnosticCommand("hostname", "读取设备主机名"),
    "uname": DiagnosticCommand("uname -a", "读取内核和系统版本"),
    "uptime": DiagnosticCommand("uptime", "读取运行时间和负载"),
    "date": DiagnosticCommand("date", "读取设备当前时间"),
    "id": DiagnosticCommand("id", "确认当前执行身份"),
    "proc_version": DiagnosticCommand("cat /proc/version", "读取内核构建信息"),
    "loadavg": DiagnosticCommand("cat /proc/loadavg", "读取系统负载"),
    "cpuinfo": DiagnosticCommand("cat /proc/cpuinfo", "读取 CPU 信息"),
    "free": DiagnosticCommand("free", "读取内存概览"),
    "meminfo": DiagnosticCommand("cat /proc/meminfo", "读取详细内存信息"),
    "df": DiagnosticCommand("df -h", "读取磁盘空间"),
    "mount": DiagnosticCommand("mount", "读取挂载点信息"),
    "ps": DiagnosticCommand("ps", "读取进程列表"),
    "ip_addr": DiagnosticCommand("ip addr show", "读取 IP 地址信息"),
    "ifconfig": DiagnosticCommand("ifconfig -a", "读取网络接口信息"),
    "ip_route": DiagnosticCommand("ip route show", "读取路由表"),
    "route": DiagnosticCommand("route -n", "读取兼容路由表"),
    "resolv": DiagnosticCommand("cat /etc/resolv.conf", "读取 DNS 配置"),
    "netstat": DiagnosticCommand("netstat -an", "读取网络连接状态"),
    "net_dev": DiagnosticCommand("cat /proc/net/dev", "读取网卡收发统计"),
    "dmesg": DiagnosticCommand("dmesg", "读取内核日志"),
    "logread": DiagnosticCommand("logread", "读取 BusyBox/OpenWrt 系统日志"),
    "var_log": DiagnosticCommand("ls -l /var/log", "查看日志目录"),
}


BASE_PROFILE = ["hostname", "uname", "uptime", "date", "id"]
PROFILE_COMMANDS: dict[str, list[str]] = {
    "system": ["proc_version", "loadavg", "cpuinfo"],
    "network": ["ip_addr", "ifconfig", "ip_route", "route", "resolv", "netstat", "net_dev"],
    "disk": ["df", "mount"],
    "memory": ["free", "meminfo"],
    "process": ["ps"],
    "logs": ["dmesg", "logread", "var_log"],
}

PROFILE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "system": ("系统", "版本", "内核", "负载", "状态", "system", "version", "kernel", "load"),
    "network": (
        "网络",
        "网口",
        "ip",
        "dns",
        "路由",
        "连接",
        "端口",
        "network",
        "route",
        "interface",
        "ping",
    ),
    "disk": ("磁盘", "空间", "挂载", "存储", "disk", "storage", "mount", "filesystem"),
    "memory": ("内存", "memory", "mem", "ram"),
    "process": ("进程", "服务", "process", "service", "daemon"),
    "logs": ("日志", "报错", "错误", "异常", "dmesg", "log", "error", "crash"),
}

DANGEROUS_PATTERN = re.compile(
    r"(^|\s)(rm|reboot|poweroff|halt|shutdown|mkfs|dd|mount\s+-o\s+remount|vi|vim|nano|sed\s+-i)\b|"
    r"(>|>>|\|\s*(sh|bash|ash)\b|;|&&|\|\||`|\$\()",
    re.IGNORECASE,
)

SENSITIVE_COMMAND_PATH_PATTERN = re.compile(
    r"(^|\s)(/etc/shadow|/etc/gshadow|/etc/sudoers|/proc/kcore)(\s|$)|"
    r"(^|\s)(/root/\.ssh|/home/[^/\s]+/\.ssh|/etc/ssh|/etc/ssl/private)(/|\s|$)",
    re.IGNORECASE,
)


def allowlist_path() -> Path:
    return app_home() / "allowlist.json"


def _load_allowlist_state(path: Path | None = None) -> dict:
    target = path or allowlist_path()
    if not target.exists():
        return {"custom": {}, "disabled_builtin_ids": []}
    raw = json.loads(target.read_text(encoding="utf-8"))
    raw.setdefault("custom", {})
    raw.setdefault("disabled_builtin_ids", [])
    return raw


def _save_allowlist_state(state: dict, path: Path | None = None) -> None:
    write_json_atomic(path or allowlist_path(), state)


def make_custom_command_id(command: str) -> str:
    digest = hashlib.sha256(command.strip().encode("utf-8")).hexdigest()[:16]
    return f"{CUSTOM_COMMAND_PREFIX}{digest}"


def normalize_command(command: str) -> str:
    return " ".join(command.strip().split())


def builtin_allowlist_commands(include_disabled: bool = True) -> list[AllowlistCommand]:
    state = _load_allowlist_state()
    disabled = set(state["disabled_builtin_ids"])
    entries: list[AllowlistCommand] = []
    for command_id, command in COMMAND_CATALOG.items():
        enabled = command_id not in disabled
        if include_disabled or enabled:
            entries.append(
                AllowlistCommand(
                    command_id=command_id,
                    command=command.command,
                    purpose=command.purpose,
                    source="builtin",
                    enabled=enabled,
                )
            )
    return entries


def custom_allowlist_commands(include_disabled: bool = True) -> list[AllowlistCommand]:
    state = _load_allowlist_state()
    entries: list[AllowlistCommand] = []
    for command_id, raw in sorted(state["custom"].items()):
        enabled = bool(raw.get("enabled", True))
        if include_disabled or enabled:
            entries.append(
                AllowlistCommand(
                    command_id=command_id,
                    command=raw["command"],
                    purpose=raw["purpose"],
                    source="custom",
                    enabled=enabled,
                )
            )
    return entries


def list_allowlist_commands(include_disabled: bool = True) -> list[AllowlistCommand]:
    return builtin_allowlist_commands(include_disabled=include_disabled) + custom_allowlist_commands(
        include_disabled=include_disabled
    )


def effective_command_catalog() -> dict[str, DiagnosticCommand]:
    return {
        entry.command_id: entry.to_diagnostic_command()
        for entry in list_allowlist_commands(include_disabled=False)
    }


def add_allowlist_commands(commands: list[dict[str, str]]) -> dict:
    if not commands:
        raise ValueError("commands is required")
    state = _load_allowlist_state()
    disabled = set(state["disabled_builtin_ids"])
    added: list[dict] = []
    reenabled: list[dict] = []
    unchanged: list[dict] = []

    builtin_by_command = {
        normalize_command(command.command): command_id
        for command_id, command in COMMAND_CATALOG.items()
    }
    custom_by_command = {
        normalize_command(raw["command"]): command_id
        for command_id, raw in state["custom"].items()
    }

    for item in commands:
        command = normalize_command(item.get("command", ""))
        purpose = item.get("purpose", "").strip() or "自定义只读诊断命令"
        validate_command_safety(command)

        builtin_id = builtin_by_command.get(command)
        if builtin_id:
            if builtin_id in disabled:
                disabled.remove(builtin_id)
                reenabled.append({"command_id": builtin_id, "command": command, "source": "builtin"})
            else:
                unchanged.append({"command_id": builtin_id, "command": command, "source": "builtin"})
            continue

        custom_id = custom_by_command.get(command) or make_custom_command_id(command)
        existing = state["custom"].get(custom_id)
        if existing and existing.get("enabled", True):
            unchanged.append({"command_id": custom_id, "command": command, "source": "custom"})
            continue

        state["custom"][custom_id] = {
            "command": command,
            "purpose": purpose,
            "enabled": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        added.append({"command_id": custom_id, "command": command, "source": "custom"})

    state["disabled_builtin_ids"] = sorted(disabled)
    _save_allowlist_state(state)
    return {"added": added, "reenabled": reenabled, "unchanged": unchanged}


def delete_allowlist_commands(
    command_ids: list[str] | None = None, commands: list[str] | None = None
) -> dict:
    identifiers = [value for value in (command_ids or []) if value]
    command_values = [normalize_command(value) for value in (commands or []) if value]
    if not identifiers and not command_values:
        raise ValueError("command_ids or commands is required")

    state = _load_allowlist_state()
    disabled = set(state["disabled_builtin_ids"])
    custom_by_command = {
        normalize_command(raw["command"]): command_id
        for command_id, raw in state["custom"].items()
    }
    builtin_by_command = {
        normalize_command(command.command): command_id
        for command_id, command in COMMAND_CATALOG.items()
    }
    identifiers.extend(custom_by_command[value] for value in command_values if value in custom_by_command)
    identifiers.extend(builtin_by_command[value] for value in command_values if value in builtin_by_command)

    deleted: list[dict] = []
    disabled_builtin: list[dict] = []
    not_found: list[str] = []
    for command_id in dedupe(identifiers):
        if command_id in state["custom"]:
            raw = state["custom"].pop(command_id)
            deleted.append({"command_id": command_id, "command": raw["command"], "source": "custom"})
        elif command_id in COMMAND_CATALOG:
            disabled.add(command_id)
            command = COMMAND_CATALOG[command_id]
            disabled_builtin.append(
                {"command_id": command_id, "command": command.command, "source": "builtin"}
            )
        else:
            not_found.append(command_id)

    state["disabled_builtin_ids"] = sorted(disabled)
    _save_allowlist_state(state)
    return {"deleted": deleted, "disabled_builtin": disabled_builtin, "not_found": not_found}


def validate_command_safety(command: str) -> None:
    if not command:
        raise ValueError("command is required")
    if "\x00" in command or "\n" in command or "\r" in command:
        raise ValueError("Command must be a single shell line.")
    if DANGEROUS_PATTERN.search(command):
        raise ValueError(f"Command is dangerous: {command}")
    if SENSITIVE_COMMAND_PATH_PATTERN.search(command):
        raise ValueError(f"Command reads a blocked sensitive path: {command}")


def select_profiles(task: str) -> list[str]:
    normalized = task.lower()
    selected: list[str] = []
    for profile, keywords in PROFILE_KEYWORDS.items():
        if any(keyword.lower() in normalized for keyword in keywords):
            selected.append(profile)
    if not selected:
        selected = ["system", "network", "disk", "logs"]
    return selected


def generate_plan(task: str, command_ids: list[str] | None = None) -> DiagnosticPlan:
    if not task or not task.strip():
        raise ValueError("task is required")
    catalog = effective_command_catalog()
    selected_ids = list(BASE_PROFILE)
    for profile in select_profiles(task):
        selected_ids.extend(PROFILE_COMMANDS[profile])
    if command_ids:
        missing = [command_id for command_id in command_ids if command_id not in catalog]
        if missing:
            raise ValueError(f"Unknown or disabled command_id values: {missing}")
        selected_ids.extend(command_ids)
    requested_ids = dedupe(selected_ids)
    commands = [catalog[command_id] for command_id in requested_ids if command_id in catalog]
    validate_commands(commands)
    command_hash = hash_commands(commands)
    return DiagnosticPlan(
        approval_id=str(uuid.uuid4()),
        task=task.strip(),
        created_at=datetime.now(timezone.utc).isoformat(),
        risk_level="low",
        risk_note="只读诊断命令；登录后会处于 root shell，但不会执行修改、重启或删除操作。",
        expected_reads=[command.purpose for command in commands],
        commands=commands,
        command_hash=command_hash,
    )


def dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def hash_commands(commands: list[DiagnosticCommand]) -> str:
    payload = json.dumps(
        [asdict(command) for command in commands],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate_commands(commands: list[DiagnosticCommand]) -> None:
    allowed = {command.command for command in effective_command_catalog().values()}
    for command in commands:
        validate_command_safety(command.command)
        if command.command not in allowed:
            raise ValueError(f"Command is not in allowlist: {command.command}")


def verify_plan_integrity(plan: DiagnosticPlan) -> None:
    validate_commands(plan.commands)
    actual = hash_commands(plan.commands)
    if actual != plan.command_hash:
        raise ValueError("Plan command hash mismatch; refusing to execute.")
    if plan.status != "planned":
        raise ValueError(f"Plan is not executable because status is {plan.status!r}.")


def truncate_output(value: str, limit: int = OUTPUT_LIMIT_CHARS) -> tuple[str, bool]:
    if len(value) <= limit:
        return value, False
    marker = f"\n\n[truncated to {limit} characters]\n"
    return value[:limit] + marker, True
