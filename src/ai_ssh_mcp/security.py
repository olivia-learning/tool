from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable


OUTPUT_LIMIT_CHARS = 12000


@dataclass(frozen=True)
class DiagnosticCommand:
    command: str
    purpose: str


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
    r"(>|>>|\|\s*(sh|bash|ash)\b|;\s*(rm|reboot|poweroff|halt|shutdown)\b)",
    re.IGNORECASE,
)


def select_profiles(task: str) -> list[str]:
    normalized = task.lower()
    selected: list[str] = []
    for profile, keywords in PROFILE_KEYWORDS.items():
        if any(keyword.lower() in normalized for keyword in keywords):
            selected.append(profile)
    if not selected:
        selected = ["system", "network", "disk", "logs"]
    return selected


def generate_plan(task: str) -> DiagnosticPlan:
    if not task or not task.strip():
        raise ValueError("task is required")
    command_ids = list(BASE_PROFILE)
    for profile in select_profiles(task):
        command_ids.extend(PROFILE_COMMANDS[profile])
    commands = [COMMAND_CATALOG[command_id] for command_id in dedupe(command_ids)]
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
    allowed = {command.command for command in COMMAND_CATALOG.values()}
    for command in commands:
        if command.command not in allowed:
            raise ValueError(f"Command is not in allowlist: {command.command}")
        if DANGEROUS_PATTERN.search(command.command):
            raise ValueError(f"Command is dangerous: {command.command}")


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

