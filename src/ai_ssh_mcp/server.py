from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from .config import DeviceConfig, load_config, save_config
from .credentials import CredentialStore
from .security import generate_plan, verify_plan_integrity
from .ssh_client import EmbeddedSSHSession
from .store import AuditStore, make_run_record


SERVER_NAME = "ai-ssh-device"


def configure_device(
    host: str,
    username: str,
    ssh_password: str,
    su_password: str,
    port: int = 22,
    connect_timeout: int = 15,
    command_timeout: int = 30,
    banner_timeout: int = 15,
    allow_unknown_host: bool = True,
) -> dict[str, Any]:
    config = DeviceConfig(
        host=host,
        username=username,
        port=port,
        connect_timeout=connect_timeout,
        command_timeout=command_timeout,
        banner_timeout=banner_timeout,
        allow_unknown_host=allow_unknown_host,
    )
    path = save_config(config)
    CredentialStore().set_device_secrets(config, ssh_password, su_password)
    public_config = asdict(config)
    public_config["config_path"] = str(path)
    return {
        "ok": True,
        "message": "Device configuration saved. Passwords were stored in the local keyring.",
        "device": public_config,
    }


def test_connection() -> dict[str, Any]:
    config = load_config()
    secrets = CredentialStore().get_device_secrets(config)
    with EmbeddedSSHSession(config, secrets) as session:
        result = session.test_connection()
    return asdict(result)


def plan_diagnostic_task(task: str) -> dict[str, Any]:
    plan = generate_plan(task)
    AuditStore().save_plan(plan)
    return plan.to_dict()


def run_approved_plan(approval_id: str, user_confirmed: bool = False) -> dict[str, Any]:
    if not user_confirmed:
        return {
            "ok": False,
            "status": "needs_user_confirmation",
            "message": "Show the plan to the user first, then call again with user_confirmed=true after they approve it in chat.",
        }

    store = AuditStore()
    plan = store.get_plan(approval_id)
    verify_plan_integrity(plan)
    config = load_config()
    secrets = CredentialStore().get_device_secrets(config)
    started_at = datetime.now(timezone.utc)

    store.mark_plan_status(approval_id, "running")
    try:
        with EmbeddedSSHSession(config, secrets) as session:
            results = session.run_commands(plan.commands)
        run = make_run_record(
            approval_id=approval_id,
            task=plan.task,
            started_at=started_at,
            results=results,
        )
        store.save_run(run)
        store.mark_plan_status(approval_id, "executed")
        return {"ok": True, "run": run.to_dict()}
    except Exception:
        store.mark_plan_status(approval_id, "failed")
        raise


def list_recent_runs(limit: int = 10) -> dict[str, Any]:
    return {"runs": AuditStore().list_recent_runs(limit=limit)}


def get_run_detail(run_id: str) -> dict[str, Any]:
    return {"run": AuditStore().get_run(run_id).to_dict()}


def build_mcp_server():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError(
            "mcp is not installed. Install project dependencies with `pip install -e .` first."
        ) from exc

    mcp = FastMCP(SERVER_NAME)
    mcp.tool()(configure_device)
    mcp.tool()(test_connection)
    mcp.tool()(plan_diagnostic_task)
    mcp.tool()(run_approved_plan)
    mcp.tool()(list_recent_runs)
    mcp.tool()(get_run_detail)
    return mcp


def main() -> None:
    build_mcp_server().run()

