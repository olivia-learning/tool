from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import state_path, write_json_atomic
from .security import DiagnosticPlan


@dataclass(frozen=True)
class CommandResult:
    command: str
    purpose: str
    stdout: str
    stderr: str
    exit_status: int
    duration_ms: int
    truncated: bool = False


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    approval_id: str
    task: str
    started_at: str
    finished_at: str
    success: bool
    summary: str
    results: list[CommandResult]

    def to_dict(self) -> dict:
        data = asdict(self)
        data["results"] = [asdict(result) for result in self.results]
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "RunRecord":
        return cls(
            run_id=data["run_id"],
            approval_id=data["approval_id"],
            task=data["task"],
            started_at=data["started_at"],
            finished_at=data["finished_at"],
            success=bool(data["success"]),
            summary=data["summary"],
            results=[CommandResult(**item) for item in data["results"]],
        )


class AuditStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or state_path()

    def save_plan(self, plan: DiagnosticPlan) -> None:
        state = self._load()
        state["plans"][plan.approval_id] = plan.to_dict()
        self._save(state)

    def get_plan(self, approval_id: str) -> DiagnosticPlan:
        state = self._load()
        try:
            raw = state["plans"][approval_id]
        except KeyError as exc:
            raise KeyError(f"Unknown approval_id: {approval_id}") from exc
        return DiagnosticPlan.from_dict(raw)

    def mark_plan_status(self, approval_id: str, status: str) -> None:
        state = self._load()
        if approval_id not in state["plans"]:
            raise KeyError(f"Unknown approval_id: {approval_id}")
        state["plans"][approval_id]["status"] = status
        self._save(state)

    def save_run(self, run: RunRecord) -> None:
        state = self._load()
        state["runs"].append(run.to_dict())
        state["runs"] = state["runs"][-100:]
        self._save(state)

    def list_recent_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        state = self._load()
        runs = state["runs"][-max(1, limit) :]
        return [
            {
                "run_id": run["run_id"],
                "approval_id": run["approval_id"],
                "task": run["task"],
                "finished_at": run["finished_at"],
                "success": run["success"],
                "summary": run["summary"],
            }
            for run in reversed(runs)
        ]

    def get_run(self, run_id: str) -> RunRecord:
        state = self._load()
        for raw in state["runs"]:
            if raw["run_id"] == run_id:
                return RunRecord.from_dict(raw)
        raise KeyError(f"Unknown run_id: {run_id}")

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"plans": {}, "runs": []}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        raw.setdefault("plans", {})
        raw.setdefault("runs", [])
        return raw

    def _save(self, state: dict[str, Any]) -> None:
        write_json_atomic(self.path, state)


def make_run_record(
    approval_id: str,
    task: str,
    started_at: datetime,
    results: list[CommandResult],
) -> RunRecord:
    finished_at = datetime.now(timezone.utc)
    failures = [result for result in results if result.exit_status != 0]
    success = not failures
    summary = (
        f"Executed {len(results)} diagnostic commands successfully."
        if success
        else f"Executed {len(results)} diagnostic commands; {len(failures)} returned non-zero exit status."
    )
    return RunRecord(
        run_id=str(uuid.uuid4()),
        approval_id=approval_id,
        task=task,
        started_at=started_at.isoformat(),
        finished_at=finished_at.isoformat(),
        success=success,
        summary=summary,
        results=results,
    )

