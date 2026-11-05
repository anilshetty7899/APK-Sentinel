"""Shared helpers for durable per-analysis progress reporting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROGRESS_STEPS = [
    ("decode", "Decode APK and extract manifest, resources, and bytecode", 5),
    ("decompile", "Decompile APK bytecode", 65),
    ("metadata", "Read APK metadata and XML manifest", 69),
    ("permissions", "Analyze permissions and risky combinations", 73),
    ("components", "Inspect activities, services, receivers, and providers", 77),
    ("apis", "Scan code for sensitive APIs and behaviors", 81),
    ("network", "Extract URLs, domains, and IP addresses", 85),
    ("secrets", "Check for embedded secrets", 89),
    ("obfuscation", "Analyze code obfuscation", 92),
    ("certificate", "Inspect signing certificate", 95),
    ("score", "Calculate deterministic risk score", 98),
    ("report", "Generate analysis report", 100),
]


def task_statuses(percent: int) -> list[dict[str, str]]:
    """Return checklist state for each scan phase at a given percentage."""
    percent = max(0, min(100, int(percent)))
    tasks: list[dict[str, str]] = []
    previous_end = 0
    for task_id, label, end_at in PROGRESS_STEPS:
        if percent >= end_at:
            status = "completed"
        elif percent > previous_end or (percent == previous_end and percent > 0):
            status = "in_progress"
        else:
            status = "pending"
        tasks.append({"id": task_id, "label": label, "status": status})
        previous_end = end_at
    return tasks


def write_progress(workspace: Path, percent: int, stage: str) -> None:
    """Persist progress so the API can serve it while analysis is running."""
    workspace.mkdir(parents=True, exist_ok=True)
    progress_file = workspace / "progress.json"
    temporary_file = workspace / "progress.json.tmp"
    payload: dict[str, Any] = {
        "percent": max(0, min(100, int(percent))),
        "stage": stage,
        "tasks": task_statuses(percent),
    }
    temporary_file.write_text(json.dumps(payload))
    temporary_file.replace(progress_file)


def read_progress(workspace: Path) -> dict[str, Any] | None:
    """Read a progress snapshot; return None if it has not been written yet."""
    try:
        payload = json.loads((workspace / "progress.json").read_text())
        if not isinstance(payload, dict):
            return None
        return payload
    except (OSError, ValueError, TypeError):
        return None
