"""
┌─────────────────────────────────────────────────────────────────────┐
│  Module: tests.test_deploy_workflow_triggers                         │
│  Role: Guard cloud deployment workflows against automatic triggers.  │
│  模块职责：防止云部署工作流重新启用自动触发。                           │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


WORKFLOW_PATH = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "deploy-containerapp.yml"


def _workflow_events(workflow_text: str) -> set[str]:
    """Read top-level event names from a GitHub Actions workflow.

    This deliberately uses only the standard library so the guard also runs
    before repository-specific Python dependencies are installed.
    """
    lines = workflow_text.splitlines()
    try:
        on_index = next(index for index, line in enumerate(lines) if line.strip() == "on:")
    except StopIteration as error:
        raise AssertionError("workflow is missing the top-level 'on:' mapping") from error

    events: set[str] = set()
    for line in lines[on_index + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            break
        match = re.match(r"^  ([A-Za-z][A-Za-z0-9_-]*):(?:\s|$)", line)
        if match:
            events.add(match.group(1))
    return events


class ManualDeploymentTriggerTests(unittest.TestCase):
    """Keep cloud deployment entry points explicit."""

    def test_only_manual_dispatch_can_start_deployment(self) -> None:
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertEqual(_workflow_events(workflow_text), {"workflow_dispatch"})


if __name__ == "__main__":
    unittest.main()
