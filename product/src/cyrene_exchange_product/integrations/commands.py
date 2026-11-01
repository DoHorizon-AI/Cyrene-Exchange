"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 commands.py                                                     │
│  Module: cyrene_exchange_product.integrations.commands               │
│  Role: Parse the fixed, bounded /issue command grammar.               │
│                                                                      │
│  模块职责：解析固定的 /issue 命令，不调用模型或外部解释器。              │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from cyrene_exchange_product.integrations.models import (
    IntegrationValidationError,
    JobState,
    Operation,
)

MAX_COMMAND_LENGTH = 4096
_ISSUE_NUMBER = re.compile(r"^#?([1-9][0-9]{0,8})$")


@dataclass(frozen=True, slots=True)
class ParsedIssueCommand:
    """A syntactically validated fixed operation and bounded arguments."""

    operation_id: str
    issue_number: int
    body: str | None = None


def parse_issue_command(command: str) -> ParsedIssueCommand:
    """Parse `/issue query|comment|close|reopen` without invoking an LLM.

    Supported forms are `/issue query 12`, `/issue comment 12 text`,
    `/issue close 12`, and `/issue reopen 12`.
    中文：仅接受固定语法，不执行自由文本规划。
    """

    if not isinstance(command, str) or not command.strip():
        raise IntegrationValidationError("command must be non-empty text")
    if len(command) > MAX_COMMAND_LENGTH:
        raise IntegrationValidationError("command exceeds the size limit")
    try:
        parts = shlex.split(command, posix=True)
    except ValueError as exc:
        raise IntegrationValidationError("command quoting is invalid") from exc
    if len(parts) < 3 or parts[0] != "/issue":
        raise IntegrationValidationError("command must use /issue <action> <number>")

    action = parts[1].lower()
    number_match = _ISSUE_NUMBER.fullmatch(parts[2])
    if number_match is None:
        raise IntegrationValidationError("issue number is invalid")
    issue_number = int(number_match.group(1))
    if action == "comment":
        body = " ".join(parts[3:]).strip()
        if not body or len(body) > 4000:
            raise IntegrationValidationError("comment body must contain 1 to 4000 characters")
        operation_id = "integration.issue.comment"
        return ParsedIssueCommand(operation_id, issue_number, body)
    if len(parts) != 3:
        raise IntegrationValidationError("this issue action does not accept extra arguments")
    operation_ids = {
        "query": "integration.issue.query",
        "close": "integration.issue.close",
        "reopen": "integration.issue.reopen",
    }
    try:
        operation_id = operation_ids[action]
    except KeyError as exc:
        raise IntegrationValidationError("unsupported issue action") from exc
    return ParsedIssueCommand(operation_id, issue_number)


def render_issue_command_result(
    operation: Operation,
    *,
    repository_name: str,
    state: JobState,
    evidence: dict[str, object],
) -> str:
    """Render a bounded deterministic reply from explicit provider evidence."""

    issue = f"{repository_name}#{operation.issue_number}"
    if state == JobState.UNKNOWN:
        return f"The result for {issue} is unknown. No automatic retry was made."
    if state == JobState.FAILED:
        return f"The requested operation for {issue} did not complete."
    if state == JobState.ACCEPTED:
        return f"The requested operation for {issue} was accepted; completion is unconfirmed."
    if operation.operation_id == "integration.issue.query":
        title = str(evidence.get("title", ""))[:500]
        issue_state = str(evidence.get("state", "unknown"))[:40]
        return f"{issue} is {issue_state}: {title}"[:1500]
    if operation.operation_id == "integration.issue.comment":
        return f"Comment on {issue} was confirmed."
    new_state = str(evidence.get("state", "confirmed"))[:40]
    return f"{issue} state change was confirmed: {new_state}."
