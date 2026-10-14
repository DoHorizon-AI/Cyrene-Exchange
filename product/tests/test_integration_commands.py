"""Fixed command grammar tests. | 固定命令语法测试。"""

import pytest

from cyrene_exchange_product.integrations.commands import parse_issue_command
from cyrene_exchange_product.integrations.models import IntegrationValidationError


@pytest.mark.parametrize(
    ("raw", "operation_id", "issue_number", "body"),
    [
        ("/issue query #12", "integration.issue.query", 12, None),
        (
            "/issue comment 12 please investigate",
            "integration.issue.comment",
            12,
            "please investigate",
        ),
        ("/issue close 12", "integration.issue.close", 12, None),
        ("/issue reopen 12", "integration.issue.reopen", 12, None),
    ],
)
def test_fixed_issue_commands_parse_to_exact_operation(
    raw, operation_id, issue_number, body
) -> None:
    parsed = parse_issue_command(raw)
    assert parsed.operation_id == operation_id
    assert parsed.issue_number == issue_number
    assert parsed.body == body


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "/issue delete 12",
        "/issue close 0",
        "/issue close 12 extra",
        "/issue comment 12",
        "/issue comment 12 " + ("x" * 4001),
        "/issue query 12; /issue close 13",
        "/issue query 9999999999",
    ],
)
def test_unsupported_or_unbounded_commands_fail_closed(raw: str) -> None:
    with pytest.raises(IntegrationValidationError):
        parse_issue_command(raw)
