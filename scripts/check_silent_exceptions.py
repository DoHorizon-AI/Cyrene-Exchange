"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 check_silent_exceptions.py                                       │
│  Module: scripts.check_silent_exceptions                             │
│  Role: Enforce explicit review of silent exception fallbacks.        │
│                                                                     │
│  模块职责：检查静默异常回退是否附有明确的允许理由。                      │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import ast
import io
import subprocess
import sys
import tokenize
from pathlib import Path

_ALLOW_PREFIX = "# diagnostic-allow: "


def find_unreviewed(source: str) -> list[tuple[int, str]]:
    """Find exception handlers that silently discard an error without a reason.

    找出没有明确理由的静默异常处理路径。
    """
    tree = ast.parse(source)
    comments = {
        token.start[0]: token.string.strip()
        for token in tokenize.generate_tokens(io.StringIO(source).readline)
        if token.type == tokenize.COMMENT
    }
    unreviewed: list[tuple[int, str]] = []
    for handler in ast.walk(tree):
        if not isinstance(handler, ast.ExceptHandler) or len(handler.body) != 1:
            continue
        statement = handler.body[0]
        if isinstance(statement, ast.Pass):
            kind = "pass"
        elif isinstance(statement, ast.Return) and (
            statement.value is None
            or (isinstance(statement.value, ast.Constant) and statement.value.value is None)
        ):
            kind = "return None"
        else:
            continue
        comment = comments.get(statement.lineno, "")
        reason = (
            comment.removeprefix(_ALLOW_PREFIX).strip() if comment.startswith(_ALLOW_PREFIX) else ""
        )
        if len(reason) < 12:
            unreviewed.append((statement.lineno, kind))
    return unreviewed


def _self_check() -> None:
    unreviewed = "try:\n    parse()\nexcept ValueError:\n    return None\n"
    reviewed = (
        "try:\n    parse()\nexcept ValueError:\n"
        "    return None  # diagnostic-allow: malformed optional field\n"
    )
    if find_unreviewed(unreviewed) != [(4, "return None")]:
        raise RuntimeError("silent return gate did not reject an unreviewed fallback")
    if find_unreviewed(reviewed):
        raise RuntimeError("silent return gate rejected a documented fallback")
    if find_unreviewed("try:\n    parse()\nexcept ValueError:\n    pass\n") != [(4, "pass")]:
        raise RuntimeError("silent pass gate did not reject an unreviewed fallback")


def main() -> int:
    """Check tracked production Python files and report exact offending lines.

    检查已跟踪的生产 Python 文件并报告违规行。
    """
    _self_check()
    root = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
    tracked = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "-z", "--", "*.py"]
    ).split(b"\0")
    failures: list[str] = []
    for raw_path in tracked:
        if not raw_path:
            continue
        relative = Path(raw_path.decode("utf-8"))
        if "tests" in relative.parts or relative.name.startswith("test_"):
            continue
        path = root / relative
        for line, kind in find_unreviewed(path.read_text(encoding="utf-8")):
            failures.append(
                f"{relative}:{line}: silent except {kind}; log it or add {_ALLOW_PREFIX}<reason>"
            )
    for failure in failures:
        print(failure, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
