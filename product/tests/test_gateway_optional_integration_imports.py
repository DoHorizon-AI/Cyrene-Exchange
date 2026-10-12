"""Gateway-only imports do not require the optional integration SDK."""

from __future__ import annotations

import subprocess
import sys


def test_gateway_imports_succeed_when_account_center_sdk_is_unavailable() -> None:
    program = """
import importlib.abc
import sys

class DenyAccountCenterSdk(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "cyrene_account_center_contracts" or fullname.startswith(
            "cyrene_account_center_contracts."
        ):
            raise ModuleNotFoundError(fullname)

sys.meta_path.insert(0, DenyAccountCenterSdk())
import cyrene_exchange_product.api
import cyrene_exchange_product.cli
"""
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
