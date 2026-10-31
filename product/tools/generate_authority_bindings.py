"""Generate the pinned Platform Authority v2 Python gRPC consumer bindings.

Run with uv and grpcio-tools 1.62.3, passing the exact Platform checkout.
The script checks source digests before invoking protoc and rewrites imports
only to place generated modules beneath the Exchange-owned package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PRODUCT_PROTO = "contracts/proto/cyrene/workspace/product/v2/product_api.proto"
AUTHORITY_PROTO = "contracts/proto/cyrene/workspace/authority/v2/workspace_authority.proto"
PROTO_FILES = (AUTHORITY_PROTO, PRODUCT_PROTO)
LOCK_PATH = REPOSITORY_ROOT / "product/contracts-authority.lock.json"
OUTPUT_ROOT = REPOSITORY_ROOT / "product/src/cyrene_exchange_product/integrations/_generated"
PROTOC_VERSION = "1.62.3"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_lock() -> dict[str, object]:
    value = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit("authority binding lock must be a JSON object")
    return value


def _resolve_proto_root(platform_root: Path) -> Path:
    root = platform_root.resolve()
    proto_root = root / "contracts/proto"
    if not proto_root.is_dir():
        raise SystemExit("Platform root has no contracts/proto directory")
    return proto_root


def _verify_lock(platform_root: Path, proto_root: Path, lock: dict[str, object]) -> None:
    pinned_revision = lock.get("sourceRevision")
    source_repo = lock.get("sourceRepository")
    if source_repo != "DoHorizon-AI/Cyrene-Platform" or not isinstance(pinned_revision, str):
        raise SystemExit("authority binding lock has no canonical Platform revision")
    completed = subprocess.run(
        ["git", "-C", str(platform_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    if completed.stdout.strip() != pinned_revision:
        raise SystemExit("Platform checkout revision does not match contracts-authority.lock.json")
    expected_files = lock.get("protoSha256")
    if not isinstance(expected_files, dict):
        raise SystemExit("authority binding lock has no protoSha256 map")
    for relative in PROTO_FILES:
        path = proto_root / relative.removeprefix("contracts/proto/")
        expected = expected_files.get(relative)
        if not isinstance(expected, str) or _sha256(path) != expected:
            raise SystemExit(f"Platform proto digest mismatch: {relative}")


def _rewrite_imports(path: Path) -> None:
    """Place protoc imports beneath the private Product generated package."""

    content = path.read_text(encoding="utf-8")
    product_module = (
        "from cyrene_exchange_product.integrations._generated.cyrene.workspace.product.v2 "
        "import product_api_pb2 as"
    )
    authority_module = (
        "from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 "
        "import workspace_authority_pb2 as"
    )
    content = re.sub(
        r"from cyrene\.workspace\.product\.v2 import product_api_pb2 as",
        product_module,
        content,
    )
    content = re.sub(
        r"from cyrene\.workspace\.authority\.v2 import workspace_authority_pb2 as",
        authority_module,
        content,
    )
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def generate(platform_root: Path) -> None:
    """Generate exact proto consumers after checking pinned source and compiler."""

    if version("grpcio-tools") != PROTOC_VERSION:
        raise SystemExit(f"grpcio-tools=={PROTOC_VERSION} is required")
    proto_root = _resolve_proto_root(platform_root)
    _verify_lock(platform_root.resolve(), proto_root, _load_lock())
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    grpc_tools_proto = Path(__import__("grpc_tools").__file__).resolve().parent / "_proto"
    command = [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"-I{proto_root}",
        f"-I{grpc_tools_proto}",
        f"--python_out={OUTPUT_ROOT}",
        f"--grpc_python_out={OUTPUT_ROOT}",
        *(str(proto_root / relative.removeprefix("contracts/proto/")) for relative in PROTO_FILES),
    ]
    subprocess.run(command, check=True)
    generated = (
        "cyrene/workspace/authority/v2/workspace_authority_pb2.py",
        "cyrene/workspace/authority/v2/workspace_authority_pb2_grpc.py",
        "cyrene/workspace/product/v2/product_api_pb2.py",
        "cyrene/workspace/product/v2/product_api_pb2_grpc.py",
    )
    for relative in generated:
        _rewrite_imports(OUTPUT_ROOT / relative)
    for relative in (
        "cyrene",
        "cyrene/workspace",
        "cyrene/workspace/authority",
        "cyrene/workspace/authority/v2",
        "cyrene/workspace/product",
        "cyrene/workspace/product/v2",
    ):
        (OUTPUT_ROOT / relative / "__init__.py").touch()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    generate(arguments.platform_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
