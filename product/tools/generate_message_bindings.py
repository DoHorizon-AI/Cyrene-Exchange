"""Generate the checked-in consumer projection of Plugins message.connector.v1."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from importlib.metadata import version
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROTO_FILES = (
    "contracts/proto/cyrene/message/connector/v1/message_connector.proto",
    "contracts/proto/cyrene/tool/provider/v1/tool_provider.proto",
)
LOCK_PATH = REPOSITORY_ROOT / "product/contracts-message.lock.json"
OUTPUT_ROOT = REPOSITORY_ROOT / "product/src/cyrene_exchange_product/integrations/_generated"
PROTOC_VERSION = "1.62.3"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate(plugins_root: Path) -> None:
    """Check the canonical Plugins source and emit one typed consumer module."""

    if version("grpcio-tools") != PROTOC_VERSION:
        raise SystemExit(f"grpcio-tools=={PROTOC_VERSION} is required")
    root = plugins_root.resolve()
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    revision = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    expected = lock.get("protoSha256")
    if (
        lock.get("sourceRepository") != "DoHorizon-AI/Cyrene-Plugins-Official"
        or lock.get("sourceRevision") != revision
        or not isinstance(expected, dict)
        or any(expected.get(relative) != _sha256(root / relative) for relative in PROTO_FILES)
    ):
        raise SystemExit("Plugins message connector source does not match its consumer lock")
    package_root = OUTPUT_ROOT / "cyrene/message/connector/v1"
    package_root.mkdir(parents=True, exist_ok=True)
    tool_package_root = OUTPUT_ROOT / "cyrene/tool/provider/v1"
    tool_package_root.mkdir(parents=True, exist_ok=True)
    grpc_tools_proto = Path(__import__("grpc_tools").__file__).resolve().parent / "_proto"
    with tempfile.TemporaryDirectory(prefix="exchange-plugin-protos-") as temporary:
        output_root = Path(temporary)
        for relative, destination in zip(
            PROTO_FILES, (package_root, tool_package_root), strict=True
        ):
            source = root / relative
            # Plugins' generated modules use the proto basenames as descriptor
            # file names. Match those bytes so in-process integration tests and
            # shared hosts reuse the same protobuf descriptors without collisions.
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "grpc_tools.protoc",
                    f"-I{source.parent}",
                    f"-I{grpc_tools_proto}",
                    f"--python_out={output_root}",
                    source.name,
                ],
                check=True,
                cwd=source.parent,
            )
            generated = output_root / f"{source.stem}_pb2.py"
            shutil.copyfile(generated, destination / generated.name)
    for relative in (
        "cyrene",
        "cyrene/message",
        "cyrene/message/connector",
        "cyrene/message/connector/v1",
        "cyrene/tool",
        "cyrene/tool/provider",
        "cyrene/tool/provider/v1",
    ):
        (OUTPUT_ROOT / relative / "__init__.py").touch()
    actual = subprocess.run(
        [
            sys.executable,
            "-c",
            "import hashlib, json; "
            "from cyrene.message.connector.v1 import message_connector_pb2 as m; "
            "from cyrene.tool.provider.v1 import tool_provider_pb2 as t; "
            "print(json.dumps({'message': hashlib.sha256(m.DESCRIPTOR.serialized_pb).hexdigest(), "
            "'tool': hashlib.sha256(t.DESCRIPTOR.serialized_pb).hexdigest()}))",
        ],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(OUTPUT_ROOT)},
    ).stdout
    expected_descriptors = lock.get("descriptorSha256")
    if not isinstance(expected_descriptors, dict) or json.loads(actual) != expected_descriptors:
        raise SystemExit("generated Plugins protobuf descriptor does not match its consumer lock")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugins-root", type=Path, required=True)
    generate(parser.parse_args(argv).plugins_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
