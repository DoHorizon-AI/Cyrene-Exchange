# Third-party notices / 第三方声明

Cyrene Exchange source is licensed under Apache License 2.0; see `LICENSE`.
Third-party packages retain their own licenses. No third-party source is copied
into this repository. Exact resolved versions are recorded in `uv.lock` and
`product/uv.lock`.

Cyrene Exchange 源码采用 Apache License 2.0，见 `LICENSE`。第三方包保留各自许可；
本仓库不复制第三方源码。精确解析版本记录在 `uv.lock` 与 `product/uv.lock`。

## Direct runtime and build dependencies / 直接运行与构建依赖

| Package | Declared or upstream license | Use |
| --- | --- | --- |
| `cyrene-model-provider-contracts` | Must be designated by the Plugins repository license map before publication | Typed `model.provider.v1` contract |
| `cyrene-plugin-runtime` | Must be designated by the Plugins repository license map before publication | Direct endpoint transport; itself depends on gRPC and Protobuf |
| gRPC Python (`grpcio`) | Apache-2.0 | Transitive direct-endpoint transport runtime |
| Protocol Buffers (`protobuf`) | BSD-3-Clause | Transitive typed payload codec |
| FastAPI | MIT | Product control and audit HTTP APIs |
| Pydantic | MIT | Product wire models and validation |
| Uvicorn | BSD-3-Clause | Optional Product API serving |
| HTTPX | BSD-3-Clause | Product tests and HTTP integration |
| Setuptools | MIT | Root package build backend |
| Hatchling | MIT | Product package build backend |

## Development and validation dependencies / 开发与验证依赖

| Package | License | Use |
| --- | --- | --- |
| pytest | MIT | Tests |
| Ruff | MIT | Lint and formatting |
| mypy | MIT | Static typing |
| jsonschema | MIT | Contract validation |
| openapi-spec-validator | Apache-2.0 | OpenAPI validation |

This table is a human-readable direct-dependency summary, not a substitute for
the complete resolved graph. Generate reviewable manifests for a release from a
clean checkout with:

```bash
uv export --frozen --all-extras --format requirements-txt > exchange-requirements.txt
uv export --directory product --frozen --group dev --format requirements-txt > product-requirements.txt
```

Review the generated transitive package list and each upstream license before
attaching it to a release. Generated files are release evidence and are not
committed unless the release process chooses to retain them.

本表只概述直接依赖，不能替代完整解析图。发布时应从干净 checkout 生成清单，审查
全部传递依赖及其上游许可证后再随发布物归档；除非发布流程决定保留，否则生成文件
不提交到源码仓库。
