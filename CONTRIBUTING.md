# Contributing to Cyrene Exchange / 参与贡献

Target normal feature work at `develop`; release promotion goes from `develop`
to protected `main`. Keep each change focused and include tests for behavior or
contract changes.

常规功能改动以 `develop` 为目标，发布再从 `develop` 提升到受保护的 `main`。
每次改动应保持单一目的，并为行为或契约变化补测试。

## Required checks / 必需检查

Run the root and Product commands documented in [README.md](README.md), then:

```bash
git diff --check
python -m json.tool service.json >/dev/null
```

Public contract changes must update `contracts/product/v1/`, `docs/API.md`, and
all call sites together. Do not add Product payload transport to Platform, copy
Plugin implementations into this repository, or reintroduce worker lifecycle,
training, custom-script, or hardware telemetry authority.

公共契约变化必须同步更新 `contracts/product/v1/`、`docs/API.md` 与全部调用点。
不得让 Platform 承载 Product 业务载荷，不得复制 Plugin 实现，也不得恢复 Worker
生命周期、训练、自定义脚本或硬件遥测权威。

Use synthetic credentials in tests. Never commit provider keys, bearer tokens,
private endpoints, model data, prompts, or response content.

测试只能使用虚构凭据；禁止提交 Provider key、Bearer token、私有 Endpoint、模型
数据、Prompt 或响应内容。
