# Repository lifecycle / 仓库生命周期

Cyrene Exchange is a `PUBLIC_PRODUCT` source repository with `develop` as its
integration branch and `main` as its release branch. GitHub Actions is the
automatic source and contract CI authority. Its immutable component workflow
publishes artifacts from the exact source SHA on `develop`, `main`, or
`release`. The Azure Container Apps workflow consumes the successful component
release for that same SHA and deploys only the attested OCI digest. Manual
dispatch follows the same release lookup and verification rules.

Cyrene Exchange 是 `PUBLIC_PRODUCT` 源码仓库，以 `develop` 为集成分支、`main` 为
发布分支。GitHub Actions 是自动源码与契约 CI 权威；不可变组件 workflow 会为
`develop`、`main` 或 `release` 上的精确源码 SHA 发布产物。Azure Container Apps
workflow 只消费同一 SHA 对应的成功组件发布，并且只部署经过证明的 OCI digest。手动
触发也必须遵循相同的发布查找与验证规则。

## Ownership / 权威边界

Exchange owns gateway endpoints, routes, trusted credential mappings, request
audit, quota limits, request normalization, fallback, and response policy.
It does not own model execution, worker/process lifecycle, node hardware facts,
training, prompt-cache implementation, usage aggregation, or cost calculation.

Exchange 拥有 Gateway Endpoint、Route、可信凭据映射、请求审计、配额上限、请求
规范化、回退与响应策略；不拥有模型执行、Worker/进程生命周期、节点硬件事实、训练、
Prompt cache 实现、用量汇总或成本计算。

## Release truth / 发布真相

`repository-policy.yaml` keeps `automated_release: false` as the repository's
release-policy setting. The SHA-addressed component stream is separate: trusted
branch pushes can publish immutable component artifacts, while only `main` and
`release` use the stable channel and `develop` uses preview. A component release
does not by itself prove an Azure deployment. Deployment runs only after the
exact source-SHA index, manifest, and OCI digest pass verification; it updates
an existing app and never creates one. A conventional repository release is
not established until its accepted exact SHA is merged to `main`, hosted checks
execute successfully, artifacts are produced, and remote state is read back.
Local tests are reported separately.

`repository-policy.yaml` 保留 `automated_release: false` 作为仓库级发布策略设置。
按 SHA 寻址的组件流是独立机制：受信分支推送可以发布不可变组件产物；只有 `main` 和
`release` 使用 stable channel，`develop` 使用 preview。组件发布本身不能证明 Azure
部署成功。部署必须先验证精确源码 SHA 对应的 index、manifest 和 OCI digest；它只更新
已有应用，不会创建应用。常规仓库发布仍需等接受的精确 SHA 合入 `main`、Hosted
checks 实际执行成功、产物生成并完成远端 read-back 后才能确认；本地测试必须单独报告。

## Public dependency gate / 公开依赖门

Public source must be buildable without private tokens. The exact pinned
Plugins SDK revision must be publicly readable and license-designated before the
GitHub repository visibility is changed. The former repository and its complete
history are retained privately as `Cyrene-Exchange-history-archive`; this
canonical repository starts at a clean root and contains only the reviewed
candidate tree. The archive is not part of the publishable source and must
remain private.

The clean-root replacement was preceded by provenance and secret review of the
candidate tree. Downstream users must clone the canonical repository again;
old branches, pull-request refs, and commit IDs remain available only from the
private archive.

公开源码必须无需私有 token 即可构建。GitHub 可见性切换前，固定的 Plugins SDK
revision 必须可匿名读取且许可证映射明确。原仓库及其完整历史已作为
`Cyrene-Exchange-history-archive` 私有保留；当前 canonical 仓库从干净 root 开始，
只包含已审查的候选 tree，归档仓库不属于可公开源码且必须保持私有。

clean-root 替换前已对候选 tree 完成来源与 Secret 审查。下游使用者必须重新 clone
canonical 仓库；旧分支、Pull Request refs 与 commit ID 仅在私有归档仓库中保留。
