# Developer integration scripts / 开发集成脚本

[`run_canonical_vllm_smoke.py`](run_canonical_vllm_smoke.py) composes the real
Exchange HTTP transport, generic Platform resolver, and Plugins-owned direct
model API connector against an already running vLLM endpoint. It owns the
temporary Plugin process and cleans it up on exit.

该脚本把真实 Exchange HTTP、通用 Platform resolver 和 Plugins 直连 model API
connector 接到已经启动的 vLLM Endpoint。临时 Plugin 进程由脚本管理并在退出时清理。

Use `--tool-smoke` to require a function call and a subsequent tool-result model
turn. Use `--serve --listen-port 0 --ready-file <path>` for a long-running
gateway with an allocated loopback port; the readiness JSON contains no token.
Read the Exchange credential from `CYRENE_EXCHANGE_BEARER_TOKEN` and an optional
upstream credential from `CYRENE_VLLM_API_KEY`. The root [README](../README.md)
describes prerequisites and invocation examples.

`--tool-smoke` 要求真实 function call 及携带 tool result 的模型续答。
`--serve --listen-port 0 --ready-file <path>` 启动使用动态本地端口的长期网关；
readiness JSON 不包含 token。Exchange 凭据通过 `CYRENE_EXCHANGE_BEARER_TOKEN`
传入，上游凭据可通过 `CYRENE_VLLM_API_KEY` 传入。前置条件和示例见根目录
[README](../README.md)。

This is a protocol integration proof with a reference routing configuration.
It does not create a persisted Product Route, provision a Reactor Deployment,
or record an authoritative Usage/Cost/Audit ledger. Provider-reported usage is
forwarded as observed; missing usage is never estimated as a successful result.

这条验证路径使用 reference routing 配置，不会创建持久化 Product Route、
Reactor Deployment 或权威 Usage/Cost/Audit ledger。Provider usage 按实际观测透传；
缺失的 usage 不会被估算成成功结果。

`deploy_to_azure_containerapp.sh` creates or updates the Exchange Container App
with **internal** ingress. Existing apps are explicitly switched to internal
ingress after image update. An internal FQDN can only be health-checked from a
network that can reach the Container Apps environment; set
`AZURE_CONTAINERAPP_VERIFY_URL` to a runner-reachable private URL when needed.
If the runner cannot reach it, image/revision deployment continues and the
script reports that runtime health was not verified.

`deploy_to_azure_containerapp.sh` 会将 Exchange Container App 创建或更新为**内部**
Ingress；即使是已有应用，也会在镜像更新后显式切换为内部 Ingress。内部 FQDN 只能由
可访问 Container Apps 环境的网络执行健康检查；需要时通过
`AZURE_CONTAINERAPP_VERIFY_URL` 指定 runner 可访问的私网 URL。若 runner 无法连通，
镜像和 revision 部署仍会继续，脚本会明确报告 runtime health 未验证。
