# Microsoft Account Center lease spine / Microsoft 账号中心租约链路

This opt-in local gate runs the current Exchange Product dispatcher through the
Microsoft Graph and Azure DevOps provider plugin entrypoints into the real local
Account Center plugin. It verifies one-use lease consumption, exact target and
argument digests, signed Entra actor binding, Graph profile-scope digests, and
ADO unlink revocation.

该本地可选门禁会通过当前 Exchange Product dispatcher、Microsoft Graph 与 Azure DevOps
provider 插件入口，调用真实本地 Account Center 插件。测试验证一次性租约消费、精确目标和
参数摘要、签名 Entra actor 绑定、Graph profile scope 摘要，以及 ADO 解除绑定后的撤销。

The test is `product/tests/test_microsoft_auth_lease_spine.py`. It needs a sibling
Plugins checkout containing the Account Center, provider packages, plugin runtime,
and shared Python contracts. From the Exchange Product directory, run:

测试文件是 `product/tests/test_microsoft_auth_lease_spine.py`。需要同级 Plugins checkout，包含
Account Center、provider packages、plugin runtime 和共享 Python contracts。在 Exchange Product
目录执行：

```bash
export CYRENE_PLUGINS_ROOT=/path/to/Cyrene-Plugins-Official
export PYTHONPATH="../src:src:$CYRENE_PLUGINS_ROOT/sdk/python/cyrene_account_center_contracts/src:$CYRENE_PLUGINS_ROOT/sdk/python/cyrene_plugin_runtime/src:$CYRENE_PLUGINS_ROOT/plugins/accounts/account-center/src:$CYRENE_PLUGINS_ROOT/plugins/providers/microsoft-graph/src:$CYRENE_PLUGINS_ROOT/plugins/providers/azure-devops-observation/src"
uv run --frozen --group dev pytest -o addopts='' -q tests/test_microsoft_auth_lease_spine.py
```

The gate uses synthetic OAuth identities, bearer values, and HTTP responses. It
does not contact Microsoft, exercise a tenant consent screen, prove real provider
permissions, or replace hosted CI. Its Directory grant claims are local fixtures;
the tested path begins at Exchange's real connector-operation dispatcher.

CI must set `CYRENE_AUTH_SPINE_REQUIRED=1`, check out Plugins at the pinned commit,
and set both `CYRENE_PLUGINS_ROOT` and `CYRENE_PLUGINS_SHA`. The test compares the
checkout's `HEAD` with that SHA and fails instead of skipping when the required
source or pin is missing.

该门禁使用合成 OAuth identity、bearer 值与 HTTP 响应；不会连接 Microsoft、打开 tenant consent
页面或证明真实 provider permissions，也不能替代 Hosted CI。Directory grant claims 是本地 fixture；
覆盖路径从 Exchange 的真实 connector-operation dispatcher 开始。

CI 必须设置 `CYRENE_AUTH_SPINE_REQUIRED=1`，按固定 commit checkout Plugins，并提供
`CYRENE_PLUGINS_ROOT` 与 `CYRENE_PLUGINS_SHA`。测试会校验 checkout 的 `HEAD` 与该 SHA 一致；缺少
要求的源代码或 pin 时会失败，不会跳过。
