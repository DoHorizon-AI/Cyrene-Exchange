# Connector operation contract v1

The private Exchange connector facade accepts only the fixed provider operations
listed in its closed operation map. Provider input schemas are supplied by the
configured `tool.provider.v1` implementation through `list_tools`; Exchange
validates the schema and independently enforces the operation, mutability,
repository binding, resource projection, and argument limits. The facade does
not add a second provider execution contract.

Every GitHub invocation is bound to the current actor, organization, workspace,
connection, GitHub App profile, operation ID, resource reference, request ID,
and RFC 8785 digest of the complete arguments. Exchange verifies the short-lived
Directory grant, creates one Account Center credential lease for the same
profile/operation/resource/digest, then calls the fixed provider tool through
`tool.provider.v1`. The provider remains the owner of GitHub API behavior.

| Operation ID | Access | Target projection |
| --- | --- | --- |
| `github.issues.search` | Read | `repository_id`, `repository` |
| `github.actions.runs.list` | Read | `repository_id`, `repository` |
| `github.actions.jobs.list` | Read | `repository_id`, `repository`, `run_id` |
| `github.actions.job.logs.read` | Read | `repository_id`, `repository`, `run_id`, `job_id` |
| `github.branch.create` | Write | `repository_id`, `repository`, `branch` |
| `github.branch.delete` | Write | `repository_id`, `repository`, `branch` |
| `github.branch.get` | Read | `repository_id`, `repository`, `branch` |
| `github.file.commit` | Write | `repository_id`, `repository`, `branch`, `path` |
| `github.file.get` | Read | `repository_id`, `repository`, `branch`, `path` |
| `github.pull_request.draft.create` | Write | `repository_id`, `repository`, `head_branch`, `base_branch` |
| `github.pull_request.draft.find` | Read | `repository_id`, `repository`, `head_branch`, `base_branch` |
| `github.actions.rerun_failed` | Write | `repository_id`, `repository`, `run_id` |

The exact provider schema adds the operation arguments shown by the provider
catalog. Issue search requires a typed `state` and bounded `limit`; optional
plain-text query, up to ten unique labels, UTC `updated_since`, and page cursor
cannot inject GitHub search qualifiers. Search always binds the selected
repository and issue type. The result reports `complete`, `truncated`, and
`next_cursor` so a page cap is not mistaken for a full scan.
Workflow run and job lists also include `total_count`, `complete`, and `truncated`;
run metadata includes the workflow ID and head branch used to validate reruns.
Resource projections intentionally contain only stable locators. The complete
canonical argument digest also binds search filters, pagination limits,
source/head SHA preconditions, expected CI attempt, commit message, file content,
and pull request title/body. Each independent readback uses the same locator as
its paired write: branch get shares the branch target, file get shares the
branch/path target, and draft find shares the head/base target. A file upload is
limited to 500,000 decoded bytes; its content is not copied into the resource
target or durable receipt. A rerun uses the same `run_id` target as
`github.actions.jobs.list`, so an uncertain rerun can be reconciled through a
read of that run. Rerun also requires the expected workflow ID, an assistant
task branch, head SHA, and attempt. Before writing, the provider rereads the run
and checks those values against its repository-specific workflow allowlist.
Exchange never automatically repeats a write after an unknown outcome.

## Microsoft Graph delegated profiles

Microsoft Graph connections are bound to one actor-owned Account Center profile.
The profile's immutable `external_subject` is `<tenant_id>:<object_id>` and its
target scope contains only the tenant, selected Planner plan IDs, consented
Planner permissions, and an optional explicitly selected SharePoint site/list.
Exchange reads that profile under the verified actor before every operation,
requires the signed Entra issuer and object ID to match the Account Center
`external_subject` (`tid:oid`), and checks the fixed host plan allowlist. It
creates one Account Center lease bound to the operation, exact target tuple,
and target-excluded argument digest; the Directory grant still covers the full
tool payload. The lease response's `profile_scope_sha256` is included in the
signed provider envelope. Exchange never receives or stores a Graph access or
refresh token. The provider redeems
the one-use lease and uses that same delegated token for `/me`; it rejects the
call unless the returned identity matches the Account Center subject and the
signed `TrustedCallerContext`.

| Operation ID | Access | Target projection |
| --- | --- | --- |
| `microsoft_graph.planner.plan.get` | Read | `tenant_id`, `plan_id` |
| `microsoft_graph.planner.tasks.list` | Read | `tenant_id`, `plan_id` |
| `microsoft_graph.planner.task.get` | Read | `tenant_id`, `plan_id`, `task_id` |
| `microsoft_graph.planner.task.create` | Write | `tenant_id`, `plan_id`, `bucket_id` |
| `microsoft_graph.planner.task.update` | Write | `tenant_id`, `plan_id`, `task_id` |
| `microsoft_graph.sharepoint.site.get` | Read | `tenant_id`, `site_id` |
| `microsoft_graph.sharepoint.list.get` | Read | `tenant_id`, `site_id`, `list_id` |
| `microsoft_graph.sharepoint.list.items.delta` | Read | `tenant_id`, `site_id`, `list_id` |

Planner reads require the initial delegated `Tasks.Read` consent. `Tasks.ReadWrite`
is requested only by the explicit Planner-write consent action; until Account
Center reports that consent, task create/update operations are denied. SharePoint
operations remain absent until the host binding selects one exact site/list set
and the actor completes separate `Sites.Selected` consent. Tenant-wide task write, Mail, Calendar,
plan enumeration, arbitrary SharePoint fields, and arbitrary Graph URLs are not
part of this operation map. The provider constrains task updates to the fixed
field allowlist and requires the current eTag as `if_match`.

## Azure DevOps observation operations

Azure DevOps profiles use Entra delegated OAuth and remain actor owned. One
Account Center profile maps to exactly one host-authorized source tuple; Exchange
derives that tuple from `authorizedSources` and compares it with the signed actor,
connection alias, operation, and request arguments before requesting a one-use
lease. The public tool selector remains `{id,kind,bindingId}`. Account Center
binds the full tenant, organization, project, source, and configured pipeline or
release filters separately from the complete payload digest. The signed provider
envelope includes the returned `profile_scope_sha256`.

| Operation ID | Access | Fixed source kind and additional fields |
| --- | --- | --- |
| `azure_devops.observations.poll` | Read | `pipeline_runs` or `release_deployments`; bounded page/window fields |
| `azure_devops.pipelines.list` | Read | `project_pipelines`; bounded page fields |
| `azure_devops.pipeline_runs.list` | Read | `pipeline_runs`; bounded page/window fields |
| `azure_devops.pipeline_run.get` | Read | `pipeline_runs`; positive `runId` |
| `azure_devops.deployments.list` | Read | `release_deployments`; bounded page/window fields |
| `azure_devops.release_environment.get` | Read | `release_deployments`; positive `releaseId` and `environmentId` |

The provider reports authentication expiry, source scope denial, authorization
denial, invalid cursor, and authorization unavailability as separate outcomes.
An OAuth profile being healthy confirms its delegated token state; the Azure
DevOps API enforces the caller's actual project and resource rights on each read.

## Host computer runner operations

An optional host-owned `connectorHost.computerRunner` profile registers one
logical workspace and the fixed `computer-runtime` DirectPlugin binding. When
that profile is absent, Exchange does not export or accept computer operations.
The four tool schemas come from the actual Plugin `tool.provider.v1/list_tools`
catalog. Exchange validates a fresh Directory grant and the complete canonical
argument digest, then calls `tool.provider.v1/call_tool` over the configured
private mTLS connection. The Plugin receives only its declared tool arguments;
Exchange does not invent an Account Center account or forward a user's provider
credential to the local runner.

| Operation ID | Access | Target projection |
| --- | --- | --- |
| `computer.command.execute` | Write | `workspace_ref` equal to the host logical `connectionRef` |
| `computer.file.read` | Read | `workspace_ref`, `path` |
| `computer.file.write` | Write | `workspace_ref`, `path` |
| `computer.directory.list` | Read | `workspace_ref`, `path` |

`workspace_ref` is an opaque host UUID, not a filesystem path. File reads and
writes use the same workspace/path target, so an uncertain write can be inspected
without repeating it. Command execution is conservatively mutating because a
shell command may change files even when it exits with an error.

Commands are limited to 32 KiB of UTF-8 text and at most 600,000 ms, with each
stdout/stderr stream bounded to 64 KiB. File writes accept at most 1 MiB of
decoded content. File reads require an explicit chunk length capped at 64 KiB;
`offset` supports later chunks. Directory depth is capped at 32. Paths must stay
relative to the runner workspace and reject absolute paths, NUL, and `..`
segments. The runner validates the configured isolation root before accessing
files or starting a command. Exchange rejects any final structured result over
800,000 bytes, leaving room for the enclosing response to remain below its
1 MiB transport limit. An ambiguous command or file write keeps an unresolved
receipt; replaying the same request returns that receipt without another call.

## Connector 操作契约 v1

Exchange 私有 connector facade 只接受闭合操作表中列出的 Provider 操作。工具参数
JSON Schema 由配置好的 `tool.provider.v1` 实现通过 `list_tools` 提供；Exchange 会校验
该 Schema，并独立执行操作 ID、读写属性、仓库绑定、资源投影和参数长度限制。该 facade
不会另建一套 Provider 执行契约。

每次调用均绑定当前 actor、组织、workspace、connection、GitHub App profile、operation ID、
resource reference、request ID 以及完整参数的 RFC 8785 digest。Exchange 验证短时 Directory
grant，再为相同 profile、operation、resource 和 digest 向 Account Center 申请一次性凭据
lease，最后通过 `tool.provider.v1` 调用固定 Provider 工具。GitHub API 行为仍由 Provider
拥有。

| Operation ID | 权限 | 目标投影 |
| --- | --- | --- |
| `github.issues.search` | 读取 | `repository_id`、`repository` |
| `github.actions.runs.list` | 读取 | `repository_id`、`repository` |
| `github.actions.jobs.list` | 读取 | `repository_id`、`repository`、`run_id` |
| `github.actions.job.logs.read` | 读取 | `repository_id`、`repository`、`run_id`、`job_id` |
| `github.branch.create` | 写入 | `repository_id`、`repository`、`branch` |
| `github.branch.delete` | 写入 | `repository_id`、`repository`、`branch` |
| `github.branch.get` | 读取 | `repository_id`、`repository`、`branch` |
| `github.file.commit` | 写入 | `repository_id`、`repository`、`branch`、`path` |
| `github.file.get` | 读取 | `repository_id`、`repository`、`branch`、`path` |
| `github.pull_request.draft.create` | 写入 | `repository_id`、`repository`、`head_branch`、`base_branch` |
| `github.pull_request.draft.find` | 读取 | `repository_id`、`repository`、`head_branch`、`base_branch` |
| `github.actions.rerun_failed` | 写入 | `repository_id`、`repository`、`run_id` |

Provider catalog 中的精确 Schema 还会声明各操作参数。Issue 搜索要求结构化 `state` 和有界
`limit`；可选纯文本 query、最多十个不重复 labels、UTC `updated_since` 和页码 cursor 不会注入
GitHub 搜索 qualifier。搜索始终绑定已选择的仓库和 Issue 类型，结果会报告 `complete`、
`truncated` 与 `next_cursor`，避免把页数上限误当完整扫描。Workflow run 与 job 列表也包含
`total_count`、`complete` 和 `truncated`；run 元数据会带 workflow ID 与 head branch，供 rerun 前
做精确核对。资源投影只包含稳定资源定位符；完整参数 digest 同时绑定搜索筛选、分页数量、来源或 head SHA 前置条件、预期
CI attempt、提交说明、文件内容和 PR 标题/正文。每个独立回读都与对应写入使用相同 locator：
branch get 与 branch target 相同，file get 与 branch/path target 相同，draft find 与 head/base
target 相同。文件最大为解码后 500,000 字节；内容不会复制到资源 target 或持久回执中。CI rerun
与 `github.actions.jobs.list` 使用相同的 `run_id` target，因此结果不明时可以读取该 run 完成对账。
rerun 还要求预期 workflow ID、助手任务分支、head SHA 与 attempt；Provider 在写入前重新读取并核对
这些值，并且只对该仓库配置的 workflow ID 执行。Exchange 不会在结果未知时自动重发写入。

## Microsoft Graph delegated profiles

Microsoft Graph 连接固定到一个 actor-owned Account Center profile。不可变
`external_subject` 为 `<tenant_id>:<object_id>`；target scope 仅包含 tenant、选定 Planner plan ID、
已同意的 Planner 权限，以及可选的显式 SharePoint site/list。Exchange 会在每次操作前用已验证 actor
读取 profile，并要求签名 Entra issuer/object ID 与 Account Center `external_subject`（`tid:oid`）
一致，同时核对 host 固定的 plan allowlist。一次性 Account Center lease 绑定 operation、精确
target tuple 和去除 target ID 后的参数 digest；Directory grant 仍覆盖完整工具 payload。lease
响应的 `profile_scope_sha256` 会包含在 Provider 签名 envelope 中。
Exchange 不会接收或保存 Graph access/refresh token。Provider 兑换一次性 lease，并使用同一个委派 token
调用 `/me`；只有返回身份与 Account Center subject、签名 `TrustedCallerContext` 一致时才继续。

| Operation ID | 权限 | Target 投影 |
| --- | --- | --- |
| `microsoft_graph.planner.plan.get` | 读取 | `tenant_id`、`plan_id` |
| `microsoft_graph.planner.tasks.list` | 读取 | `tenant_id`、`plan_id` |
| `microsoft_graph.planner.task.get` | 读取 | `tenant_id`、`plan_id`、`task_id` |
| `microsoft_graph.planner.task.create` | 写入 | `tenant_id`、`plan_id`、`bucket_id` |
| `microsoft_graph.planner.task.update` | 写入 | `tenant_id`、`plan_id`、`task_id` |
| `microsoft_graph.sharepoint.site.get` | 读取 | `tenant_id`、`site_id` |
| `microsoft_graph.sharepoint.list.get` | 读取 | `tenant_id`、`site_id`、`list_id` |
| `microsoft_graph.sharepoint.list.items.delta` | 读取 | `tenant_id`、`site_id`、`list_id` |

Planner 读取要求初次委派 `Tasks.Read` consent。只有显式执行 Planner 写权限 consent action 时才申请
`Tasks.ReadWrite`；Account Center 确认前，create/update 均会拒绝。SharePoint 操作默认不可用；host binding
固定 site/list 且 actor 单独完成 `Sites.Selected` consent 后才开放。该操作表不包含 tenant-wide task write、Mail、
Calendar、plan 枚举、任意 SharePoint 字段或任意 Graph URL。Provider 将 task update 限制为固定字段，
并要求以当前 eTag 作为 `if_match` 前置条件。

## Azure DevOps observation 操作

Azure DevOps profile 使用 Entra 委派 OAuth，并始终为 actor-owned。每个 Account Center profile 只映射到
一个 host `authorizedSources` source tuple；Exchange 从该配置派生 tenant、organization、project、source
及 pipeline/release 过滤条件，并在申请一次性 lease 前核对签名 actor、connection alias、operation 和请求参数。
公开工具 target 固定为 `{id,kind,bindingId}`；完整 source tuple 与完整参数 digest 分别受 Account Center lease 绑定。
Provider 签名 envelope 包含返回的 `profile_scope_sha256`。

| Operation ID | 权限 | 固定 source kind 与附加字段 |
| --- | --- | --- |
| `azure_devops.observations.poll` | 读取 | `pipeline_runs` 或 `release_deployments`；分页与时间窗口字段 |
| `azure_devops.pipelines.list` | 读取 | `project_pipelines`；分页字段 |
| `azure_devops.pipeline_runs.list` | 读取 | `pipeline_runs`；分页与时间窗口字段 |
| `azure_devops.pipeline_run.get` | 读取 | `pipeline_runs`；正整数 `runId` |
| `azure_devops.deployments.list` | 读取 | `release_deployments`；分页与时间窗口字段 |
| `azure_devops.release_environment.get` | 读取 | `release_deployments`；正整数 `releaseId` 和 `environmentId` |

Provider 分别报告认证过期、source scope 拒绝、authorization 拒绝、无效 cursor 和授权服务不可用。
OAuth profile 健康只代表委派 token 状态；Azure DevOps API 会在每次读取时校验调用者实际具备的
project/resource 权限。

## Host computer runner 操作

可选的 Host `connectorHost.computerRunner` profile 注册一个逻辑 workspace 与固定的
`computer-runtime` DirectPlugin binding。profile 缺失时，Exchange 不导出也不接受 computer
操作。四个工具 Schema 来自实际 Plugin `tool.provider.v1/list_tools` catalog。Exchange 验证
新的 Directory grant 与完整 canonical 参数 digest，再通过已配置的私有 mTLS 连接调用
`tool.provider.v1/call_tool`。Plugin 只接收它声明的工具参数；Exchange 不伪造 Account Center
账号，也不把用户的 Provider 凭据传给本地 runner。

| Operation ID | 权限 | 目标投影 |
| --- | --- | --- |
| `computer.command.execute` | 写入 | `workspace_ref`，即 Host 逻辑 `connectionRef` |
| `computer.file.read` | 读取 | `workspace_ref`、`path` |
| `computer.file.write` | 写入 | `workspace_ref`、`path` |
| `computer.directory.list` | 读取 | `workspace_ref`、`path` |

`workspace_ref` 是不透明 Host UUID，不是文件系统路径。文件读写使用相同的 workspace/path
target，因此写入结果不确定时可以检查状态，不会重发原写入。Shell 命令保守地按写操作处理，
因为命令即使返回错误也可能已经改动文件。

Command 最多 32 KiB UTF-8 文本、最多运行 600,000 毫秒；stdout 与 stderr 各不超过 64 KiB。
文件写入解码后最多 1 MiB。文件读取必须指定分块长度，每次最多 64 KiB；`offset` 用于后续
读取。目录枚举深度最多 32。路径必须相对于 runner workspace，拒绝绝对路径、NUL 和 `..`
路径段。Runner 在访问文件或启动命令前会校验配置的隔离根目录。Exchange 拒绝最终结构化
结果超过 800,000 字节，给外层响应保留空间并将其控制在 1 MiB 传输限制内。命令或文件写入
结果有歧义时保留未解决回执；相同 request 重放只返回回执，不会再次调用。
