# Connector operation contract v1

The private Exchange connector facade accepts only the fixed provider operations
listed in its closed operation map. Provider input schemas are supplied by the
configured `tool.provider.v1` implementation through `list_tools`; Exchange
validates the schema and independently enforces the operation, mutability,
repository binding, resource projection, and argument limits. The facade does
not add a second provider execution contract.

Every invocation is bound to the current actor, organization, workspace,
connection, GitHub App profile, operation ID, resource reference, request ID,
and RFC 8785 digest of the complete arguments. Exchange verifies the short-lived
Directory grant, creates one Account Center credential lease for the same
profile/operation/resource/digest, then calls the fixed provider tool through
`tool.provider.v1`. The provider remains the owner of GitHub API behavior.

| Operation ID | Access | Target projection |
| --- | --- | --- |
| `github.issues.search` | Read | `repository_id`, `repository` |
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
Resource projections intentionally contain only stable locators. The complete
canonical argument digest also binds search filters, pagination limits,
source/head SHA preconditions, expected CI attempt, commit message, file content,
and pull request title/body. Each independent readback uses the same locator as
its paired write: branch get shares the branch target, file get shares the
branch/path target, and draft find shares the head/base target. A file upload is
limited to 500,000 decoded bytes; its content is not copied into the resource
target or durable receipt. A rerun uses the same `run_id` target as
`github.actions.jobs.list`, so an uncertain rerun can be reconciled through a
read of that run. Exchange never automatically repeats a write after an unknown
outcome.

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
`truncated` 与 `next_cursor`，避免把页数上限误当完整扫描。资源投影只包含
稳定资源定位符；完整参数 digest 同时绑定搜索筛选、分页数量、来源或 head SHA 前置条件、预期
CI attempt、提交说明、文件内容和 PR 标题/正文。每个独立回读都与对应写入使用相同 locator：
branch get 与 branch target 相同，file get 与 branch/path target 相同，draft find 与 head/base
target 相同。文件最大为解码后 500,000 字节；内容不会复制到资源 target 或持久回执中。CI rerun
与 `github.actions.jobs.list` 使用相同的 `run_id` target，因此结果不明时可以读取该 run 完成对账。
Exchange 不会在结果未知时自动重发写入。
