# Product tests / 产品测试

Existing tests cover routing, tool protocol and request audit. `test_route_drafts`
checks that Send to remains unpublished until an authorized, version-matching
confirmation succeeds. Unit fixtures do not count as live model evidence.

已有路由、工具协议和请求审计测试继续执行；草稿测试仅证明产品状态与权限行为。
---
<!-- Chinese Translation / 中文翻译 -->

## Product 测试说明

现有测试覆盖路由、工具协议和请求审计。`test_route_drafts` 验证只有在获得授权且版本匹配的确认成功后，Send to 创建的 Route 才会发布。单元测试夹具不构成真实模型运行证据。
