# Product runners / 产品运行入口

`run_product_vllm_smoke.py` composes generic Platform selection with a direct
Official Plugin model API endpoint. Optional draft-control mode adds the Product route
review/confirmation API, without automatically publishing a model route.

脚本复用 Platform 通用解析和 Plugins 直连 provider；草稿模式不自动启用路由。详细配置见上层指南。
---
<!-- Chinese Translation / 中文翻译 -->

## Product 运行脚本说明

`run_product_vllm_smoke.py` 将 Platform 通用选择与 Official Plugin 的直连模型 API 端点组合起来。可选草稿控制模式会增加 Product Route 的审核/确认 API，但不会自动发布模型 Route。
