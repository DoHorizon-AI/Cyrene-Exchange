# Product runners / 产品运行入口

`run_product_vllm_smoke.py` composes generic Platform selection with a direct
Official Plugin model API endpoint. Optional draft-control mode adds the Product route
review/confirmation API, without automatically publishing a model route.

脚本复用 Platform 通用解析和 Plugins 直连 provider；草稿模式不自动启用路由。详细配置见上层指南。
