# Huawei Cloud TEE Wallet Core v1 计划

## Summary

第一阶段不再做 `AWS Nitro -> QingTian` 的云密钥链路平移，而是直接验证一个最小但完整的钱包内核：

- 私钥在 TEE 内生成，只保存在 enclave 进程内存
- 宿主机仅保留一个本地 HTTP gateway 和一个 TEE IPC bridge
- 对外暴露最小钱包能力：`create_wallet`、`get_address`、`sign_transaction`、`get_attestation`
- 第二阶段 TODO 明确写入根 README：把内存态密钥替换成外部存储/可恢复存储

## Key Changes

### 1. 架构收缩

- 删除第一阶段对 `KMS/CSMS/metadata credential/function trigger` 的依赖，不再把它们当作核心交付物
- 保留一个极薄的宿主机服务，只做 HTTP 请求解析、TEE 转发、结果返回、health/attestation 暴露
- 把 `application/eth1/enclave/server.py` 重构成真正的钱包内核，而不是“解密后签名”的一段处理器
- `AF_VSOCK` 继续保留为默认 TEE IPC，除非华为云当前环境里有更直接且更简单的本地 enclave 通道

### 2. 钱包内核接口

第一阶段 TEE 内核固定提供 4 个命令/接口：

- `create_wallet`
  在 TEE 内生成 secp256k1 私钥，分配 `wallet_id`，返回 `wallet_id + address`
- `get_address`
  输入 `wallet_id`，返回地址；若不存在返回明确错误
- `sign_transaction`
  输入 `wallet_id + transaction_payload`，在 TEE 内完成签名，返回 `signed_tx + tx_hash`
- `get_attestation`
  返回当前 enclave 的 quote/measurement；只要求导出，不做完整远程证明闭环

宿主机本地 HTTP API 与 TEE 命令一一对应：

- `POST /wallets`
- `GET /wallets/{wallet_id}/address`
- `POST /wallets/{wallet_id}/sign`
- `GET /attestation`
- `GET /health`

### 3. 状态与边界

- TEE 内维护一个内存态 key registry：`wallet_id -> private_key`
- 不提供 `set_key`、`get_key`、`secret_id`、`encrypted_key` 这些第一阶段不再需要的概念
- 宿主机不接触私钥、不接触密文、不拼装 cloud credentials
- 错误边界明确：
  - `wallet_id` 不存在
  - 交易 payload 非法
  - TEE IPC 失败
  - attestation 获取失败
- README 新增本地 TODO/roadmap 段，明确写入：
  - `TODO: replace in-memory key registry with external encrypted/sealed storage`
  - `TODO: add recovery/restore workflow`
  - `TODO: add policy-based signing controls`

### 4. 文档与计划收口

- 根 README 的 `eth1` 交互图改成新 v1 数据流，不再描述 `Lambda + KMS + Secrets Manager`
- 在根 README 的 `eth1` 章节下新增一个 `Local TODO` 或 `Next Step` 小节，专门记录“后续改为外部存储”
- `docs/codex-plan.md` 整体改写为“TEE wallet core v1”计划，旧的 KMS/CSMS 平移内容移除，不保留双重目标

## Test Plan

- `create_wallet` 能在 TEE 内生成新 wallet，并返回稳定可查询的 `wallet_id + address`
- 对同一 `wallet_id` 调用 `get_address` 多次，地址一致
- `sign_transaction` 对有效 EIP-1559 payload 返回 `signed_tx + tx_hash`
- 使用不存在的 `wallet_id` 调用 `get_address` 或 `sign_transaction` 返回明确业务错误
- 非法交易字段在 TEE 内被拒绝，不产生签名
- `get_attestation` 返回非空 quote/measurement
- 宿主机进程日志和响应中不出现私钥明文
- 重启 enclave 后，内存态 wallet 消失，这一行为在 v1 中应被视为符合预期，并在 README 中明确说明
- README 中存在第二阶段 TODO：外部存储替换计划

## Assumptions

- 第一阶段优先验证“完整钱包内核”，不是“生产级密钥托管链路”
- 默认保留本地 HTTP gateway，方便手测和后续接入华为云外围服务
- 默认保留 `vsock` 作为宿主机到 TEE 的 IPC
- attestation 只做到可导出 quote/measurement，不做远程策略校验闭环
- 根 README 是你说的“本地 README”，TODO 记录写在这里，而不是单独写进 `docs/`
