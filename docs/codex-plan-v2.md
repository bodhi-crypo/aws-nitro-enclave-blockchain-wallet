  # 华为云 KMS 集成第二阶段实施计划

  ## Summary

  第二阶段采用 KMS 包裹模型 + 官方 SDK + qt_proxy：

  - 对外 HTTP API 保持不变：继续使用 POST /wallets、GET /wallets/{id}/address、POST /wallets/{id}/sign
  - KMS 只允许指定 QingTian Enclave 访问，策略固定绑定当前 release EIF 的 PCR0 + PCR8
  - KMS 调用只发生在 enclave 内；parent 只负责拿临时凭证、转发请求、落本地密文文件
  - 先不接 CSMS，密文先落宿主机本地文件目录，完成“可恢复 + KMS 受控”的最小闭环

  ## Key Changes

  ### 1. 钱包生成与存储流

  - POST /wallets 由 host gateway 接收，host 获取 ECS metadata 临时凭证后经 vsock 传给 enclave
  - enclave 内调用 KMS：
      - generateRandom 生成 32 字节随机数，并在 enclave 内形成有效 secp256k1 私钥
      - createDataKey 生成数据密钥，得到 plaintext DEK + encrypted DEK
  - enclave 内用 AES-256-GCM 加密私钥，返回 wallet record
  - host 将 wallet record 持久化到 WALLET_STORE_DIR，默认 /var/lib/tee-wallet/wallets/<wallet_id>.json
  - wallet record 固定包含：version、wallet_id、address、kms_key_id、encrypted_data_key、encrypted_private_key、nonce、tag

  ### 2. 签名流

  - POST /wallets/{id}/sign 时，host 从本地文件读取 wallet record
  - host 获取 ECS 临时凭证，并将 wallet record + transaction_payload + credentials 经 vsock 发给 enclave
  - enclave 内调用 decryptDataKey，解出 DEK 后恢复私钥并完成签名
  - enclave 返回 signed_tx + tx_hash
  - GET /wallets/{id}/address 直接由 host 从本地 wallet record 返回

  ### 3. 权限与运行边界

  - KMS 接入固定为：QingTian SDK + qt_proxy
  - KMS 身份固定为 ECS 临时凭证透传
  - KMS policy 只允许：
      - kms::generateRandom
      - kms:cmk:createDataKey
      - kms:cmk:decryptDataKey
  - 所有权限绑定：
      - kms:RecipientAttestation/PCR0
      - kms:RecipientAttestation/PCR8
  - 第二阶段固定只允许当前 release EIF 的 PCR，不做多版本白名单
  - 调试模式 PCR 不进入正式 policy

  ### 4. 实现拆分

  - enclave 新增 HuaweiKmsClient，封装：
      - generate_random
      - create_data_key
      - decrypt_data_key
  - enclave 的 create_wallet 改为输出 wallet record，不再把私钥留在内存表中
  - enclave 的 sign_transaction 改为依赖 wallet record
  - host 新增：
      - qt_proxy 配置和健康检查
  - 新增环境变量：
      - HWC_KMS_KEY_ID
      - HWC_PROJECT_ID
      - WALLET_STORE_DIR
      - QT_PROXY_PORT

  ## Test Plan

  - 单元测试：
      - create_wallet 在 fake KMS 下返回稳定 wallet_id + address + wallet_record
      - sign_transaction 在 fake decryptDataKey 下返回 signed_tx + tx_hash
      - wallet record 缺字段时返回明确错误
      - metadata 临时凭证缺失时 host 返回明确错误
  - 集成测试：
      - POST /wallets 后生成本地 <wallet_id>.json
      - enclave 重启后，之前钱包仍可 sign
      - 停掉 qt_proxy 后 KMS 请求失败且错误清晰
      - 错误 PCR 下 KMS 调用失败
  - 安全测试：
      - 宿主机日志、文件、HTTP 响应中不出现明文私钥或明文 DEK
      - KMS policy 不允许非目标 enclave 成功调用

  ## Assumptions

  - 第二阶段只做 KMS + 本地密文存储，不接 CSMS
  - 当前仍以单节点验证为目标，不处理多实例共享目录
  - 当前使用华为云官方 qt_proxy 路径
  - 如 Python 侧无法直接稳定接官方 KMS SDK，可接受在 enclave 内增加一个窄包装层，但不改变上层接口