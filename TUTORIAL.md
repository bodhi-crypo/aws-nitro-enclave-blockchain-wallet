application 下面其实放了 6 个“示例应用模板”。它们共用同一种基本组织方式，但演示的通信模式不同。

先说目录规律。多数 app 都有这几层：

enclave/：真正跑在 Nitro Enclave 里的代码或启动脚本。
server/：跑在 parent EC2 instance 上的辅助服务，负责和 enclave 用 vsock 通信，或者做代理。
lambda/：只有部分场景有，用来从 AWS 外部触发流程。
user_data/：EC2 启动时的装机和拉起脚本。
README.md：这个场景自己的部署说明。
一个容易忽略的点：根 README 列了 5 个 advanced networking pattern，但 application/eth1 其实是“基础钱包示例”，不算 advanced networking，所以没列在那 5 个里。

1. eth1
路径：application/eth1

当前主线不是旧版 AWS KMS custody 流程，而是 QingTian `wallet core v1`：

- `application/eth1/server/app.py`
  宿主机本地 HTTP gateway，对外暴露 `POST /wallets`、`GET /wallets/{wallet_id}/address`、`POST /wallets/{wallet_id}/sign`、`GET /attestation`。
- `application/eth1/enclave/server.py`
  enclave 内的钱包内核，负责生成私钥、维护内存态 wallet registry，以及实际交易签名。
- `application/eth1/lambda/lambda_function.py`
  只是兼容性客户端，转发给本地 gateway，不是主运行链路。

这条路径的关键点是：

- 私钥只在 enclave 内生成并保存在进程内存里。
- 宿主机通过 `AF_VSOCK` 转发请求，但不会接触明文私钥。
- enclave 重启后钱包状态会丢失，这是当前 v1 的预期行为。

如果你已经把 gateway 和 enclave 跑起来，可以直接用仓库里的压测脚本做端到端签名压测：

```bash
python3 scripts/bench_eth1_sign.py \
  --base-url http://127.0.0.1:8080 \
  --concurrency 8 \
  --wallet-count 8 \
  --duration-seconds 15
```

脚本会先预创建多个钱包，再并发调用 `POST /wallets/{wallet_id}/sign`，输出签名 `TPS` 和耗时分位数。
