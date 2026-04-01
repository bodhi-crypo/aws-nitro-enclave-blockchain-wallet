# 华为云 QingTian `eth1` Wallet Core v2 部署与验证手册

本文档聚焦当前仓库里真正生效的华为云 QingTian `eth1` 运行路径：

- host gateway：`application/eth1/server/app.py`
- enclave wallet core：`application/eth1/enclave/server.py`
- KMS bridge：`application/eth1/enclave/qingtian_kms_bridge.c`

root `README.md` 里的 AWS/CDK 内容仍然保留，但属于 legacy 路径，不是本文档的重点。

## 1. 架构概览

### 1.1 运行组件

- `application/eth1/server/app.py`
  宿主机本地 HTTP gateway，对外暴露钱包 API，并通过 `AF_VSOCK` 转发请求。
- `application/eth1/enclave/server.py`
  enclave 内的钱包核心，负责创建钱包、恢复钱包、查询地址、签名交易和导出 attestation。
- `application/eth1/enclave/qingtian_kms_bridge.c`
  enclave 内调用华为云 KMS 的 bridge，当前通过 `qt_proxy` 出网。

### 1.2 当前行为

- `POST /wallets` 会在 enclave 内生成私钥材料。
- enclave 使用 `createDataKey + AES-256-GCM` 将私钥包裹成 `wallet record`。
- host 只保存 `wallet record`，不保存明文私钥或明文数据密钥。
- enclave 重启后，可通过本地 `wallet record + KMS decryptDataKey` 恢复并继续签名。
- host gateway 不接触明文私钥，但会把配置好的 KMS 凭证转发给 enclave。

### 1.3 对外 API

- `POST /wallets`
- `GET /wallets/{wallet_id}/address`
- `POST /wallets/{wallet_id}/sign`
- `GET /attestation`
- `GET /health`

## 2. 环境变量

### 2.1 当前 QingTian `eth1` 运行时

| 变量 | 组件 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- | --- |
| `PORT` | host gateway | 否 | `8080` | 宿主机 HTTP gateway 监听端口。 |
| `TEE_ENCLAVE_CID` | host gateway | 否 | `16` | gateway 连接 enclave 时使用的 vsock CID。 |
| `TEE_VSOCK_PORT` | host gateway + enclave | 否 | `5000` | vsock 端口；host 和 enclave 两侧必须一致。 |
| `WALLET_STORE_DIR` | host gateway | 否 | `/var/lib/tee-wallet/wallets` | 宿主机持久化 `wallet record` 的目录。 |
| `HWC_KMS_ACCESS_KEY` | host gateway | 是 | 无 | 当前主路径使用的静态 AK。 |
| `HWC_KMS_SECRET_KEY` | host gateway | 是 | 无 | 当前主路径使用的静态 SK。 |
| `HWC_KMS_SECURITY_TOKEN` | host gateway | 否 | 无 | 使用临时安全凭证时才需要。 |
| `HWC_KMS_CREDENTIAL_EXPIRES_AT` | host gateway | 否 | 无 | 凭证过期时间，当前仅透传给 enclave helper。 |
| `HWC_KMS_KEY_ID` | host gateway -> enclave | 是 | 无 | 用于 `createDataKey/decryptDataKey` 的 CMK ID。 |
| `HWC_KMS_ENDPOINT` | host gateway -> enclave | 是 | 无 | KMS endpoint，例如 `kms.cn-north-4.myhuaweicloud.com`。 |
| `HWC_PROJECT_ID` | host gateway -> enclave | 是 | 无 | 当前项目 ID。 |
| `QT_PROXY_PORT` | host gateway -> enclave | 否 | `8000` | host 上 `qt_proxy` 监听端口。 |
| `HWC_KMS_BRIDGE_CMD` | enclave | 否 | `/app/qingtian_kms_bridge` | enclave 内调用 KMS bridge 的命令。默认由镜像注入。 |
| `HWC_ATTESTATION_CACHE_TTL_SECONDS` | enclave bridge | 否 | `60` | `qingtian_kms_bridge` 进程内 attestation document + RSA keypair 缓存 TTL。 |
| `HWC_DEK_CACHE_TTL_SECONDS` | enclave | 否 | `60` | enclave 内明文 DEK 进程内缓存 TTL。 |
| `HWC_DEK_CACHE_MAX_ENTRIES` | enclave | 否 | `256` | enclave 内明文 DEK 缓存最大条目数。 |
| `QINGTIAN_ATTESTATION_QUOTE` | enclave | 否 | `quote-unavailable` | 当前占位 attestation quote。 |
| `QINGTIAN_ATTESTATION_MEASUREMENT` | enclave | 否 | `measurement-unavailable` | 当前占位 attestation measurement。 |
| `LD_LIBRARY_PATH` | enclave runtime | 否 | `/usr/local/lib:${LD_LIBRARY_PATH}` | enclave runtime 动态库搜索路径，镜像内已预设。 |

当前主路径最关键的一组变量是：
`HWC_KMS_ACCESS_KEY`、`HWC_KMS_SECRET_KEY`、`HWC_KMS_KEY_ID`、`HWC_KMS_ENDPOINT`、`HWC_PROJECT_ID`、`TEE_ENCLAVE_CID`、`TEE_VSOCK_PORT`、`QT_PROXY_PORT`、`WALLET_STORE_DIR`。

性能调优时，优先关注：
`HWC_ATTESTATION_CACHE_TTL_SECONDS`、`HWC_DEK_CACHE_TTL_SECONDS`、`HWC_DEK_CACHE_MAX_ENTRIES`。

### 2.2 enclave 重建脚本

这些变量由 `scripts/rebuild_eth1_qingtian_enclave.sh` 使用：

| 变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `IMAGE_TAG` | 否 | `tee-wallet-enclave:v1` | Docker image tag。 |
| `EIF_PATH` | 否 | `/root/tee-wallet-enclave.eif` | 生成的 EIF 路径。 |
| `ENCLAVE_CID` | 否 | `16` | 启动 enclave 时传给 `qt enclave start` 的 CID。 |
| `ENCLAVE_CPU_COUNT` | 否 | `2` | 分配给 enclave 的 vCPU 数。 |
| `ENCLAVE_MEMORY_MIB` | 否 | `2048` | 分配给 enclave 的内存大小。 |
| `ENCLAVE_ID` | 否 | `0` | 停止旧 enclave 时使用的 enclave id。 |
| `DEBUG_MODE` | 否 | `1` | 为 `1` 时附带 `--debug-mode` 启动 enclave。 |
| `NO_CACHE` | 否 | `0` | 为 `1` 时 Docker build 使用 `--no-cache`。 |

### 2.3 debug 与 normal 模式

- `debug` 模式便于使用 `qt enclave console`，但不适合验证基于 `PCR0` 的 KMS 策略。
- `normal` 模式下不要依赖 console 输出。当前 shell wrapper 会把 guest 内 stdout/stderr 重定向到：
  `/var/log/tee-wallet/service.log`
- 如果 `normal` 模式 enclave 一启动就退出，优先怀疑 guest 进程启动方式或日志输出链路，而不是先假设 KMS 或 PCR 配置有误。


## 3. 前置条件

### 3.1 基础条件

- 华为云账号已开通 QingTian Enclave。
- ECS 规格支持 QingTian，推荐 `C7t` 或 `kC2`。
- 父机建议至少 `8 vCPU / 16 GiB`。
- 已准备 SSH key pair 和 EIP。
- 已创建 DEW KMS CMK，并拿到以下信息：
  - `HWC_KMS_KEY_ID`
  - `HWC_KMS_ENDPOINT`
  - `HWC_PROJECT_ID`

### 3.2 推荐环境基线

- parent：`C7t + QingTian Enclave + EulerOS 2.0`
- enclave runtime：`Ubuntu 22.04`
- KMS 通道：`qt_proxy + qingtian_kms_bridge`
- host 凭证：静态 `HWC_KMS_ACCESS_KEY / HWC_KMS_SECRET_KEY`
- KMS policy：先只绑定 `PCR0`
- enclave 重建：默认走 Docker cache，必要时再 `NO_CACHE=1`

### 3.3 推荐购买参数

- 区域：选择你账号当前支持 QingTian Enclave 的区域。
- 镜像：`Huawei Cloud EulerOS 2.0`
- 打开 enclave 能力。
- 安全组：
  - `22/tcp` 仅放行你自己的公网 IP。
  - `8080/tcp` 不建议直接公网开放，优先使用 SSH 隧道测试。

## 4. KMS 策略与 PCR0

### 4.1 当前建议

当前阶段建议先把 KMS 权限挂到 ECS 使用的 Agency/实例身份上；如果你还在联调，也可以先直接用静态 `AK/SK`。

当前运行链路是：

- host 把配置好的 KMS 凭证转发给 enclave。
- enclave 内的 `qingtian_kms_bridge` 使用这组凭证调用 KMS。
- 如果后续切回 ECS metadata 临时凭证，再由 Agency 成为运行时真实身份。

### 4.2 最小可用策略

当前建议先使用只绑定 `PCR0` 的最小策略：

```json
{
  "Version": "1.1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:cmk:generate",
        "kms:dek:create",
        "kms:cmk:decrypt",
        "kms:dek:decrypt"
      ],
      "Resource": [
        "*"
      ],
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation/PCR0": [
            "<release EIF 的 PCR0>"
          ]
        }
      }
    }
  ]
}
```

说明：

- 这一轮先只绑定 `PCR0`。
- 当前 EIF 没有启用镜像签名，因此 `PCR8` 还是全 `0`，先不要写进策略。
- `Resource` 可以先用 `"*"`，先把 attestation + KMS 路径跑通，再考虑收紧到指定 key。

### 4.3 如何获取 `PCR0`

必须使用最终 release 镜像对应的 EIF 取值：

```bash
qt enclave make-img --docker-uri tee-wallet-enclave:v1 --eif /root/tee-wallet-enclave.eif
```

命令输出里会包含 `PCR0` 和 `PCR8`。当前阶段只把 `PCR0` 写进策略。

注意：

- 重新构建 enclave 镜像后，`PCR0` 可能变化。
- `PCR0` 变化后，需要同步更新 KMS policy。
- 不要使用 debug 阶段随手构建出来的临时 PCR 值。

## 5. 部署步骤

### 5.1 初始化 ECS

```bash
sudo -i
yum install -y git docker python3 python3-pip jq
systemctl enable --now docker
```

安装 QingTian 组件：

```bash
yum install -y qt-enclave-bootstrap virtio-qtbox qingtian-tool
qt enclave -h
```

配置资源隔离：

```bash
cat >/etc/qingtian/enclave/qt-enclave-env.conf <<'EOF'
hugepage_size:1024
memory_mib:2048
cpu_count:2
EOF

systemctl enable --now qt-enclave-env
systemctl status qt-enclave-env --no-pager
```

### 5.2 上传仓库

```bash
cd /root
git clone <your-repo-url> aws-nitro-enclave-blockchain-wallet
cd aws-nitro-enclave-blockchain-wallet
```

### 5.3 构建 enclave 镜像并生成 EIF

```bash
docker build -f application/eth1/enclave/Dockerfile . -t tee-wallet-enclave:v1
qt enclave make-img --docker-uri tee-wallet-enclave:v1 --eif /root/tee-wallet-enclave.eif
ls -lh /root/tee-wallet-enclave.eif
```

这里必须使用仓库根目录 `.` 作为 build context，因为 enclave 镜像同时依赖：

- `application/eth1/enclave/`
- `third_party/huawei-qingtian/`

不要把 `application/eth1` 当作 build context，否则 Dockerfile 看不到 vendored QingTian SDK 源码。

### 5.4 启动 `qt_proxy`

第二阶段的 KMS 路径固定使用 `qt_proxy`：

```bash
/usr/local/bin/qingtian/enclave/qt_proxy -l 8000 -a kms.ap-southeast-3.myhuaweicloud.com -p 443
```

建议把它做成独立 `systemd` 服务，并让 gateway 和 enclave 都依赖它先启动。

### 5.5 启动 enclave

第一次建议用 debug 模式启动，便于查看 console：

```bash
qt enclave start --cpus 2 --mem 2048 --eif /root/tee-wallet-enclave.eif --cid 16 --debug-mode
qt enclave query
qt enclave console --enclave-id 0
```

如果返回的 enclave ID 不是 `0`，后续命令里替换成实际值。

如果你频繁修改 enclave 代码，建议直接用仓库里的重建脚本：

```bash
cd /root/aws-nitro-enclave-blockchain-wallet
bash scripts/rebuild_eth1_qingtian_enclave.sh
```

示例：

```bash
IMAGE_TAG=tee-wallet-enclave:v1 \
EIF_PATH=/root/tee-wallet-enclave.eif \
ENCLAVE_CID=16 \
ENCLAVE_CPU_COUNT=2 \
ENCLAVE_MEMORY_MIB=2048 \
DEBUG_MODE=1 \
bash scripts/rebuild_eth1_qingtian_enclave.sh
```

只有在你怀疑缓存脏了、改了系统依赖、更新了 `third_party/huawei-qingtian` 或需要强制全量重建时，才建议：

```bash
NO_CACHE=1 bash scripts/rebuild_eth1_qingtian_enclave.sh
```

### 5.6 启动宿主机 gateway

debug 阶段先不要做 `systemd`，直接在宿主机启动：

```bash
cd /root/aws-nitro-enclave-blockchain-wallet
PORT=8080 \
TEE_ENCLAVE_CID=16 \
TEE_VSOCK_PORT=5000 \
HWC_KMS_KEY_ID=<your-kms-key-id> \
HWC_KMS_ENDPOINT=kms.ap-southeast-3.myhuaweicloud.com \
HWC_PROJECT_ID=<your-project-id> \
HWC_KMS_ACCESS_KEY=<your-ak> \
HWC_KMS_SECRET_KEY=<your-sk> \
QT_PROXY_PORT=8000 \
WALLET_STORE_DIR=/var/lib/tee-wallet/wallets \
python3 application/eth1/server/app.py
```

如果使用的是临时安全凭证，再额外补：

```bash
HWC_KMS_SECURITY_TOKEN=<your-security-token>
```

## 6. 功能验证

### 6.1 健康检查

```bash
curl http://127.0.0.1:8080/health
```

预期结果：

```json
{"status":"ok"}
```

### 6.2 创建钱包

```bash
curl -s -X POST http://127.0.0.1:8080/wallets | jq
```

成功后，宿主机会在 `WALLET_STORE_DIR` 下生成 `<wallet_id>.json`。

### 6.3 查询地址

```bash
curl -s http://127.0.0.1:8080/wallets/<wallet_id>/address | jq
```

### 6.4 签名交易

```bash
curl -s -X POST http://127.0.0.1:8080/wallets/<wallet_id>/sign \
  -H 'Content-Type: application/json' \
  -d '{
    "transaction_payload": {
      "chainId": 11155111,
      "nonce": 0,
      "type": 2,
      "to": "0x1111111111111111111111111111111111111111",
      "value": "0.001",
      "gas": 21000,
      "maxFeePerGas": 2000000000,
      "maxPriorityFeePerGas": 1000000000
    }
  }' | jq
```

### 6.5 读取 attestation

```bash
curl -s http://127.0.0.1:8080/attestation | jq
```

## 7. 恢复验证

重启 enclave：

```bash
qt enclave stop --enclave-id 0
qt enclave start --cpus 2 --mem 2048 --eif /root/tee-wallet-enclave.eif --cid 16 --debug-mode
```

再次使用之前的钱包签名：

```bash
curl -s -X POST http://127.0.0.1:8080/wallets/<wallet_id>/sign \
  -H 'Content-Type: application/json' \
  -d '{
    "transaction_payload": {
      "chainId": 11155111,
      "nonce": 1,
      "type": 2,
      "to": "0x1111111111111111111111111111111111111111",
      "value": "0.001",
      "gas": 21000,
      "maxFeePerGas": 2000000000,
      "maxPriorityFeePerGas": 1000000000
    }
  }' | jq
```

预期仍然成功。这说明当前实现已经从“纯内存态”进入“KMS 包裹 + 本地密文 record”的恢复模型。

## 8. 压测签名 TPS 和耗时

当前仓库提供了一个端到端 benchmark 脚本：

```bash
python3 scripts/bench_eth1_sign.py --help
```

测量口径：

- 通过宿主机 HTTP gateway 调用 `POST /wallets/{wallet_id}/sign`
- 包含 HTTP + `AF_VSOCK` + enclave signing 的整体耗时
- 默认固定并发模型
- 默认预创建多个钱包，并让每个 worker 独占一个 wallet，自增自己的 `nonce`

常用示例：

```bash
cd /root/aws-nitro-enclave-blockchain-wallet
python3 scripts/bench_eth1_sign.py \
  --base-url http://127.0.0.1:8080 \
  --concurrency 8 \
  --wallet-count 8 \
  --warmup-seconds 5 \
  --duration-seconds 15 \
  --timeout-seconds 10
```

建议先从 `4` 或 `8` 并发开始，再逐步提升到 `16`、`32`，观察：

- TPS 是否继续线性增长
- `p95/p99` 是否明显抬高
- 是否出现 `timeout`、`http_error` 或 `network_error`

同一组压测参数下，`v1`、`v2` 优化前、`v2` 优化后的结果可以直接对比如下：

- 压测参数：`--base-url http://127.0.0.1:8080 --concurrency 8 --wallet-count 8 --warmup-seconds 5 --duration-seconds 15 --timeout-seconds 10`
- `v1`：不走 KMS，TEE 内生成私钥并直接签名
- `v2` 优化前：走 KMS 包裹与恢复链路，但每次签名都会重新拉起 bridge、重新生成 attestation 和 RSA keypair
- `v2` 优化后：bridge 常驻、attestation/keypair 缓存、明文 DEK 短期缓存

| 指标 | v1 | v2 优化前 | v2 优化后 |
| --- | --- | --- | --- |
| `total_requests` | `2312` | `301` | `2863` |
| `successful_requests` | `2311` | `301` | `2862` |
| `failed_requests` | `1` | `0` | `1` |
| `elapsed_seconds` | `15.167` | `18.33` | `17.583` |
| `tps` | `152.374` | `16.421` | `162.768` |
| `latency_ms_avg` | `51.993` | `414.473` | `42.817` |
| `latency_ms_p50` | `45.446865` | `355.565668` | `36.26544` |
| `latency_ms_p95` | `45.944895` | `374.058428` | `36.745666` |
| `latency_ms_p99` | `46.670864` | `1360.693787` | `37.025741` |
| `latency_ms_min` | `7.908026` | `48.674712` | `6.933192` |
| `latency_ms_max` | 未记录 | `9718.514533` | `10009.974017` |

结论上：

- `v2` 优化前引入 KMS 包裹与恢复后，吞吐相比 `v1` 明显下降，延迟整体抬高。
- `v2` 优化后，`TPS` 已恢复到与 `v1` 同量级，当前这一组数据里甚至略高于 `v1`。
- 长尾仍然存在，当前 `latency_ms_max` 仍接近 `10s`，说明后续仍值得继续看超时请求和偶发慢请求。

### 8.1 这次优化的核心思路

`v2` 优化前慢的根因，不只是多了一次 `decrypt-datakey` 网络调用，而是每次签名都重复执行了一整套高固定成本动作：

- Python 每次都 `subprocess.run()` 拉起一个新的 `qingtian_kms_bridge`
- bridge 每次都重新生成 `RSA-2048` keypair
- bridge 每次都重新获取 attestation document
- bridge 每次都重新初始化/销毁 `curl` 和 proxy 连接上下文
- 然后才真正调用 KMS 解密 DEK

所以优化的重点不是“减少一点点 Python 开销”，而是把这些重复的固定成本从“每次签名”改成“每个 enclave 进程”或“短时间窗口内一次”。

当前采用了三层优化：

- **bridge 常驻**
  `HuaweiKmsClient` 不再为每次 KMS 调用拉起一次 helper，而是复用同一个 `qingtian_kms_bridge` 进程。
- **attestation/keypair 缓存**
  bridge 进程内缓存 attestation document 和对应的 RSA keypair，避免每次签名都重新生成。
- **明文 DEK 短期缓存**
  enclave 进程内对明文 DEK 做 TTL + LRU 缓存。命中时不再重复调用 `decrypt-datakey`，但缓存仅存在于 enclave 进程内存中，重启即失效。

### 8.2 当前优化为什么没有破坏安全边界

这次优化没有把明文私钥落盘，也没有把明文 DEK 带出 enclave。

当前边界仍然是：

- host 只保存 `wallet record`
- 明文私钥仍然只在 enclave 进程内短暂存在
- 明文 DEK 只在 enclave 进程内做短期内存缓存
- attestation document 仍随需要 KMS 授权的请求一起发送

因此，这一轮优化是“减少重复的 enclave 内固定成本”，不是“把密钥材料下沉到 host 或磁盘”。

### 8.3 这组数据该如何解读

当前 `v2` 优化后数据说明两件事：

- 主路径瓶颈已经不再是“每次签名都重新生成 attestation / RSA keypair / bridge 进程”
- 当前还剩的主要性能风险是**长尾请求**，而不是平均吞吐不足

所以后续如果还要继续优化，优先级应该是：

1. 看导致 `latency_ms_max` 接近 `10s` 的超时/慢请求
2. 再决定是否要进一步调大 DEK cache TTL 或 cache 容量
3. 最后才考虑更激进的私钥级缓存方案



## 9. 运行建议

### 9.1 建议把 `qt_proxy` 做成独立服务

当前 KMS 路径固定依赖 `qt_proxy`。建议把它做成独立 `systemd` 服务，并让 gateway、enclave 都依赖它先启动。

### 9.2 推荐的一键重建方式

平时开发直接使用：

```bash
bash scripts/rebuild_eth1_qingtian_enclave.sh
```

只有在这些场景才建议强制全量重建：

- 改了 Dockerfile
- 改了系统依赖
- 改了 `requirements.txt`
- 更新了 `third_party/huawei-qingtian`
- 怀疑缓存脏了

命令：

```bash
NO_CACHE=1 bash scripts/rebuild_eth1_qingtian_enclave.sh
```

### 9.3 不要在 Docker build 阶段联网拉取 `huawei-qingtian`

实际联调中，外网访问 `gitee.com` 不稳定，容易导致构建失败。当前稳定方案是把需要的 QingTian SDK 目录直接 vendoring 到仓库，并在本地构建。

### 9.4 builder 和 runtime 保持同一发行版

当前稳定方案是：

- builder：`ubuntu:22.04`
- runtime：`ubuntu:22.04`

不要再混用 Ubuntu builder 和 Debian runtime，否则容易出现运行时动态库不匹配。

### 9.5 当前 host 默认使用静态 AK/SK

为了降低联调复杂度，当前 host gateway 只使用静态配置的：

- `HWC_KMS_ACCESS_KEY`
- `HWC_KMS_SECRET_KEY`
- `HWC_KMS_SECURITY_TOKEN` 可选

不要把 ECS metadata 临时凭证当成当前主路径的默认前提。

## 10. Troubleshooting

### 10.1 `qt enclave -h` 报 `ModuleNotFoundError: No module named 'docker'`

`qt` 是一个 Python 脚本，实际使用的是当前 PATH 里的 `python`。如果 `docker` 和 `knack` 没装到这个解释器环境里，CLI 会直接报错。

检查：

```bash
head -1 /usr/local/bin/qt
which python
python --version
```

修复：

```bash
yum install -y python3-pip
python -m pip install docker knack
qt enclave -h
```

### 10.2 `qt-enclave-env` 启动失败，`virtio-qtbox.ko` 无法加载

如果你看到类似：

- `sandbox driver is uninstalled`
- `insmod ... virtio-qtbox.ko`
- `Invalid parameters`

先检查：

```bash
getenforce
uname -r
modinfo /opt/qingtian/enclave/virtio-qtbox.ko
cat /etc/qingtian/enclave/qt-enclave-env.conf
```

如果 `vermagic` 和当前运行内核不匹配，例如：

- 宿主机：`5.10.0-182...hce2`
- 模块：`5.10.0-60...`

说明是驱动和当前内核版本不兼容，不是配置文件问题。

可尝试切换到与 QingTian 驱动包更匹配的旧 kernel，例如：

```bash
yum install -y kernel-5.10.0-60.18.0.50.r1141_59.hce2.x86_64
grubby --set-default /boot/vmlinuz-5.10.0-60.18.0.50.r1141_59.hce2.x86_64
reboot
```

重启后确认：

```bash
uname -r
systemctl restart qt-enclave-env
systemctl status qt-enclave-env --no-pager
```

### 10.3 `qt enclave start` 成功，但 `qt enclave query` 很快变成 `[]`

优先检查 enclave 镜像启动结构是否仍然保持为：

- 先执行 `/app/start.sh`
- 再由 shell wrapper 启动 `python3 /app/server.py`

当前稳定基线里，不建议让 `python3` 直接作为容器 `CMD`。另外 enclave 运行时应固定为 `Python 3.10`，避免 `web3==5.23.0` 在 `Python 3.11` 下触发 `inspect.getargspec` 导入错误。

### 10.4 Docker build 时报找不到 vendored QingTian SDK

确认构建命令使用的是仓库根目录 `.` 作为 build context：

```bash
docker build -f application/eth1/enclave/Dockerfile . -t tee-wallet-enclave:v1
```

不要使用：

```bash
docker build -f application/eth1/enclave/Dockerfile application/eth1 -t tee-wallet-enclave:v1
```

### 10.5 vendored qtsm 构建时报 `cp libqtsm.so ../output/` 失败

根因通常是 `output/` 目录不存在。当前 Dockerfile 里已经通过以下方式规避：

```bash
mkdir -p /opt/huawei-qingtian/enclave/qtsm/output
```

### 10.6 `/app/qingtian_kms_bridge: error while loading shared libraries: libcbor.so.0.8`

这通常是 builder/runtime 发行版不一致导致的。回到当前稳定方案：

- builder：`ubuntu:22.04`
- runtime：`ubuntu:22.04`

### 10.7 ECS metadata 返回 `401 Unauthorized`

如果你看到：

```text
401 Unauthorized
Please configure Cloud Service Agency first
```

这说明你在尝试走 metadata 临时凭证。当前主路径默认不依赖 metadata，先退回静态：

- `HWC_KMS_ACCESS_KEY`
- `HWC_KMS_SECRET_KEY`
- `HWC_KMS_SECURITY_TOKEN` 可选

### 10.8 KMS 返回 `KMS.2203 Data key hash verification failed`

这是因为把 `createDataKey` 返回的密文 DEK 错误地送到了 `decrypt-data`。

正确做法：

- 密文 DEK 必须走 `decrypt-datakey`
- 不能误用 `decrypt-data`

### 10.9 Python 侧 `json.loads(process.stdout)` 报错

如果 bridge 或 vendored SDK 向 stdout 混入日志，例如：

```text
unix socket listening...
```

Python 侧就不能直接把整个 stdout 当成纯 JSON。当前正确做法是：

- 从 stdout 最后一行向前查找合法 JSON
- 不要假设整个 stdout 都是 JSON

## 11. TODO

- TODO: replace in-memory key registry with external encrypted/sealed storage
- TODO: add recovery/restore workflow
- TODO: add policy-based signing controls
