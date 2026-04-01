# 华为云 QingTian `eth1` Wallet Core v2部署手册

本文档说明当前仓库中 `eth1` 的运行路径，以及如何在华为云上一步一步部署并验证钱包能力。

## 运行组件

- `application/eth1/server/app.py`
  宿主机本地 HTTP gateway，对外暴露钱包 API，并通过 `AF_VSOCK` 转发请求。
- `application/eth1/enclave/server.py`
  TEE 内的钱包内核，负责内存态 key registry、创建钱包、查询地址、签名交易和导出 attestation。

## 对外 API

- `POST /wallets`
- `GET /wallets/{wallet_id}/address`
- `POST /wallets/{wallet_id}/sign`
- `GET /attestation`
- `GET /health`

## 当前行为

- 当前分支已经进入第二阶段：`POST /wallets` 会通过 KMS 包裹模型生成钱包。
- enclave 内生成私钥材料，并用 `createDataKey + AES-256-GCM` 包裹成 `wallet record`。
- 宿主机只保存 `wallet record`，不保存明文私钥或明文数据密钥。
- enclave 重启后，钱包仍可通过本地 `wallet record + KMS decryptDataKey` 恢复并签名。
- 宿主机 gateway 不接触明文私钥，但会把静态配置的 `AK/SK` 凭证转发给 enclave。

## 第二阶段新增环境变量

- `HWC_KMS_KEY_ID`
  DEW KMS 中用于 `createDataKey/decryptDataKey` 的 CMK ID
- `HWC_KMS_ENDPOINT`
  对应区域的 KMS endpoint，例如 `kms.cn-north-4.myhuaweicloud.com`
- `HWC_PROJECT_ID`
  当前项目 ID
- `HWC_KMS_ACCESS_KEY`
  手动配置的访问密钥 AK
- `HWC_KMS_SECRET_KEY`
  手动配置的访问密钥 SK
- `HWC_KMS_SECURITY_TOKEN`
  可选。仅在你使用临时安全凭证时配置；手动下载的永久 AK/SK 一般不需要
- `QT_PROXY_PORT`
  host 上 `qt_proxy` 监听端口，默认 `8000`
- `WALLET_STORE_DIR`
  宿主机 `wallet record` 目录，默认 `/var/lib/tee-wallet/wallets`
- `HWC_KMS_BRIDGE_CMD`
  enclave 内部调用真实 KMS bridge 的命令。镜像默认值是 `/app/qingtian_kms_bridge`

## 前置条件

- 一个已开通 `QingTian Enclave` 能力的华为云账号。
- 一个支持 QingTian Enclave 的 Linux ECS 规格，推荐 `C7t` 或 `kC2`。
- 父机至少 `8 vCPU / 16 GiB`。
- 一个用于 SSH 登录的 key pair。
- 一个绑定到 ECS 的 EIP。

推荐购买参数：

- 区域：选择你账号当前支持 QingTian Enclave 的区域。
- 镜像：`Huawei Cloud EulerOS 2.0`
- enable enclave
- 安全组：
  - `22/tcp` 仅放行你自己的公网 IP
  - `8080/tcp` 建议不要直接公网开放，优先使用 SSH 隧道测试

## KMS IAM 身份策略配置

第二阶段推荐把 KMS 权限挂在 **ECS 使用的 Agency/实例身份** 上；但如果你当前是手动下载的 `AK/SK`，也可以先直接用这组访问密钥联调。

原因是当前运行链路里：

- 宿主机把配置里的 `AK/SK` 凭证转发给 enclave
- enclave 内的 `qingtian_kms_bridge` 使用这组凭证调用 KMS
- 如果后续切回 ECS metadata 临时凭证，再由 Agency 成为运行时真实身份

### 最小可用策略

当前实现建议先使用只绑定 `PCR0` 的最小策略：

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
- 当前这一轮先只绑定 `PCR0`
- 当前 EIF 没有启用镜像签名，因此 `PCR8` 还是全 `0`，先不要写进策略
- `Resource` 先用 `"*"`，先把 attestation + KMS 路径跑通，后面再考虑收紧到指定 key

### `PCR0` 如何获取

必须使用最终 release 镜像对应的 EIF 来取值：

```bash
qt enclave make-img --docker-uri tee-wallet-enclave:v1 --eif /root/tee-wallet-enclave.eif
```

命令输出里会包含：

- `PCR0`
- `PCR8`

当前阶段只把 `PCR0` 写进策略。

注意：

- 重新 build enclave 镜像后，`PCR0` 可能变化
- 变化后需要同步更新 KMS policy
- 不要使用 debug 阶段随手构建出来的临时 PCR 值


## 1. 初始化 ECS

登录 ECS 后，先安装基础环境：

```bash
sudo -i
yum install -y git docker python3 python3-pip jq
systemctl enable --now docker
```

安装 QingTian 相关组件：

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

## 2. 上传仓库

如果代码已经在远端仓库中，可以直接拉取：

```bash
cd /root
git clone <your-repo-url> tee-wallet
cd tee-wallet
```

## 3. 构建 Enclave 镜像

基于当前 `wallet core v1` 代码构建 enclave 镜像：

```bash
docker build -f application/eth1/enclave/Dockerfile . -t tee-wallet-enclave:v1
qt enclave make-img --docker-uri tee-wallet-enclave:v1 --eif /root/tee-wallet-enclave.eif
ls -lh /root/tee-wallet-enclave.eif
```

这里必须把 **仓库根目录 `.`** 作为 build context，因为 enclave 镜像会同时使用：

- `application/eth1/enclave/`
- `third_party/huawei-qingtian/`

如果仍然用 `application/eth1` 作为 build context，Dockerfile 将看不到 vendored QingTian SDK 源码。

## 3.1 启动 `qt_proxy`

第二阶段的 KMS 路径固定使用 `qt_proxy`：

```bash
/usr/local/bin/qingtian/enclave/qt_proxy -l 8000 -a kms.ap-southeast-3.myhuaweicloud.com -p 443
```

建议把它做成独立 `systemd` 服务，并让 gateway 和 enclave 都依赖它先启动。

## 4. 启动 Enclave

第一次建议用 debug 模式启动，方便查看 console：

```bash
qt enclave start --cpus 2 --mem 2048 --eif /root/tee-wallet-enclave.eif --cid 16 --debug-mode
qt enclave query
qt enclave console --enclave-id 0
```

如果返回的 enclave ID 不是 `0`，后续命令里替换成实际值。

如果你频繁修改 enclave 代码，可以直接用仓库里的重建脚本代替手工 4 步：

```bash
cd /root/aws-nitro-enclave-blockchain-wallet
bash scripts/rebuild_eth1_qingtian_enclave.sh
```

可覆盖的环境变量：

- `IMAGE_TAG`
- `EIF_PATH`
- `ENCLAVE_CID`
- `ENCLAVE_CPU_COUNT`
- `ENCLAVE_MEMORY_MIB`
- `ENCLAVE_ID`
- `DEBUG_MODE`
- `NO_CACHE`

例如：

```bash
IMAGE_TAG=tee-wallet-enclave:v1 \
EIF_PATH=/root/tee-wallet-enclave.eif \
ENCLAVE_CID=16 \
ENCLAVE_CPU_COUNT=2 \
ENCLAVE_MEMORY_MIB=2048 \
DEBUG_MODE=1 \
bash scripts/rebuild_eth1_qingtian_enclave.sh
```

脚本默认使用 Docker cache。只有在你怀疑缓存脏了、改了系统依赖、更新了 `third_party/huawei-qingtian` 或需要强制全量重建时，才建议加：

```bash
NO_CACHE=1 bash scripts/rebuild_eth1_qingtian_enclave.sh
```

## 5. 启动宿主机 Gateway

debug 阶段先不要做 systemd，直接在宿主机上启动：

```bash
cd /root/aws-nitro-enclave-blockchain-wallet
PORT=8080 \
TEE_ENCLAVE_CID=16 \
TEE_VSOCK_PORT=5000 \
HWC_KMS_KEY_ID=32fd74c5-941e-46c1-9ffc-844f5e8286f7 \
HWC_KMS_ENDPOINT=kms.ap-southeast-3.myhuaweicloud.com \
HWC_PROJECT_ID=<your-project-id> \
HWC_KMS_ACCESS_KEY=<your-ak> \
HWC_KMS_SECRET_KEY=<your-sk> \
QT_PROXY_PORT=8000 \
WALLET_STORE_DIR=/var/lib/tee-wallet/wallets \
python3 application/eth1/server/app.py
```

如果你使用的是临时安全凭证，再额外补：

```bash
HWC_KMS_SECURITY_TOKEN=<your-security-token>
```

另开一个 shell，先做健康检查：

```bash
curl http://127.0.0.1:8080/health
```

预期结果：

```json
{"status":"ok"}
```

## 6. 验证钱包 API

创建钱包：

```bash
curl -s -X POST http://127.0.0.1:8080/wallets | jq
```

成功后，宿主机会在 `WALLET_STORE_DIR` 下生成 `<wallet_id>.json`。

查询钱包地址：

```bash
curl -s http://127.0.0.1:8080/wallets/<wallet_id>/address | jq
```

签名一笔 EIP-1559 风格交易：

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

读取当前 attestation 占位值：

```bash
curl -s http://127.0.0.1:8080/attestation | jq
```

## 7. 验证第二阶段的可恢复行为

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

它的测量口径是：

- 通过宿主机 HTTP gateway 调用 `POST /wallets/{wallet_id}/sign`
- 包含 HTTP + `AF_VSOCK` + enclave signing 的整体耗时
- 默认固定并发模型
- 默认预创建多个钱包，并让每个 worker 独占一个 wallet，自增自己的 `nonce`

一个常用示例：

```bash
cd /root/tee-wallet
python3 scripts/bench_eth1_sign.py \
  --base-url http://127.0.0.1:8080 \
  --concurrency 8 \
  --wallet-count 8 \
  --warmup-seconds 5 \
  --duration-seconds 15 \
  --timeout-seconds 10
```

如果想保存结构化结果：

```bash
python3 scripts/bench_eth1_sign.py \
  --concurrency 8 \
  --wallet-count 8 \
  --duration-seconds 15 \
  --report-json /tmp/eth1-bench.json
cat /tmp/eth1-bench.json | jq
```

输出重点包括：

- `tps`
- `total_requests`
- `successful_requests`
- `failed_requests`
- `latency_ms_avg`
- `latency_ms_p50`
- `latency_ms_p95`
- `latency_ms_p99`
- `error_breakdown`

如果压测中出现失败，脚本会保留统计结果，并以非零退出码结束，方便接到 CI 或自动化巡检里。

建议先从较小并发开始，例如 `4` 或 `8`，再逐步提升到 `16`、`32`，观察：

- TPS 是否继续线性增长
- `p95/p99` 是否明显抬高
- 是否出现 `timeout`、`http_error` 或 `network_error`

一次实际样例记录：

```bash
[root@ecs-tee-wallet-test aws-nitro-enclave-blockchain-wallet]# python3 scripts/bench_eth1_sign.py --base-url http://127.0.0.1:8080 --concurrency 8 --wallet-count 8 --duration-seconds 15
Benchmark configuration
base_url: http://127.0.0.1:8080
concurrency: 8
wallet_count: 8
warmup_seconds: 5.0
duration_seconds: 15.0
Benchmark results
total_requests: 2312
successful_requests: 2311
failed_requests: 1
elapsed_seconds: 15.167
tps: 152.374
latency_ms_avg: 51.993
latency_ms_p50: 45.446865
latency_ms_p95: 45.944895
latency_ms_p99: 46.670864
latency_ms_min: 7.908026
```

这组数据说明在 `8` 并发下，当前环境端到端签名吞吐大约在 `152 TPS`，中位延迟约 `45 ms`，但已经出现了 `1` 次失败请求。继续拉高并发前，建议先结合 gateway 和 enclave 日志定位失败原因。

## 下一步加固建议

- 把宿主机 gateway 做成 `systemd` 服务
- 把 attestation 占位值替换成真正的 QingTian quote 获取逻辑
- 把本地 `wallet record` 存储替换成 `CSMS` 或其他托管密文存储
- 增加恢复、恢复校验和签名策略控制

## Troubleshooting

### 1. `qt enclave -h` 报 `ModuleNotFoundError: No module named 'docker'`

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

### 2. `qt-enclave-env` 启动失败，`virtio-qtbox.ko` 无法加载

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

在这类场景里，仓库中的旧 kernel 反而可能和 QingTian 驱动包匹配。可以安装并切换到旧 kernel，例如 `5.10.0-60.18.0.50.r1141_59.hce2`：

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

如果状态是 `active (exited)` 且日志里能看到 hugepages 和 CPU reservation 成功，说明父机环境已经通了。

### 3. `qt enclave start` 成功，但 `qt enclave query` 立刻变成 `[]`

#### 3.1 当前阶段的结论

当前仓库里的 enclave 镜像已经按 QingTian 调试结论做了兼容处理：

- 不再让 `python3` 直接作为容器 `CMD`
- 改为先执行 `/app/start.sh`
- 再由 shell wrapper 启动 `python3 /app/server.py`
- enclave 运行时固定为 `Python 3.10`，避免 `web3==5.23.0` 在 `Python 3.11` 下触发 `inspect.getargspec` 导入错误
- 默认内置 `qingtian_kms_bridge`，由仓库内源码在 Docker 多阶段构建中编译，并直接调用官方 QingTian C SDK

如果后续你重写 Dockerfile，优先保留这个启动结构。

### 4. Docker build context 必须是仓库根目录

enclave 镜像现在不只是依赖 `application/eth1/enclave/`，还依赖：

- `third_party/huawei-qingtian/`

因此构建命令必须使用仓库根目录 `.` 作为 build context：

```bash
docker build -f application/eth1/enclave/Dockerfile . -t tee-wallet-enclave:v1
```

不能再用：

docker build -f application/eth1/enclave/Dockerfile application/eth1 -t tee-wallet-enclave:v1

否则 Dockerfile 看不到 vendored QingTian SDK 源码。

### 5. 不要在 Docker build 阶段联网拉取 huawei-qingtian

实际联调中，gitee.com 在 ECS/容器内访问不稳定，容易导致：

- git clone ... timed out

当前稳定方案是：

- 先把 huawei-qingtian 源码 vendoring 到仓库
- 只保留需要的最小目录：
    - third_party/huawei-qingtian/enclave/qtsm
    - third_party/huawei-qingtian/enclave/qtsm-sdk-c

这样做的好处：

- Docker build 不依赖外网
- 构建更可复现
- PCR0 更容易稳定

### 6. vendored qtsm 源码构建前要创建 output/ 目录

upstream third_party/huawei-qingtian/enclave/qtsm/lib/Makefile 会在构建时执行：

cp libqtsm.so ../output/

如果 output/ 目录不存在，会直接失败。

当前 Dockerfile 里已经通过下面的方式修复：

mkdir -p /opt/huawei-qingtian/enclave/qtsm/output

### 7. builder 和 runtime 必须统一发行版

曾经出现过：

/app/qingtian_kms_bridge: error while loading shared libraries: libcbor.so.0.8

根因是：

- builder 使用 ubuntu:22.04
- runtime 使用 Debian 系镜像

导致 bridge 编译时链接到的 libcbor.so.0.8 在 runtime 里找不到。

当前稳定方案：

- builder：ubuntu:22.04
- runtime：ubuntu:22.04

不要再混用 Ubuntu builder 和 Debian runtime。

### 8. host 当前使用静态 AK/SK，不再依赖 metadata

第二阶段联调里，ECS metadata 的 /openstack/latest/securitykey 返回过：

401 Unauthorized
Please configure Cloud Service Agency first

为了降低联调复杂度，当前 host gateway 已改成：

- 只使用静态配置的：
    - HWC_KMS_ACCESS_KEY
    - HWC_KMS_SECRET_KEY
    - HWC_KMS_SECURITY_TOKEN 可选
- 不再依赖 metadata 回退

### 9. createDataKey 生成的密文 DEK 必须走 decrypt-datakey

这是本轮最关键的一条 KMS 语义经验。

错误做法：

- 把 createDataKey 返回的密文 DEK 送到 decrypt-data

会导致 KMS 返回：

KMS.2203
Data key hash verification failed.

当前修复结论：

- 密文 DEK 必须走：
    - decrypt-datakey
- 不能误用：
    - decrypt-data

### 10. bridge stdout 可能混入日志，Python 侧不能直接 json.loads(stdout)

实际联调中，bridge 或 vendored QingTian SDK 可能向 stdout 打日志，例如：

unix socket listening...

如果 Python 侧直接：

json.loads(process.stdout)

就会报：

Expecting value: line 1 column 1 (char 0)

当前修复结论：

- Python 侧必须从 stdout 的最后一行向前查找合法 JSON
- 不能假设整个 stdout 都是纯 JSON

### 11. 当前稳定基线

截至今天，当前联调通过的稳定基线是：

- parent：C7t + QingTian Enclave + EulerOS 2.0
- enclave build：repo root context + vendored third_party/huawei-qingtian
- runtime：Ubuntu 22.04
- 启动方式：start.sh -> python3 /app/server.py
- KMS 通道：qt_proxy + qingtian_kms_bridge
- host 凭证：静态 HWC_KMS_ACCESS_KEY / HWC_KMS_SECRET_KEY
- KMS policy：先只绑定 PCR0
- enclave 重建：默认走缓存，必要时再 NO_CACHE=1

### 12. 当前推荐的一键重建方式

平时开发直接使用：

bash scripts/rebuild_eth1_qingtian_enclave.sh

只有在下面场景才建议强制全量重建：

- 改了 Dockerfile
- 改了系统依赖
- 改了 requirements.txt
- 更新了 third_party/huawei-qingtian
- 怀疑缓存脏了

命令：

NO_CACHE=1 bash scripts/rebuild_eth1_qingtian_enclave.sh


## 本地 TODO

- 将内存态 key registry 替换为外部加密存储或 sealed storage
- 增加钱包恢复和 restore 流程
- 增加基于策略的签名控制
