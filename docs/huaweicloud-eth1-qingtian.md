# 华为云 QingTian `eth1` Wallet Core v1 部署手册

本文档说明当前仓库中 `eth1` 的运行路径，以及如何在华为云上一步一步部署并验证这个 TEE wallet core v1。

## 运行组件

- `application/eth1/server/app.py`
  宿主机本地 HTTP gateway，对外暴露钱包 API，并通过 `AF_VSOCK` 转发请求。
- `application/eth1/enclave/server.py`
  TEE 内的钱包内核，负责内存态 key registry、创建钱包、查询地址、签名交易和导出 attestation。
- `application/eth1/lambda/lambda_function.py`
  兼容性测试客户端，只是把请求转发给本地 gateway，不属于核心运行链路。

## 对外 API

- `POST /wallets`
- `GET /wallets/{wallet_id}/address`
- `POST /wallets/{wallet_id}/sign`
- `GET /attestation`
- `GET /health`

## 当前行为

- 私钥在 enclave 内生成。
- 私钥在 v1 中只保存在 enclave 进程内存。
- enclave 重启后，所有钱包都会丢失，这是 v1 的预期行为。
- 宿主机 gateway 不接触私钥，也不接触密文密钥材料。

## 前置条件

- 一个已开通 `QingTian Enclave` 能力的华为云账号。
- 一个支持 QingTian Enclave 的 Linux ECS 规格，推荐 `C7t` 或 `kC2`。
- 父机至少 `8 vCPU / 16 GiB`。
- 一个用于 SSH 登录的 key pair。
- 一个绑定到 ECS 的 EIP。

推荐购买参数：

- 区域：选择你账号当前支持 QingTian Enclave 的区域。
- 镜像：`Huawei Cloud EulerOS 2.0`
- 登录方式：`Key pair`
- 安全组：
  - `22/tcp` 仅放行你自己的公网 IP
  - `8080/tcp` 建议不要直接公网开放，优先使用 SSH 隧道测试

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
docker build -f application/eth1/enclave/Dockerfile application/eth1 -t tee-wallet-enclave:v1
qt enclave make-img --docker-uri tee-wallet-enclave:v1 --eif /root/tee-wallet-enclave.eif
ls -lh /root/tee-wallet-enclave.eif
```

当前仓库里的 enclave 镜像已经按 QingTian 调试结论做了兼容处理：

- 不再让 `python3` 直接作为容器 `CMD`
- 改为先执行 `/app/start.sh`
- 再由 shell wrapper 启动 `python3 /app/server.py`
- enclave 运行时固定为 `Python 3.10`，避免 `web3==5.23.0` 在 `Python 3.11` 下触发 `inspect.getargspec` 导入错误

如果后续你重写 Dockerfile，优先保留这个启动结构。

## 4. 启动 Enclave

第一次建议用 debug 模式启动，方便查看 console：

```bash
qt enclave start --cpus 2 --mem 2048 --eif /root/tee-wallet-enclave.eif --cid 16 --debug-mode
qt enclave query
qt enclave console --enclave-id 0
```

如果返回的 enclave ID 不是 `0`，后续命令里替换成实际值。

## 5. 启动宿主机 Gateway

第一轮先不要做 systemd，直接在宿主机上启动：

```bash
cd /root/tee-wallet
PORT=8080 TEE_ENCLAVE_CID=16 TEE_VSOCK_PORT=5000 python3 application/eth1/server/app.py
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

## 7. 验证 v1 的内存态行为

重启 enclave：

```bash
qt enclave stop --enclave-id 0
qt enclave start --cpus 2 --mem 2048 --eif /root/tee-wallet-enclave.eif --cid 16 --debug-mode
```

再次查询之前的钱包：

```bash
curl -s http://127.0.0.1:8080/wallets/<old_wallet_id>/address | jq
```

预期钱包不存在。这说明当前实现确实是“只保存在 enclave 内存中”，符合 v1 设计。

## 下一步加固建议

- 把宿主机 gateway 做成 `systemd` 服务
- 把 attestation 占位值替换成真正的 QingTian quote 获取逻辑
- 引入外部加密存储或 sealed storage
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

这说明 EIF 已经被拉起，但 enclave 内的用户进程一启动就退出了。

先看最新日志：

```bash
tail -n 120 /var/log/qingtian_enclaves/qingtian-tool.log
```

如果日志里出现：

- `get heart beat from enclave`
- `enclave start successfully`
- 随后紧跟 `handle_enclave_exit`

说明不是 `qt-enclave-env`、EIF 加载或资源隔离问题，而是 enclave guest 已经起来，但 guest 里的用户进程很快退出。

此时先排除旧镜像 tag 和应用入口本身：

```bash
docker run --rm tee-wallet-enclave:v1
docker run --rm tee-wallet-enclave:v1 python3 /app/server.py
```

如果在普通 Docker 里进程能正常阻塞，但在 enclave 里仍然秒退，就继续做两个最小实验。

实验 A：纯存活容器

```bash
cat > /root/Dockerfile.sleep <<'EOF'
FROM python:3.11-slim
CMD ["python3", "-c", "import time; print('sleep-enclave-started', flush=True); time.sleep(600)"]
EOF

docker build -f /root/Dockerfile.sleep /root -t enclave-sleep:v1
qt enclave make-img --docker-uri enclave-sleep:v1 --eif /root/enclave-sleep.eif
qt enclave start --cpus 2 --mem 1024 --eif /root/enclave-sleep.eif --cid 16 --debug-mode
sleep 2
qt enclave query
```

实验 B：更小的 `busybox` 存活镜像

```bash
cat > /root/Dockerfile.busybox <<'EOF'
FROM busybox:1.36
CMD ["sh", "-c", "echo busybox-enclave-started; sleep 600"]
EOF

docker build -f /root/Dockerfile.busybox /root -t enclave-busybox:v1
qt enclave make-img --docker-uri enclave-busybox:v1 --eif /root/enclave-busybox.eif
qt enclave start --cpus 2 --mem 1024 --eif /root/enclave-busybox.eif --cid 16 --debug-mode
sleep 2
qt enclave query
```

当前这台机器的实际排查结论已经可以明确写死：

- `tee-wallet-enclave:v1` 在普通 Docker 里能正常阻塞，不是镜像入口脚本本身有语法错误
- `enclave-sleep:v1` 在 QingTian Enclave 内也会秒退
- `enclave-busybox:v1` 在 QingTian Enclave 内同样秒退
- 最新日志仍然是：
  - `get heart beat from enclave`
  - `enclave start successfully`
  - 紧接着 `handle_enclave_exit`

这意味着当前问题已经排除：

- 当前 `eth1` 应用代码问题
- Python 运行时本身的问题
- `AF_VSOCK` 监听逻辑的问题

故障边界已经收敛到 `QingTian guest/runtime 层`，而不是 `wallet core` 应用层。

后续继续细化后，已经额外确认了一点：

- 官方 `ubuntu + hello_enclave.sh` 可以稳定运行
- `python3` 直接作为容器 `CMD` 时，镜像会在 QingTian 内秒退
- 通过 shell wrapper 启动 `python3` 可以正常运行

因此当前仓库里的 `application/eth1/enclave/Dockerfile` 已经切换为 `start.sh -> python3 /app/server.py` 的启动方式，这不是风格调整，而是当前 QingTian 环境下的兼容性修复。

可以按下面的故障树继续排查。

#### 3.1 已排除项

- 父机规格错误：已确认是 `c7t.xlarge.4`
- 镜像错误：已确认是 `Huawei Cloud EulerOS 2.0 标准版 64位`
- 可信系统未开启：已确认 `Enclave` 已开启
- `qt` CLI 缺 Python 依赖：已修复
- `qt-enclave-env` 未正常工作：已通过切换到兼容 kernel 后恢复
- 业务镜像自身无法启动：普通 Docker 已验证可运行
- Python 专属兼容问题：`busybox` 同样秒退，已排除

#### 3.2 当前最可能的原因

在 `busybox` 也秒退后，优先级最高的怀疑对象只剩这些：

1. `QingTian guest runtime` 与当前父机上的某个组件版本仍不兼容
2. `qt enclave make-img` 生成的 EIF 对某些用户态镜像有额外约束，但日志没有把退出原因透出来
3. 当前 `virtio-qtbox / qt-enclave-bootstrap / qingtian-tool` 组合虽然能让 parent 成功拉起 guest，但 guest 内用户态进程会异常退出
4. 需要华为云侧提供更细粒度的 guest console / sandbox 日志，当前 `qingtian-tool.log` 只看到 guest exit 事件，看不到用户态崩溃原因

#### 3.3 建议的系统化排查顺序

第一步，固定证据，避免继续猜：

```bash
uname -r
rpm -qa | grep -Ei 'qingtian|qtbox|enclave'
qt enclave query
tail -n 200 /var/log/qingtian_enclaves/qingtian-tool.log
```

第二步，继续搜 guest 侧日志位置，而不是只看 `qingtian-tool.log`：

```bash
find /var/log -maxdepth 4 | grep -i qingtian
find /var/log -maxdepth 4 | grep -i enclave
find /var/run -maxdepth 4 | grep -i enclave
```

第三步，确认是否存在更细粒度的 kernel / virtualization 报错：

```bash
dmesg -T | tail -n 200
journalctl -k --no-pager | tail -n 200
```

第四步，检查当前安装包是否有更高版本或配套说明：

```bash
yum list installed | grep -Ei 'qingtian|qtbox|enclave'
yum list available --showduplicates | grep -Ei 'qingtian|qtbox|enclave'
rpm -qi virtio-qtbox
rpm -qi qingtian-tool
rpm -qi qt-enclave-bootstrap
```

第五步，如果以上仍无法看到 guest 用户态退出原因，建议直接向华为云提交工单，并附上以下最小复现实验：

- 机器规格：`c7t.xlarge.4`
- 镜像：`Huawei Cloud EulerOS 2.0 标准版 64位`
- 可信系统：`Enclave`
- 当前兼容 kernel：`5.10.0-60.18.0.50.r1141_59.hce2`
- `qt-enclave-env` 已成功
- 最小 `python sleep` 镜像会秒退
- 最小 `busybox sleep` 镜像也会秒退
- `qingtian-tool.log` 中 guest 已 ready，但立即 `handle_enclave_exit`

这组证据足以说明问题不在业务代码，而在 QingTian runtime/guest 侧，需要云厂商提供更底层日志或兼容性结论。

#### 3.4 当前阶段的结论

截至目前，这条链路的状态应该这样理解：

- `parent instance` 已经通了
- `QingTian resource allocator` 已经通了
- `EIF` 能成功生成并被加载
- `guest heartbeat` 能成功上报
- 但 `guest user process` 会立即退出

所以当前阻塞点不是 “如何部署 `eth1`”，而是 “为什么任何最小用户态进程在当前 QingTian guest 里都会退出”。
在这个问题被解开前，不建议继续调整 `application/eth1` 代码。

## 本地 TODO

- 将内存态 key registry 替换为外部加密存储或 sealed storage
- 增加钱包恢复和 restore 流程
- 增加基于策略的签名控制
