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

这是整个 repo 的主线示例，也就是“区块链私钥保存在 KMS 密文中，解密和签名发生在 enclave 内”。

Lambda 在 application/eth1/lambda/lambda_function.py 里处理 set_key 和 sign_transaction。
Parent EC2 上的 HTTPS 服务在 application/eth1/server/app.py，它会读 Secrets Manager、取 IMDS 凭证，然后通过 AF_VSOCK 把数据送进 enclave。
Enclave 内逻辑在 application/eth1/enclave/server.py，会调用 kmstool_enclave_cli 做 attested KMS decrypt，再用 web3.py 签名。
这是“私钥只在 enclave 内短暂明文出现”的核心实现。