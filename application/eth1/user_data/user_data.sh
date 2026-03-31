#!/bin/bash

exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1

set -x
set -euo pipefail

usermod -aG docker ecs-user || true

yum install -y docker jq git
systemctl enable --now docker

# QingTian Enclave runtime bootstrap. Package names and service names can vary by image version.
yum install -y qt-enclave-bootstrap virtio-qtbox qingtian-tools || true
systemctl enable --now qt-enclave-env || true

mkdir -p /home/ecs-user/app/eth1
cd /home/ecs-user/app/eth1

cat <<'EOF' >/home/ecs-user/app/eth1/build_qingtian_images.sh
#!/bin/bash
set -euo pipefail

docker pull ${__SIGNING_SERVER_IMAGE_URI__}
docker pull ${__SIGNING_ENCLAVE_IMAGE_URI__}

# The Huawei Cloud QingTian CLI expects the enclave image to be packaged before start.
qt enclave make-img \
  --docker-uri ${__SIGNING_ENCLAVE_IMAGE_URI__} \
  --output-file /home/ecs-user/app/eth1/signing_server.eif
EOF

chmod +x /home/ecs-user/app/eth1/build_qingtian_images.sh
sudo -H -u ecs-user bash -c "/home/ecs-user/app/eth1/build_qingtian_images.sh"

cat <<'EOF' >/etc/systemd/system/qingtian-signing-server.service
[Unit]
Description=QingTian TEE Wallet Core
After=network-online.target docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/home/ecs-user/app/eth1/start_qingtian_enclave.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

cat <<'EOF' >/home/ecs-user/app/eth1/start_qingtian_enclave.sh
#!/bin/bash
set -euo pipefail

qt enclave stop --name signing_server || true
qt enclave start \
  --name signing_server \
  --image /home/ecs-user/app/eth1/signing_server.eif \
  --cid 16 \
  --memory 4096 \
  --cpu-count 2
EOF

chmod +x /home/ecs-user/app/eth1/start_qingtian_enclave.sh
systemctl enable --now qingtian-signing-server.service

docker run -d \
  --restart unless-stopped \
  --name qingtian_wallet_gateway \
  -p 8080:8080 \
  ${__SIGNING_SERVER_IMAGE_URI__}
