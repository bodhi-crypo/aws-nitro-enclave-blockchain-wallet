FROM ubuntu:22.04 AS bridge-builder

ARG QINGTIAN_REPO_COMMIT=516a3f4531d0ff6cbde6e19764fb6319650b9fc5

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
      git \
      make \
      gcc \
      pkg-config \
      libglib2.0-dev \
      libcurl4-openssl-dev \
      libssl-dev \
      libjson-c-dev \
      libcbor-dev \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Build this image from the repository root as the Docker build context.
COPY ./third_party/huawei-qingtian /opt/huawei-qingtian
WORKDIR /opt/huawei-qingtian/enclave/qtsm/lib
RUN mkdir -p /opt/huawei-qingtian/enclave/qtsm/output && \
    make && \
    cp libqtsm.so /usr/local/lib/libqtsm.so

WORKDIR /opt/build-src
COPY ./application/eth1/enclave/qingtian_kms_bridge.c ./qingtian_kms_bridge.c
COPY ./application/eth1/enclave/Makefile.qingtian_kms_bridge ./Makefile.qingtian_kms_bridge
RUN make -f Makefile.qingtian_kms_bridge QINGTIAN_SRC=/opt/huawei-qingtian OUTPUT_DIR=/opt/build

FROM ubuntu:22.04 AS runtime

WORKDIR /app

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
      python3.10 \
      python3-pip \
      libglib2.0-0 \
      libcurl4 \
      libssl3 \
      libjson-c5 \
      libcbor0.8 && \
    rm -rf /var/lib/apt/lists/*

# Build this image from the repository root as the Docker build context.
COPY ./application/eth1/enclave/requirements.txt ./requirements.txt
RUN python3 -m pip install -r /app/requirements.txt

COPY --from=bridge-builder /usr/local/lib/libqtsm.so /usr/local/lib/libqtsm.so
COPY --from=bridge-builder /opt/build/qingtian_kms_bridge /app/qingtian_kms_bridge
COPY ./application/eth1/enclave/server.py ./server.py
COPY ./application/eth1/enclave/start.sh ./start.sh

ENV HWC_KMS_BRIDGE_CMD="/app/qingtian_kms_bridge"
ENV LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}"

RUN chmod +x /app/start.sh /app/qingtian_kms_bridge

CMD ["/app/start.sh"]
