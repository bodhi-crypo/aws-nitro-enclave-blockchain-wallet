#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE_TAG="${IMAGE_TAG:-tee-wallet-enclave:v1}"
EIF_PATH="${EIF_PATH:-/root/tee-wallet-enclave.eif}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
ENCLAVE_CPU_COUNT="${ENCLAVE_CPU_COUNT:-2}"
ENCLAVE_MEMORY_MIB="${ENCLAVE_MEMORY_MIB:-2048}"
ENCLAVE_ID="${ENCLAVE_ID:-0}"
DEBUG_MODE="${DEBUG_MODE:-1}"
NO_CACHE="${NO_CACHE:-0}"

cd "${REPO_ROOT}"

echo "[1/4] Building enclave image: ${IMAGE_TAG}"
DOCKER_BUILD_ARGS=(-f application/eth1/enclave/Dockerfile . -t "${IMAGE_TAG}")
if [[ "${NO_CACHE}" == "1" ]]; then
  DOCKER_BUILD_ARGS=(--no-cache "${DOCKER_BUILD_ARGS[@]}")
  echo "Docker cache: disabled"
else
  echo "Docker cache: enabled"
fi
docker build "${DOCKER_BUILD_ARGS[@]}"

echo "[2/4] Packaging EIF: ${EIF_PATH}"
qt enclave make-img --docker-uri "${IMAGE_TAG}" --eif "${EIF_PATH}"

echo "[3/4] Stopping existing enclave id=${ENCLAVE_ID} if present"
qt enclave stop --enclave-id "${ENCLAVE_ID}" || true

echo "[4/4] Starting enclave"
START_ARGS=(
  --cpus "${ENCLAVE_CPU_COUNT}"
  --mem "${ENCLAVE_MEMORY_MIB}"
  --eif "${EIF_PATH}"
  --cid "${ENCLAVE_CID}"
)

if [[ "${DEBUG_MODE}" == "1" ]]; then
  START_ARGS+=(--debug-mode)
fi

qt enclave start "${START_ARGS[@]}"

echo
echo "Enclave rebuild complete."
echo "Image tag : ${IMAGE_TAG}"
echo "EIF path  : ${EIF_PATH}"
echo "CID       : ${ENCLAVE_CID}"
echo "CPU count : ${ENCLAVE_CPU_COUNT}"
echo "MemoryMiB : ${ENCLAVE_MEMORY_MIB}"
echo "Debug     : ${DEBUG_MODE}"
echo "No cache  : ${NO_CACHE}"
