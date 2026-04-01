#!/bin/sh
set -eu

ENCLAVE_LOG_DIR="${ENCLAVE_LOG_DIR:-/var/log/tee-wallet}"
LOG_FILE="${ENCLAVE_LOG_FILE:-$ENCLAVE_LOG_DIR/service.log}"

mkdir -p "$ENCLAVE_LOG_DIR"
exec >>"$LOG_FILE" 2>&1

echo "Starting TEE wallet core wrapper..."
python3 /app/server.py
