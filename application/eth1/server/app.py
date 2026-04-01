import json
import logging
import os
import pathlib
import socket
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer


def get_env(name, default=None):
    return os.getenv(name, default)


class WalletRecordStore:
    def __init__(self, root_dir=None):
        self.root_dir = pathlib.Path(root_dir or get_env("WALLET_STORE_DIR", "/var/lib/tee-wallet/wallets"))

    def save(self, wallet_record):
        wallet_id = wallet_record["wallet_id"]
        self.root_dir.mkdir(parents=True, exist_ok=True)
        target_path = self.root_dir / f"{wallet_id}.json"
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.root_dir,
            delete=False,
        ) as temp_file:
            json.dump(wallet_record, temp_file)
            temp_file.write("\n")
            temp_path = pathlib.Path(temp_file.name)
        temp_path.replace(target_path)

    def load(self, wallet_id):
        target_path = self.root_dir / f"{wallet_id}.json"
        if not target_path.exists():
            raise FileNotFoundError(wallet_id)
        return json.loads(target_path.read_text(encoding="utf-8"))


class StaticCredentialProvider:
    def __init__(self, payload=None):
        self.payload = payload

    def get_credentials(self):
        payload = self.payload or {
            "access": get_env("HWC_KMS_ACCESS_KEY"),
            "secret": get_env("HWC_KMS_SECRET_KEY"),
            "securitytoken": get_env("HWC_KMS_SECURITY_TOKEN"),
            "expires_at": get_env("HWC_KMS_CREDENTIAL_EXPIRES_AT"),
        }
        return self._normalize_credentials(payload)

    def _normalize_credentials(self, payload):
        credentials = {
            "access": payload.get("access") or payload.get("access_key"),
            "secret": payload.get("secret") or payload.get("secret_key"),
            "securitytoken": payload.get("securitytoken") or payload.get("security_token"),
            "expires_at": payload.get("expires_at") or payload.get("expires"),
        }
        required_fields = ("access", "secret")
        missing_fields = [field for field in required_fields if not credentials.get(field)]
        if missing_fields:
            raise ValueError(
                "static credentials missing required fields: {}".format(", ".join(sorted(missing_fields)))
            )
        return credentials


def call_enclave(payload, cid=16, port=5000):
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.connect((cid, port))
    s.send(str.encode(json.dumps(payload)))
    payload_processed = s.recv(4096).decode()
    s.close()
    return json.loads(payload_processed)


def get_kms_config():
    return {
        "key_id": get_env("HWC_KMS_KEY_ID"),
        "endpoint": get_env("HWC_KMS_ENDPOINT"),
        "project_id": get_env("HWC_PROJECT_ID"),
        "proxy_port": int(get_env("QT_PROXY_PORT", "8000")),
    }


def error_status(response):
    if response.get("error") == "wallet_not_found":
        return 404
    if response.get("error") == "invalid_request":
        return 400
    return 500


def route_request(
    method,
    path,
    body,
    enclave_client=call_enclave,
    credential_provider=None,
    wallet_record_store=None,
):
    enclave_cid = int(get_env("TEE_ENCLAVE_CID", "16"))
    enclave_port = int(get_env("TEE_VSOCK_PORT", "5000"))
    credential_provider = credential_provider or StaticCredentialProvider()
    wallet_record_store = wallet_record_store or WalletRecordStore()

    if method == "GET" and path == "/health":
        return 200, {"status": "ok"}

    if method == "GET" and path == "/attestation":
        return 200, enclave_client({"action": "get_attestation"}, cid=enclave_cid, port=enclave_port)

    if method == "POST" and path == "/wallets":
        credentials = credential_provider.get_credentials()
        response = enclave_client(
            {"action": "create_wallet", "credentials": credentials, "kms_config": get_kms_config()},
            cid=enclave_cid,
            port=enclave_port,
        )
        if response.get("status") == "error":
            return error_status(response), response
        wallet_record_store.save(response["wallet_record"])
        return 201, {"wallet_id": response["wallet_id"], "address": response["address"]}

    parts = [segment for segment in path.split("/") if segment]
    if len(parts) == 3 and parts[0] == "wallets" and parts[2] == "address" and method == "GET":
        try:
            wallet_record = wallet_record_store.load(parts[1])
        except FileNotFoundError:
            return 404, {"status": "error", "error": "wallet_not_found", "wallet_id": parts[1]}
        return 200, {"wallet_id": parts[1], "address": wallet_record["address"]}

    if len(parts) == 3 and parts[0] == "wallets" and parts[2] == "sign" and method == "POST":
        transaction_payload = body.get("transaction_payload") if isinstance(body, dict) else None
        if not transaction_payload:
            return 400, {
                "status": "error",
                "error": "invalid_request",
                "message": "transaction_payload is required",
            }
        try:
            wallet_record = wallet_record_store.load(parts[1])
        except FileNotFoundError:
            return 404, {"status": "error", "error": "wallet_not_found", "wallet_id": parts[1]}
        credentials = credential_provider.get_credentials()
        response = enclave_client(
            {
                "action": "sign_transaction",
                "wallet_id": parts[1],
                "wallet_record": wallet_record,
                "transaction_payload": transaction_payload,
                "credentials": credentials,
                "kms_config": get_kms_config(),
            },
            cid=enclave_cid,
            port=enclave_port,
        )
        if response.get("status") == "error":
            return error_status(response), response
        return 200, response

    return 404, {"status": "error", "error": "not_found", "path": path}


class S(BaseHTTPRequestHandler):
    def _set_response(self, http_status=200):
        self.send_response(http_status)
        self.send_header("Content-type", "application/json")
        self.end_headers()

    def _read_body(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return None
        raw_body = self.rfile.read(content_length).decode("utf-8")
        return json.loads(raw_body)

    def do_GET(self):
        status, response = route_request("GET", self.path, None)
        self._set_response(status)
        self.wfile.write(str.encode(json.dumps(response)))

    def do_POST(self):
        body = self._read_body()
        logging.info("POST request path=%s body=%s", self.path, body)
        status, response = route_request("POST", self.path, body)
        self._set_response(status)
        self.wfile.write(str.encode(json.dumps(response)))


def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ("0.0.0.0", port)
    httpd = server_class(server_address, handler_class)
    logging.info("Starting local HTTP gateway on port %s", port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info("Stopping local HTTP gateway")


if __name__ == "__main__":
    run(port=int(get_env("PORT", "8080")))
