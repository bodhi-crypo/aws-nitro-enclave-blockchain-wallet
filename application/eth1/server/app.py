import json
import logging
import os
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer


def get_env(name, default=None):
    return os.getenv(name, default)


def call_enclave(payload, cid=16, port=5000):
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.connect((cid, port))
    s.send(str.encode(json.dumps(payload)))
    payload_processed = s.recv(4096).decode()
    s.close()
    return json.loads(payload_processed)


def route_request(method, path, body, enclave_client=call_enclave):
    enclave_cid = int(get_env("TEE_ENCLAVE_CID", "16"))
    enclave_port = int(get_env("TEE_VSOCK_PORT", "5000"))

    if method == "GET" and path == "/health":
        return 200, {"status": "ok"}

    if method == "GET" and path == "/attestation":
        return 200, enclave_client({"action": "get_attestation"}, cid=enclave_cid, port=enclave_port)

    if method == "POST" and path == "/wallets":
        return 201, enclave_client({"action": "create_wallet"}, cid=enclave_cid, port=enclave_port)

    parts = [segment for segment in path.split("/") if segment]
    if len(parts) == 3 and parts[0] == "wallets" and parts[2] == "address" and method == "GET":
        return 200, enclave_client(
            {"action": "get_address", "wallet_id": parts[1]},
            cid=enclave_cid,
            port=enclave_port,
        )

    if len(parts) == 3 and parts[0] == "wallets" and parts[2] == "sign" and method == "POST":
        transaction_payload = body.get("transaction_payload") if isinstance(body, dict) else None
        if not transaction_payload:
            return 400, {
                "status": "error",
                "error": "invalid_request",
                "message": "transaction_payload is required",
            }
        return 200, enclave_client(
            {
                "action": "sign_transaction",
                "wallet_id": parts[1],
                "transaction_payload": transaction_payload,
            },
            cid=enclave_cid,
            port=enclave_port,
        )

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
