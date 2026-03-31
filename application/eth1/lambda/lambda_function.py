import json
import os
from http import client


def get_env(name, default=None):
    return os.getenv(name, default)


def request_gateway(method, path, body=None):
    gateway_host = get_env("TEE_WALLET_HOST", "127.0.0.1")
    gateway_port = int(get_env("TEE_WALLET_PORT", "8080"))
    conn = client.HTTPConnection(gateway_host, gateway_port)
    payload = json.dumps(body) if body is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    conn.request(method, path, body=payload, headers=headers)
    response = conn.getresponse()
    response_raw = response.read()
    conn.close()
    return json.loads(response_raw)


def lambda_handler(event, context):
    operation = event.get("operation")

    if operation == "create_wallet":
        return request_gateway("POST", "/wallets")

    if operation == "get_address":
        wallet_id = event.get("wallet_id")
        if not wallet_id:
            raise RuntimeError("get_address requires wallet_id")
        return request_gateway("GET", f"/wallets/{wallet_id}/address")

    if operation == "sign_transaction":
        wallet_id = event.get("wallet_id")
        transaction_payload = event.get("transaction_payload")
        if not wallet_id or not transaction_payload:
            raise RuntimeError("sign_transaction requires wallet_id and transaction_payload")
        return request_gateway(
            "POST",
            f"/wallets/{wallet_id}/sign",
            {"transaction_payload": transaction_payload},
        )

    if operation == "get_attestation":
        return request_gateway("GET", "/attestation")

    if operation == "health":
        return request_gateway("GET", "/health")

    raise RuntimeError("operation: {} not supported right now".format(operation))
