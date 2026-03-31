import json
import os
import socket
import uuid


class WalletNotFoundError(Exception):
    def __init__(self, wallet_id):
        self.wallet_id = wallet_id
        super().__init__(wallet_id)


class Web3WalletBackend:
    def create_account(self):
        from web3 import Account

        account = Account.create()
        private_key = getattr(account, "key", None) or getattr(account, "privateKey")
        if isinstance(private_key, bytes):
            private_key = private_key.hex()
        return {"private_key": private_key, "address": account.address}

    def sign_transaction(self, transaction_payload, private_key):
        import web3
        from web3.auto import w3

        tx = dict(transaction_payload)
        if "value" in tx and isinstance(tx["value"], str):
            tx["value"] = web3.Web3.toWei(tx["value"], "ether")
        transaction_signed = w3.eth.account.sign_transaction(tx, private_key)
        return {
            "signed_tx": transaction_signed.rawTransaction.hex(),
            "tx_hash": transaction_signed.hash.hex(),
        }


def default_attestation_provider():
    return {
        "quote": os.getenv("QINGTIAN_ATTESTATION_QUOTE", "quote-unavailable"),
        "measurement": os.getenv(
            "QINGTIAN_ATTESTATION_MEASUREMENT", "measurement-unavailable"
        ),
    }


def get_wallet_store(wallet_store=None):
    return wallet_store if wallet_store is not None else WALLET_STORE


def get_wallet_backend(wallet_backend=None):
    return wallet_backend if wallet_backend is not None else Web3WalletBackend()


def create_wallet(wallet_store=None, wallet_backend=None, wallet_id_factory=None):
    wallet_store = get_wallet_store(wallet_store)
    wallet_backend = get_wallet_backend(wallet_backend)
    wallet_id_factory = wallet_id_factory or (lambda: str(uuid.uuid4()))

    account = wallet_backend.create_account()
    wallet_id = wallet_id_factory()
    wallet_store[wallet_id] = account
    return {"wallet_id": wallet_id, "address": account["address"]}


def get_wallet_entry(wallet_id, wallet_store=None):
    wallet_store = get_wallet_store(wallet_store)
    entry = wallet_store.get(wallet_id)
    if not entry:
        raise WalletNotFoundError(wallet_id)
    return entry


def get_address(wallet_id, wallet_store=None):
    entry = get_wallet_entry(wallet_id, wallet_store=wallet_store)
    return {"wallet_id": wallet_id, "address": entry["address"]}


def sign_transaction(
    wallet_id, transaction_payload, wallet_store=None, wallet_backend=None
):
    validate_transaction_payload(transaction_payload)

    entry = get_wallet_entry(wallet_id, wallet_store=wallet_store)
    wallet_backend = get_wallet_backend(wallet_backend)
    signed = wallet_backend.sign_transaction(transaction_payload, entry["private_key"])
    return {"wallet_id": wallet_id, **signed}


def get_attestation(attestation_provider=None):
    provider = attestation_provider or default_attestation_provider
    return provider()


def validate_transaction_payload(transaction_payload):
    if not isinstance(transaction_payload, dict):
        raise ValueError("transaction_payload must be a JSON object")

    required_fields = ("chainId", "gas", "nonce")
    missing_fields = [field for field in required_fields if field not in transaction_payload]
    if missing_fields:
        raise ValueError(
            "transaction_payload missing required fields: {}".format(
                ", ".join(sorted(missing_fields))
            )
        )


def process_request(
    request,
    wallet_store=None,
    wallet_backend=None,
    attestation_provider=None,
    wallet_id_factory=None,
):
    action = request.get("action")

    try:
        if action == "create_wallet":
            return create_wallet(
                wallet_store=wallet_store,
                wallet_backend=wallet_backend,
                wallet_id_factory=wallet_id_factory,
            )
        if action == "get_address":
            return get_address(request["wallet_id"], wallet_store=wallet_store)
        if action == "sign_transaction":
            return sign_transaction(
                request["wallet_id"],
                request["transaction_payload"],
                wallet_store=wallet_store,
                wallet_backend=wallet_backend,
            )
        if action == "get_attestation":
            return get_attestation(attestation_provider=attestation_provider)
        if action == "health":
            return {"status": "ok"}
        return {"status": "error", "error": "unsupported_action", "action": action}
    except WalletNotFoundError as exc:
        return {
            "status": "error",
            "error": "wallet_not_found",
            "wallet_id": exc.wallet_id,
        }
    except (KeyError, ValueError) as exc:
        return {"status": "error", "error": "invalid_request", "message": str(exc)}
    except Exception as exc:
        return {"status": "error", "error": "internal_error", "message": str(exc)}


def main():
    print("Starting TEE wallet core...")

    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    cid = socket.VMADDR_CID_ANY
    port = int(os.getenv("TEE_VSOCK_PORT", "5000"))
    s.bind((cid, port))
    s.listen()

    while True:
        c, _addr = s.accept()
        payload = c.recv(4096)
        payload_json = json.loads(payload.decode())
        response_plaintext = process_request(payload_json)
        c.send(str.encode(json.dumps(response_plaintext)))
        c.close()


WALLET_STORE = {}


if __name__ == "__main__":
    main()
