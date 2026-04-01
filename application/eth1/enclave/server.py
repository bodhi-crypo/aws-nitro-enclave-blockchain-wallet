import base64
import json
import os
import shlex
import socket
import subprocess
import time
import uuid
from collections import OrderedDict


class WalletNotFoundError(Exception):
    def __init__(self, wallet_id):
        self.wallet_id = wallet_id
        super().__init__(wallet_id)


class WalletRecordError(ValueError):
    pass


class PersistentHelperSession:
    def __init__(self, helper_command):
        self.helper_command = helper_command
        self.process = None

    def request(self, payload):
        last_error = None
        for _ in range(2):
            self._ensure_process()
            try:
                self.process.stdin.write(json.dumps(payload) + "\n")
                self.process.stdin.flush()
                return self._read_response()
            except (BrokenPipeError, OSError, RuntimeError) as exc:
                last_error = exc
                self.close()
        raise RuntimeError(f"KMS helper failed: {last_error}")

    def close(self):
        if self.process is None:
            return
        try:
            if self.process.stdin is not None:
                self.process.stdin.close()
        except Exception:
            pass
        try:
            self.process.terminate()
            self.process.wait(timeout=1)
        except Exception:
            try:
                self.process.kill()
            except Exception:
                pass
        self.process = None

    def _ensure_process(self):
        if self.process is not None and self.process.poll() is None:
            return
        self.process = subprocess.Popen(
            shlex.split(self.helper_command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

    def _read_response(self):
        lines = []
        while True:
            line = self.process.stdout.readline()
            if line == "":
                raise RuntimeError("KMS helper exited before returning a response")
            lines.append(line)
            try:
                return parse_helper_json_output("".join(lines))
            except ValueError:
                continue


class TimedDekCache:
    def __init__(self, max_entries=256, ttl_seconds=60, time_fn=None):
        self.max_entries = max(0, int(max_entries))
        self.ttl_seconds = max(0, int(ttl_seconds))
        self.time_fn = time_fn or time.monotonic
        self.entries = OrderedDict()

    def get(self, key):
        if not self.is_enabled():
            return None
        entry = self.entries.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if self.time_fn() >= expires_at:
            self.entries.pop(key, None)
            return None
        self.entries.move_to_end(key)
        return value

    def set(self, key, value):
        if not self.is_enabled():
            return
        expires_at = self.time_fn() + self.ttl_seconds
        self.entries[key] = (expires_at, value)
        self.entries.move_to_end(key)
        while len(self.entries) > self.max_entries:
            self.entries.popitem(last=False)

    def is_enabled(self):
        return self.max_entries > 0 and self.ttl_seconds > 0


class Web3WalletBackend:
    def create_account(self):
        from web3 import Account

        account = Account.create()
        private_key = getattr(account, "key", None) or getattr(account, "privateKey")
        if isinstance(private_key, bytes):
            private_key = private_key.hex()
        return {"private_key": private_key, "address": account.address}

    def account_from_private_key(self, private_key):
        from web3 import Account

        normalized_private_key = normalize_private_key(private_key)
        account_factory = getattr(Account, "from_key", None)
        if account_factory is not None:
            account = account_factory(bytes.fromhex(normalized_private_key))
        else:
            account = Account.privateKeyToAccount(bytes.fromhex(normalized_private_key))

        return {"private_key": normalized_private_key, "address": account.address}

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


class AesGcmWalletRecordCrypto:
    def encrypt_private_key(self, private_key, plaintext_data_key):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        data_key = ensure_bytes(plaintext_data_key, "plaintext_data_key")
        if len(data_key) != 32:
            raise ValueError("plaintext_data_key must be 32 bytes")

        normalized_private_key = normalize_private_key(private_key)
        nonce = os.urandom(12)
        encrypted = AESGCM(data_key).encrypt(nonce, normalized_private_key.encode("utf-8"), None)

        return {
            "encrypted_private_key": encode_base64(encrypted[:-16]),
            "nonce": encode_base64(nonce),
            "tag": encode_base64(encrypted[-16:]),
        }

    def decrypt_private_key(self, wallet_record, plaintext_data_key):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        data_key = ensure_bytes(plaintext_data_key, "plaintext_data_key")
        if len(data_key) != 32:
            raise ValueError("plaintext_data_key must be 32 bytes")

        validated_record = validate_wallet_record(wallet_record)
        encrypted_private_key = decode_base64(validated_record["encrypted_private_key"], "encrypted_private_key")
        nonce = decode_base64(validated_record["nonce"], "nonce")
        tag = decode_base64(validated_record["tag"], "tag")
        plaintext = AESGCM(data_key).decrypt(nonce, encrypted_private_key + tag, None)
        return normalize_private_key(plaintext.decode("utf-8"))


class HuaweiKmsClient:
    def __init__(self, credentials, kms_config, helper_command=None):
        self.credentials = validate_credentials(credentials)
        self.kms_config = validate_kms_config(kms_config)
        self.helper_command = helper_command or os.getenv("HWC_KMS_BRIDGE_CMD")
        if not self.helper_command:
            raise RuntimeError("HWC_KMS_BRIDGE_CMD is not configured")

    def generate_random(self, num_bytes):
        response = self._run("generate_random", {"num_bytes": num_bytes})
        return decode_base64(response["random"], "random")

    def create_data_key(self):
        response = self._run("create_data_key", {})
        return {
            "plaintext": decode_base64(response["plaintext"], "plaintext"),
            "ciphertext": response["ciphertext"],
        }

    def decrypt_data_key(self, encrypted_data_key):
        response = self._run("decrypt_data_key", {"ciphertext": encrypted_data_key})
        return decode_base64(response["plaintext"], "plaintext")

    def _run(self, action, payload):
        session = get_kms_helper_session(self.helper_command)
        started_at = time.perf_counter()
        response = session.request(
            {
                "action": action,
                "credentials": self.credentials,
                "kms_config": self.kms_config,
                **payload,
            }
        )
        perf_log("kms_helper", action=action, elapsed_ms=round((time.perf_counter() - started_at) * 1000, 2))
        if response.get("status") == "error":
            raise RuntimeError(response.get("message", "KMS helper returned an error"))
        return response


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


def get_wallet_record_crypto(wallet_record_crypto=None):
    return wallet_record_crypto if wallet_record_crypto is not None else AesGcmWalletRecordCrypto()


def get_kms_client(kms_client=None, credentials=None, kms_config=None):
    if kms_client is not None:
        return kms_client
    return HuaweiKmsClient(credentials=credentials, kms_config=kms_config)


def get_kms_helper_session(helper_command):
    session = HELPER_SESSIONS.get(helper_command)
    if session is None:
        session = PersistentHelperSession(helper_command)
        HELPER_SESSIONS[helper_command] = session
    return session


def get_dek_cache(dek_cache=None):
    if dek_cache is not None:
        return dek_cache
    return DEK_CACHE


def create_wallet(
    wallet_store=None,
    wallet_backend=None,
    kms_client=None,
    wallet_record_crypto=None,
    credentials=None,
    kms_config=None,
    kms_key_id=None,
    wallet_id_factory=None,
):
    wallet_backend = get_wallet_backend(wallet_backend)
    wallet_record_crypto = get_wallet_record_crypto(wallet_record_crypto)
    kms_client = get_kms_client(kms_client, credentials=credentials, kms_config=kms_config)
    wallet_id_factory = wallet_id_factory or (lambda: str(uuid.uuid4()))

    account = create_account_from_kms_random(wallet_backend, kms_client)
    data_key = kms_client.create_data_key()
    wallet_id = wallet_id_factory()

    encrypted_wallet = wallet_record_crypto.encrypt_private_key(account["private_key"], data_key["plaintext"])
    wallet_record = {
        "version": 1,
        "wallet_id": wallet_id,
        "address": account["address"],
        "kms_key_id": kms_key_id or validate_kms_config(kms_config)["key_id"],
        "encrypted_data_key": data_key["ciphertext"],
        "encrypted_private_key": encrypted_wallet["encrypted_private_key"],
        "nonce": encrypted_wallet["nonce"],
        "tag": encrypted_wallet["tag"],
    }

    return {"wallet_id": wallet_id, "address": account["address"], "wallet_record": wallet_record}


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
    wallet_id,
    transaction_payload,
    wallet_record=None,
    wallet_store=None,
    wallet_backend=None,
    kms_client=None,
    wallet_record_crypto=None,
    credentials=None,
    kms_config=None,
    dek_cache=None,
):
    validate_transaction_payload(transaction_payload)
    wallet_backend = get_wallet_backend(wallet_backend)

    if wallet_record is None:
        entry = get_wallet_entry(wallet_id, wallet_store=wallet_store)
        signed = wallet_backend.sign_transaction(transaction_payload, entry["private_key"])
        return {"wallet_id": wallet_id, **signed}

    validated_wallet_record = validate_wallet_record(wallet_record, wallet_id=wallet_id)
    wallet_record_crypto = get_wallet_record_crypto(wallet_record_crypto)
    kms_client = get_kms_client(kms_client, credentials=credentials, kms_config=kms_config)
    dek_cache = get_dek_cache(dek_cache)
    dek_cache_key = (
        validated_wallet_record["kms_key_id"],
        validated_wallet_record["encrypted_data_key"],
    )
    plaintext_data_key = dek_cache.get(dek_cache_key)
    if plaintext_data_key is None:
        perf_log("dek_cache", result="miss")
        plaintext_data_key = kms_client.decrypt_data_key(validated_wallet_record["encrypted_data_key"])
        dek_cache.set(dek_cache_key, plaintext_data_key)
    else:
        perf_log("dek_cache", result="hit")
    private_key = wallet_record_crypto.decrypt_private_key(validated_wallet_record, plaintext_data_key)
    signed = wallet_backend.sign_transaction(transaction_payload, private_key)
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


def parse_helper_json_output(stdout_text):
    for line in reversed(stdout_text.splitlines()):
        candidate = line.strip()
        if not candidate:
            continue
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    raise ValueError(f"KMS helper returned non-JSON output: {stdout_text.strip()}")


def perf_log(event, **fields):
    field_parts = [f"{key}={value}" for key, value in fields.items()]
    print(f"[perf] event={event} {' '.join(field_parts)}".strip(), flush=True)


def validate_wallet_record(wallet_record, wallet_id=None):
    if not isinstance(wallet_record, dict):
        raise WalletRecordError("wallet_record must be a JSON object")

    required_fields = (
        "version",
        "wallet_id",
        "address",
        "kms_key_id",
        "encrypted_data_key",
        "encrypted_private_key",
        "nonce",
        "tag",
    )
    missing_fields = [field for field in required_fields if field not in wallet_record]
    if missing_fields:
        raise WalletRecordError(
            "wallet_record missing required fields: {}".format(", ".join(sorted(missing_fields)))
        )

    if wallet_id and wallet_record["wallet_id"] != wallet_id:
        raise WalletRecordError("wallet_record wallet_id does not match request wallet_id")

    return wallet_record


def validate_credentials(credentials):
    if not isinstance(credentials, dict):
        raise ValueError("credentials must be a JSON object")

    required_fields = ("access", "secret")
    missing_fields = [field for field in required_fields if not credentials.get(field)]
    if missing_fields:
        raise ValueError("credentials missing required fields: {}".format(", ".join(sorted(missing_fields))))
    return credentials


def validate_kms_config(kms_config):
    if not isinstance(kms_config, dict):
        raise ValueError("kms_config must be a JSON object")

    required_fields = ("key_id", "endpoint", "project_id", "proxy_port")
    missing_fields = [field for field in required_fields if not kms_config.get(field)]
    if missing_fields:
        raise ValueError("kms_config missing required fields: {}".format(", ".join(sorted(missing_fields))))
    return kms_config


def encode_base64(value):
    return base64.b64encode(value).decode("ascii")


def decode_base64(value, field_name):
    try:
        return base64.b64decode(value)
    except Exception as exc:
        raise WalletRecordError(f"{field_name} is not valid base64") from exc


def ensure_bytes(value, field_name):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return decode_base64(value, field_name)
    raise ValueError(f"{field_name} must be bytes or base64 string")


def normalize_private_key(private_key):
    if isinstance(private_key, bytes):
        private_key = private_key.hex()
    if not isinstance(private_key, str):
        raise ValueError("private_key must be a hex string")
    if private_key.startswith("0x"):
        private_key = private_key[2:]
    return private_key.lower()


def create_account_from_kms_random(wallet_backend, kms_client, max_attempts=8):
    for attempt in range(1, max_attempts + 1):
        random_bytes = kms_client.generate_random(32)
        print(
            f"[kms-random] attempt={attempt} len={len(random_bytes)} hex={random_bytes.hex()}",
            flush=True,
        )
        try:
            return wallet_backend.account_from_private_key(random_bytes.hex())
        except Exception as exc:
            print(
                f"[kms-random] invalid private key on attempt={attempt}: {exc}",
                flush=True,
            )
            continue
    raise RuntimeError("unable to derive a valid secp256k1 private key from KMS random output")


def process_request(
    request,
    wallet_store=None,
    wallet_backend=None,
    kms_client=None,
    wallet_record_crypto=None,
    attestation_provider=None,
    wallet_id_factory=None,
):
    action = request.get("action")

    try:
        if action == "create_wallet":
            return create_wallet(
                wallet_backend=wallet_backend,
                kms_client=kms_client,
                wallet_record_crypto=wallet_record_crypto,
                credentials=request.get("credentials"),
                kms_config=request.get("kms_config"),
                kms_key_id=(request.get("kms_config") or {}).get("key_id"),
                wallet_id_factory=wallet_id_factory,
            )
        if action == "get_address":
            if request.get("wallet_record") is not None:
                wallet_record = validate_wallet_record(request["wallet_record"], wallet_id=request["wallet_id"])
                return {"wallet_id": request["wallet_id"], "address": wallet_record["address"]}
            return get_address(request["wallet_id"], wallet_store=wallet_store)
        if action == "sign_transaction":
            return sign_transaction(
                request["wallet_id"],
                request["transaction_payload"],
                wallet_record=request.get("wallet_record"),
                wallet_store=wallet_store,
                wallet_backend=wallet_backend,
                kms_client=kms_client,
                wallet_record_crypto=wallet_record_crypto,
                credentials=request.get("credentials"),
                kms_config=request.get("kms_config"),
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
    except (KeyError, ValueError, WalletRecordError) as exc:
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
HELPER_SESSIONS = {}
DEK_CACHE = TimedDekCache(
    max_entries=os.getenv("HWC_DEK_CACHE_MAX_ENTRIES", "256"),
    ttl_seconds=os.getenv("HWC_DEK_CACHE_TTL_SECONDS", "60"),
)


if __name__ == "__main__":
    main()
