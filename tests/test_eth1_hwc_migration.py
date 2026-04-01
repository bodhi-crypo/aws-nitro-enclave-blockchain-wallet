import importlib.util
import os
import pathlib


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(module_name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeWalletBackend:
    def __init__(self):
        self.created = 0
        self.created_from_keys = []
        self.signed = []

    def create_account(self):
        self.created += 1
        return {"private_key": f"priv-{self.created}", "address": f"0xaddr{self.created}"}

    def account_from_private_key(self, private_key):
        self.created_from_keys.append(private_key)
        return {"private_key": private_key, "address": "0xaddr1"}

    def sign_transaction(self, transaction_payload, private_key):
        self.signed.append((transaction_payload, private_key))
        return {"signed_tx": "0xsigned", "tx_hash": "0xhash"}


class FakeKmsClient:
    def __init__(self):
        self.generated_random = []
        self.created_data_keys = []
        self.decrypted_data_keys = []

    def generate_random(self, num_bytes):
        self.generated_random.append(num_bytes)
        return b"\x11" * num_bytes

    def create_data_key(self):
        self.created_data_keys.append("AES_256")
        return {"plaintext": b"\x22" * 32, "ciphertext": "encrypted-dek"}

    def decrypt_data_key(self, encrypted_data_key):
        self.decrypted_data_keys.append(encrypted_data_key)
        return b"\x22" * 32


class FakeWalletRecordCrypto:
    def __init__(self):
        self.encrypted = []
        self.decrypted = []

    def encrypt_private_key(self, private_key, plaintext_data_key):
        self.encrypted.append((private_key, plaintext_data_key))
        return {
            "encrypted_private_key": "encrypted-private-key",
            "nonce": "nonce-value",
            "tag": "tag-value",
        }

    def decrypt_private_key(self, wallet_record, plaintext_data_key):
        self.decrypted.append((wallet_record, plaintext_data_key))
        return "11" * 32


class FakeCredentialProvider:
    def __init__(self, credentials):
        self.credentials = credentials
        self.calls = 0

    def get_credentials(self):
        self.calls += 1
        return self.credentials


class FakeWalletRecordStore:
    def __init__(self, records=None):
        self.records = records or {}
        self.saved = []
        self.loaded = []

    def save(self, wallet_record):
        self.saved.append(wallet_record)
        self.records[wallet_record["wallet_id"]] = wallet_record

    def load(self, wallet_id):
        self.loaded.append(wallet_id)
        if wallet_id not in self.records:
            raise FileNotFoundError(wallet_id)
        return self.records[wallet_id]


def test_enclave_create_wallet_returns_wallet_record_encrypted_by_data_key():
    module = load_module("eth1_enclave_server", "application/eth1/enclave/server.py")
    wallet_backend = FakeWalletBackend()
    kms_client = FakeKmsClient()
    wallet_record_crypto = FakeWalletRecordCrypto()

    response = module.create_wallet(
        wallet_backend=wallet_backend,
        kms_client=kms_client,
        wallet_record_crypto=wallet_record_crypto,
        kms_key_id="kms-key-1",
        wallet_id_factory=lambda: "wallet-1",
    )

    assert response == {
        "wallet_id": "wallet-1",
        "address": "0xaddr1",
        "wallet_record": {
            "version": 1,
            "wallet_id": "wallet-1",
            "address": "0xaddr1",
            "kms_key_id": "kms-key-1",
            "encrypted_data_key": "encrypted-dek",
            "encrypted_private_key": "encrypted-private-key",
            "nonce": "nonce-value",
            "tag": "tag-value",
        },
    }
    assert kms_client.generated_random == [32]
    assert kms_client.created_data_keys == ["AES_256"]
    assert wallet_backend.created_from_keys == ["11" * 32]
    assert wallet_record_crypto.encrypted == [("11" * 32, b"\x22" * 32)]


def test_enclave_sign_transaction_uses_wallet_record_and_kms_decrypt():
    module = load_module("eth1_enclave_server", "application/eth1/enclave/server.py")
    wallet_backend = FakeWalletBackend()
    kms_client = FakeKmsClient()
    wallet_record_crypto = FakeWalletRecordCrypto()
    wallet_record = {
        "version": 1,
        "wallet_id": "wallet-1",
        "address": "0xaddr1",
        "kms_key_id": "kms-key-1",
        "encrypted_data_key": "encrypted-dek",
        "encrypted_private_key": "encrypted-private-key",
        "nonce": "nonce-value",
        "tag": "tag-value",
    }

    sign_response = module.sign_transaction(
        "wallet-1",
        {"nonce": 1, "gas": 21000, "chainId": 11155111, "value": "0.1"},
        wallet_record=wallet_record,
        wallet_backend=wallet_backend,
        kms_client=kms_client,
        wallet_record_crypto=wallet_record_crypto,
    )

    assert sign_response == {
        "wallet_id": "wallet-1",
        "signed_tx": "0xsigned",
        "tx_hash": "0xhash",
    }
    assert kms_client.decrypted_data_keys == ["encrypted-dek"]
    assert wallet_record_crypto.decrypted == [(wallet_record, b"\x22" * 32)]
    assert wallet_backend.signed == [
        ({"nonce": 1, "gas": 21000, "chainId": 11155111, "value": "0.1"}, "11" * 32)
    ]


def test_enclave_unknown_wallet_returns_structured_error():
    module = load_module("eth1_enclave_server", "application/eth1/enclave/server.py")

    response = module.process_request(
        {"action": "get_address", "wallet_id": "missing"},
        wallet_store={},
        wallet_backend=FakeWalletBackend(),
        attestation_provider=lambda: {"quote": "q", "measurement": "m"},
    )

    assert response == {
        "status": "error",
        "error": "wallet_not_found",
        "wallet_id": "missing",
    }


def test_enclave_get_attestation_returns_non_empty_values(monkeypatch):
    module = load_module("eth1_enclave_server", "application/eth1/enclave/server.py")
    monkeypatch.setenv("QINGTIAN_ATTESTATION_QUOTE", "quote-value")
    monkeypatch.setenv("QINGTIAN_ATTESTATION_MEASUREMENT", "measurement-value")

    response = module.get_attestation()

    assert response == {"quote": "quote-value", "measurement": "measurement-value"}


def test_enclave_rejects_invalid_transaction_payload():
    module = load_module("eth1_enclave_server", "application/eth1/enclave/server.py")
    wallet_record = {
        "version": 1,
        "wallet_id": "wallet-1",
        "address": "0xaddr1",
        "kms_key_id": "kms-key-1",
        "encrypted_data_key": "encrypted-dek",
        "encrypted_private_key": "encrypted-private-key",
        "nonce": "nonce-value",
        "tag": "tag-value",
    }

    response = module.process_request(
        {
            "action": "sign_transaction",
            "wallet_id": "wallet-1",
            "wallet_record": wallet_record,
            "transaction_payload": {"to": "0xabc"},
        },
        wallet_backend=FakeWalletBackend(),
        kms_client=FakeKmsClient(),
        wallet_record_crypto=FakeWalletRecordCrypto(),
        attestation_provider=lambda: {"quote": "q", "measurement": "m"},
    )

    assert response == {
        "status": "error",
        "error": "invalid_request",
        "message": "transaction_payload missing required fields: chainId, gas, nonce",
    }


def test_kms_client_extracts_json_from_last_stdout_line():
    module = load_module("eth1_enclave_server", "application/eth1/enclave/server.py")

    response = module.parse_helper_json_output(
        "unix socket listening...\n[bridge] generate_random status=0 len=32 hex=abcd\n{\"random\":\"YWJjZA==\"}\n"
    )

    assert response == {"random": "YWJjZA=="}


def test_kms_client_reports_non_json_helper_output():
    module = load_module("eth1_enclave_server", "application/eth1/enclave/server.py")

    try:
        module.parse_helper_json_output("unix socket listening...\nbridge failed badly\n")
    except ValueError as exc:
        assert "non-JSON output" in str(exc)
    else:
        raise AssertionError("expected ValueError for non-JSON helper output")


def test_server_create_wallet_persists_wallet_record_and_hides_it(monkeypatch):
    module = load_module("eth1_parent_server", "application/eth1/server/app.py")
    recorded = []
    wallet_record_store = FakeWalletRecordStore()
    credential_provider = FakeCredentialProvider(
        {
            "access": "ak",
            "secret": "sk",
            "securitytoken": "token",
            "expires_at": "2026-03-31T00:00:00Z",
        }
    )

    monkeypatch.setenv("HWC_KMS_KEY_ID", "kms-key-1")
    monkeypatch.setenv("HWC_KMS_ENDPOINT", "kms.test.myhuaweicloud.com")
    monkeypatch.setenv("HWC_PROJECT_ID", "project-1")
    monkeypatch.setenv("QT_PROXY_PORT", "8000")

    def fake_call_enclave(payload, cid=16, port=5000):
        recorded.append((cid, port, payload))
        return {
            "wallet_id": "wallet-1",
            "address": "0xaddr1",
            "wallet_record": {
                "version": 1,
                "wallet_id": "wallet-1",
                "address": "0xaddr1",
                "kms_key_id": "kms-key-1",
                "encrypted_data_key": "encrypted-dek",
                "encrypted_private_key": "encrypted-private-key",
                "nonce": "nonce-value",
                "tag": "tag-value",
            },
        }

    status, response = module.route_request(
        method="POST",
        path="/wallets",
        body=None,
        enclave_client=fake_call_enclave,
        credential_provider=credential_provider,
        wallet_record_store=wallet_record_store,
    )

    assert status == 201
    assert response == {"wallet_id": "wallet-1", "address": "0xaddr1"}
    assert credential_provider.calls == 1
    assert wallet_record_store.saved == [
        {
            "version": 1,
            "wallet_id": "wallet-1",
            "address": "0xaddr1",
            "kms_key_id": "kms-key-1",
            "encrypted_data_key": "encrypted-dek",
            "encrypted_private_key": "encrypted-private-key",
            "nonce": "nonce-value",
            "tag": "tag-value",
        }
    ]
    assert recorded == [
        (
            16,
            5000,
            {
                "action": "create_wallet",
                "credentials": {
                    "access": "ak",
                    "secret": "sk",
                    "securitytoken": "token",
                    "expires_at": "2026-03-31T00:00:00Z",
                },
                "kms_config": {
                    "key_id": "kms-key-1",
                    "endpoint": "kms.test.myhuaweicloud.com",
                    "project_id": "project-1",
                    "proxy_port": 8000,
                },
            },
        )
    ]


def test_server_gets_address_from_local_wallet_record_store():
    module = load_module("eth1_parent_server", "application/eth1/server/app.py")
    wallet_record_store = FakeWalletRecordStore(
        {
            "wallet-1": {
                "version": 1,
                "wallet_id": "wallet-1",
                "address": "0xaddr1",
            }
        }
    )

    status, response = module.route_request(
        method="GET",
        path="/wallets/wallet-1/address",
        body=None,
        enclave_client=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not call enclave")),
        wallet_record_store=wallet_record_store,
    )

    assert status == 200
    assert response == {"wallet_id": "wallet-1", "address": "0xaddr1"}


def test_static_credential_provider_reads_access_key_and_secret_from_env(monkeypatch):
    module = load_module("eth1_parent_server", "application/eth1/server/app.py")
    monkeypatch.setenv("HWC_KMS_ACCESS_KEY", "ak")
    monkeypatch.setenv("HWC_KMS_SECRET_KEY", "sk")
    monkeypatch.delenv("HWC_KMS_SECURITY_TOKEN", raising=False)

    provider = module.StaticCredentialProvider()

    assert provider.get_credentials() == {
        "access": "ak",
        "secret": "sk",
        "securitytoken": None,
        "expires_at": None,
    }


def test_route_request_uses_static_credentials_by_default(monkeypatch):
    module = load_module("eth1_parent_server", "application/eth1/server/app.py")
    wallet_record_store = FakeWalletRecordStore()
    monkeypatch.setenv("HWC_KMS_ACCESS_KEY", "ak")
    monkeypatch.setenv("HWC_KMS_SECRET_KEY", "sk")
    monkeypatch.delenv("HWC_KMS_SECURITY_TOKEN", raising=False)
    monkeypatch.setenv("HWC_KMS_KEY_ID", "kms-key-1")
    monkeypatch.setenv("HWC_KMS_ENDPOINT", "kms.test.myhuaweicloud.com")
    monkeypatch.setenv("HWC_PROJECT_ID", "project-1")
    monkeypatch.setenv("QT_PROXY_PORT", "8000")
    recorded = []

    def fake_call_enclave(payload, cid=16, port=5000):
        recorded.append((cid, port, payload))
        return {
            "wallet_id": "wallet-1",
            "address": "0xaddr1",
            "wallet_record": {
                "version": 1,
                "wallet_id": "wallet-1",
                "address": "0xaddr1",
                "kms_key_id": "kms-key-1",
                "encrypted_data_key": "encrypted-dek",
                "encrypted_private_key": "encrypted-private-key",
                "nonce": "nonce-value",
                "tag": "tag-value",
            },
        }

    status, response = module.route_request(
        method="POST",
        path="/wallets",
        body=None,
        enclave_client=fake_call_enclave,
        wallet_record_store=wallet_record_store,
    )

    assert status == 201
    assert response == {"wallet_id": "wallet-1", "address": "0xaddr1"}
    assert recorded[0][2]["credentials"] == {
        "access": "ak",
        "secret": "sk",
        "securitytoken": None,
        "expires_at": None,
    }


def test_server_sign_uses_local_wallet_record_and_credentials(monkeypatch):
    module = load_module("eth1_parent_server", "application/eth1/server/app.py")
    wallet_record = {
        "version": 1,
        "wallet_id": "wallet-1",
        "address": "0xaddr1",
        "kms_key_id": "kms-key-1",
        "encrypted_data_key": "encrypted-dek",
        "encrypted_private_key": "encrypted-private-key",
        "nonce": "nonce-value",
        "tag": "tag-value",
    }
    wallet_record_store = FakeWalletRecordStore({"wallet-1": wallet_record})
    credential_provider = FakeCredentialProvider(
        {
            "access": "ak",
            "secret": "sk",
            "securitytoken": "token",
            "expires_at": "2026-03-31T00:00:00Z",
        }
    )
    monkeypatch.setenv("HWC_KMS_KEY_ID", "kms-key-1")
    monkeypatch.setenv("HWC_KMS_ENDPOINT", "kms.test.myhuaweicloud.com")
    monkeypatch.setenv("HWC_PROJECT_ID", "project-1")
    monkeypatch.setenv("QT_PROXY_PORT", "8000")
    recorded = []

    def fake_call_enclave(payload, cid=16, port=5000):
        recorded.append((cid, port, payload))
        return {"wallet_id": "wallet-1", "signed_tx": "0xsigned", "tx_hash": "0xhash"}

    status, response = module.route_request(
        method="POST",
        path="/wallets/wallet-1/sign",
        body={"transaction_payload": {"nonce": 1, "gas": 21000, "chainId": 11155111, "value": "0.1"}},
        enclave_client=fake_call_enclave,
        credential_provider=credential_provider,
        wallet_record_store=wallet_record_store,
    )

    assert status == 200
    assert response == {"wallet_id": "wallet-1", "signed_tx": "0xsigned", "tx_hash": "0xhash"}
    assert credential_provider.calls == 1
    assert recorded == [
        (
            16,
            5000,
            {
                "action": "sign_transaction",
                "wallet_id": "wallet-1",
                "wallet_record": wallet_record,
                "transaction_payload": {
                    "nonce": 1,
                    "gas": 21000,
                    "chainId": 11155111,
                    "value": "0.1",
                },
                "credentials": {
                    "access": "ak",
                    "secret": "sk",
                    "securitytoken": "token",
                    "expires_at": "2026-03-31T00:00:00Z",
                },
                "kms_config": {
                    "key_id": "kms-key-1",
                    "endpoint": "kms.test.myhuaweicloud.com",
                    "project_id": "project-1",
                    "proxy_port": 8000,
                },
            },
        )
    ]


def test_readme_tracks_external_storage_todo():
    readme_text = (REPO_ROOT / "README.md").read_text()

    assert "TODO: replace in-memory key registry with external encrypted/sealed storage" in readme_text
    assert "TODO: add recovery/restore workflow" in readme_text
    assert "TODO: add policy-based signing controls" in readme_text


def test_enclave_dockerfile_uses_shell_wrapper_entrypoint():
    dockerfile_text = (REPO_ROOT / "application/eth1/enclave/Dockerfile").read_text()
    start_script_text = (REPO_ROOT / "application/eth1/enclave/start.sh").read_text()

    assert 'COPY ./application/eth1/enclave/start.sh ./start.sh' in dockerfile_text
    assert 'CMD ["/app/start.sh"]' in dockerfile_text
    assert 'ENCLAVE_LOG_DIR="${ENCLAVE_LOG_DIR:-/var/log/tee-wallet}"' in start_script_text
    assert 'LOG_FILE="${ENCLAVE_LOG_FILE:-$ENCLAVE_LOG_DIR/service.log}"' in start_script_text
    assert 'exec >>"$LOG_FILE" 2>&1' in start_script_text
    assert "python3 /app/server.py" in start_script_text


def test_enclave_dockerfile_pins_python_310_for_web3_compatibility():
    dockerfile_text = (REPO_ROOT / "application/eth1/enclave/Dockerfile").read_text()

    assert "FROM ubuntu:22.04 AS runtime" in dockerfile_text
    assert "python3.10" in dockerfile_text
    assert "python3-pip" in dockerfile_text


def test_enclave_requirements_include_cryptography_for_wallet_record_encryption():
    requirements_text = (REPO_ROOT / "application/eth1/enclave/requirements.txt").read_text()

    assert "cryptography==" in requirements_text


def test_enclave_dockerfile_sets_default_kms_bridge_command():
    dockerfile_text = (REPO_ROOT / "application/eth1/enclave/Dockerfile").read_text()
    server_text = (REPO_ROOT / "application/eth1/enclave/server.py").read_text()

    assert "FROM ubuntu:22.04 AS bridge-builder" in dockerfile_text
    assert "QINGTIAN_REPO_COMMIT=516a3f4531d0ff6cbde6e19764fb6319650b9fc5" in dockerfile_text
    assert "COPY --from=bridge-builder /opt/build/qingtian_kms_bridge /app/qingtian_kms_bridge" in dockerfile_text
    assert "COPY ./third_party/huawei-qingtian /opt/huawei-qingtian" in dockerfile_text
    assert 'ENV HWC_KMS_BRIDGE_CMD="/app/qingtian_kms_bridge"' in dockerfile_text
    assert 'os.getenv("HWC_KMS_BRIDGE_CMD")' in server_text


def test_enclave_bridge_sources_exist():
    bridge_source = REPO_ROOT / "application/eth1/enclave/qingtian_kms_bridge.c"
    bridge_makefile = REPO_ROOT / "application/eth1/enclave/Makefile.qingtian_kms_bridge"

    assert bridge_source.exists()
    assert bridge_makefile.exists()


def test_enclave_bridge_uses_decrypt_datakey_api_for_encrypted_data_keys():
    bridge_source_text = (
        REPO_ROOT / "application/eth1/enclave/qingtian_kms_bridge.c"
    ).read_text()

    assert "decrypt-datakey" in bridge_source_text


def test_enclave_bridge_attaches_attestation_to_decrypt_datakey_requests():
    bridge_source_text = (
        REPO_ROOT / "application/eth1/enclave/qingtian_kms_bridge.c"
    ).read_text()

    assert "recipient" in bridge_source_text
    assert "attestation_document" in bridge_source_text
    assert "RSAES_OAEP_SHA_256" in bridge_source_text


def test_enclave_bridge_uses_qingtian_attestation_api_for_decrypt_datakey():
    bridge_source_text = (
        REPO_ROOT / "application/eth1/enclave/qingtian_kms_bridge.c"
    ).read_text()

    assert '#include "attestation.h"' in bridge_source_text
    assert "attestation_rsa_keypair_new" in bridge_source_text
    assert "get_attestation_doc" in bridge_source_text


def test_qingtian_rebuild_script_exists_with_expected_steps():
    script_path = REPO_ROOT / "scripts/rebuild_eth1_qingtian_enclave.sh"
    script_text = script_path.read_text()

    assert script_path.exists()
    assert 'NO_CACHE="${NO_CACHE:-0}"' in script_text
    assert 'DOCKER_BUILD_ARGS=(-f application/eth1/enclave/Dockerfile . -t "${IMAGE_TAG}")' in script_text
    assert 'if [[ "${NO_CACHE}" == "1" ]]; then' in script_text
    assert 'DOCKER_BUILD_ARGS=(--no-cache "${DOCKER_BUILD_ARGS[@]}")' in script_text
    assert 'docker build "${DOCKER_BUILD_ARGS[@]}"' in script_text
    assert "qt enclave make-img --docker-uri" in script_text
    assert "qt enclave stop --enclave-id" in script_text
    assert 'qt enclave start "${START_ARGS[@]}"' in script_text
    assert '--cpus "${ENCLAVE_CPU_COUNT}"' in script_text
