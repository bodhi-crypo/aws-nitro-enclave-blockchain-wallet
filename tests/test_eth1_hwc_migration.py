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
        self.signed = []

    def create_account(self):
        self.created += 1
        return {"private_key": f"priv-{self.created}", "address": f"0xaddr{self.created}"}

    def sign_transaction(self, transaction_payload, private_key):
        self.signed.append((transaction_payload, private_key))
        return {"signed_tx": "0xsigned", "tx_hash": "0xhash"}


def test_enclave_create_wallet_stores_private_key_in_memory():
    module = load_module("eth1_enclave_server", "application/eth1/enclave/server.py")
    wallet_store = {}
    wallet_backend = FakeWalletBackend()

    response = module.create_wallet(
        wallet_store=wallet_store,
        wallet_backend=wallet_backend,
        wallet_id_factory=lambda: "wallet-1",
    )

    assert response == {"wallet_id": "wallet-1", "address": "0xaddr1"}
    assert wallet_store == {"wallet-1": {"private_key": "priv-1", "address": "0xaddr1"}}


def test_enclave_get_address_and_sign_transaction_use_same_wallet():
    module = load_module("eth1_enclave_server", "application/eth1/enclave/server.py")
    wallet_store = {"wallet-1": {"private_key": "priv-1", "address": "0xaddr1"}}
    wallet_backend = FakeWalletBackend()

    address_response = module.get_address("wallet-1", wallet_store=wallet_store)
    sign_response = module.sign_transaction(
        "wallet-1",
        {"nonce": 1, "gas": 21000, "chainId": 11155111, "value": "0.1"},
        wallet_store=wallet_store,
        wallet_backend=wallet_backend,
    )

    assert address_response == {"wallet_id": "wallet-1", "address": "0xaddr1"}
    assert sign_response == {
        "wallet_id": "wallet-1",
        "signed_tx": "0xsigned",
        "tx_hash": "0xhash",
    }
    assert wallet_backend.signed == [
        ({"nonce": 1, "gas": 21000, "chainId": 11155111, "value": "0.1"}, "priv-1")
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
    wallet_store = {"wallet-1": {"private_key": "priv-1", "address": "0xaddr1"}}

    response = module.process_request(
        {
            "action": "sign_transaction",
            "wallet_id": "wallet-1",
            "transaction_payload": {"to": "0xabc"},
        },
        wallet_store=wallet_store,
        wallet_backend=FakeWalletBackend(),
        attestation_provider=lambda: {"quote": "q", "measurement": "m"},
    )

    assert response == {
        "status": "error",
        "error": "invalid_request",
        "message": "transaction_payload missing required fields: chainId, gas, nonce",
    }


def test_server_routes_http_requests_to_tee_actions():
    module = load_module("eth1_parent_server", "application/eth1/server/app.py")
    recorded = []

    def fake_call_enclave(payload, cid=16, port=5000):
        recorded.append((cid, port, payload))
        return {"wallet_id": "wallet-1", "address": "0xaddr1"}

    status, response = module.route_request(
        method="POST",
        path="/wallets",
        body=None,
        enclave_client=fake_call_enclave,
    )

    assert status == 201
    assert response == {"wallet_id": "wallet-1", "address": "0xaddr1"}
    assert recorded == [(16, 5000, {"action": "create_wallet"})]


def test_readme_tracks_external_storage_todo():
    readme_text = (REPO_ROOT / "README.md").read_text()

    assert "TODO: replace in-memory key registry with external encrypted/sealed storage" in readme_text
    assert "TODO: add recovery/restore workflow" in readme_text
    assert "TODO: add policy-based signing controls" in readme_text
