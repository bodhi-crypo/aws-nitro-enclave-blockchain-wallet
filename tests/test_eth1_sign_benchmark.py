import importlib.util
import json
import pathlib
import socket
import urllib.error

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(module_name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_create_wallets_collects_wallet_ids():
    module = load_module("eth1_sign_benchmark", "scripts/bench_eth1_sign.py")
    requests = []

    def fake_request(method, url, body=None, timeout_seconds=10):
        requests.append((method, url, body, timeout_seconds))
        return 201, {"wallet_id": f"wallet-{len(requests)}", "address": "0xaddr"}

    wallet_ids = module.create_wallets(
        base_url="http://127.0.0.1:8080",
        wallet_count=3,
        timeout_seconds=7,
        request_fn=fake_request,
    )

    assert wallet_ids == ["wallet-1", "wallet-2", "wallet-3"]
    assert requests == [
        ("POST", "http://127.0.0.1:8080/wallets", None, 7),
        ("POST", "http://127.0.0.1:8080/wallets", None, 7),
        ("POST", "http://127.0.0.1:8080/wallets", None, 7),
    ]


def test_parse_args_rejects_wallet_count_lower_than_concurrency():
    module = load_module("eth1_sign_benchmark", "scripts/bench_eth1_sign.py")

    with pytest.raises(SystemExit):
        module.parse_args(["--concurrency", "4", "--wallet-count", "2"])


def test_worker_uses_wallet_specific_sign_url_and_increments_nonce():
    module = load_module("eth1_sign_benchmark", "scripts/bench_eth1_sign.py")
    requests = []
    responses = iter(
        [
            (200, {"wallet_id": "wallet-1", "signed_tx": "0xa", "tx_hash": "0x1"}),
            (200, {"wallet_id": "wallet-1", "signed_tx": "0xb", "tx_hash": "0x2"}),
        ]
    )

    def fake_request(method, url, body=None, timeout_seconds=10):
        requests.append((method, url, body, timeout_seconds))
        return next(responses)

    run_until = [100.0, 100.0, 102.0]
    perf_times = iter(
        [
            1_000_000_000,
            1_010_000_000,
            2_000_000_000,
            2_015_000_000,
        ]
    )

    samples = module.run_worker(
        wallet_id="wallet-1",
        request_fn=fake_request,
        base_url="http://127.0.0.1:8080",
        timeout_seconds=9,
        run_until_fn=lambda: run_until.pop(0),
        perf_counter_ns_fn=lambda: next(perf_times),
        transaction_template=module.TransactionTemplate(
            chain_id=11155111,
            gas=21000,
            to="0x1111111111111111111111111111111111111111",
            value_ether="0.001",
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
        ),
    )

    assert [sample["success"] for sample in samples] == [True, True]
    assert [request[1] for request in requests] == [
        "http://127.0.0.1:8080/wallets/wallet-1/sign",
        "http://127.0.0.1:8080/wallets/wallet-1/sign",
    ]
    assert [request[2]["transaction_payload"]["nonce"] for request in requests] == [
        0,
        1,
    ]


def test_classify_response_errors():
    module = load_module("eth1_sign_benchmark", "scripts/bench_eth1_sign.py")

    http_error = module.measure_request(
        wallet_id="wallet-1",
        request_fn=lambda *args, **kwargs: (500, {"status": "error"}),
        base_url="http://127.0.0.1:8080",
        timeout_seconds=3,
        perf_counter_ns_fn=iter([0, 5_000_000]).__next__,
        transaction_payload={"nonce": 0, "gas": 21000, "chainId": 1},
    )
    invalid_json = module.measure_request(
        wallet_id="wallet-1",
        request_fn=lambda *args, **kwargs: (_ for _ in ()).throw(
            json.JSONDecodeError("bad", "", 0)
        ),
        base_url="http://127.0.0.1:8080",
        timeout_seconds=3,
        perf_counter_ns_fn=iter([10, 20]).__next__,
        transaction_payload={"nonce": 0, "gas": 21000, "chainId": 1},
    )
    invalid_shape = module.measure_request(
        wallet_id="wallet-1",
        request_fn=lambda *args, **kwargs: (
            200,
            {"wallet_id": "wallet-1", "tx_hash": "0x1"},
        ),
        base_url="http://127.0.0.1:8080",
        timeout_seconds=3,
        perf_counter_ns_fn=iter([30, 40]).__next__,
        transaction_payload={"nonce": 0, "gas": 21000, "chainId": 1},
    )
    timeout = module.measure_request(
        wallet_id="wallet-1",
        request_fn=lambda *args, **kwargs: (_ for _ in ()).throw(
            socket.timeout("timed out")
        ),
        base_url="http://127.0.0.1:8080",
        timeout_seconds=3,
        perf_counter_ns_fn=iter([50, 60]).__next__,
        transaction_payload={"nonce": 0, "gas": 21000, "chainId": 1},
    )
    wrapped_timeout = module.measure_request(
        wallet_id="wallet-1",
        request_fn=lambda *args, **kwargs: (_ for _ in ()).throw(
            urllib.error.URLError(socket.timeout("timed out"))
        ),
        base_url="http://127.0.0.1:8080",
        timeout_seconds=3,
        perf_counter_ns_fn=iter([70, 80]).__next__,
        transaction_payload={"nonce": 0, "gas": 21000, "chainId": 1},
    )

    assert http_error["error_type"] == "http_error"
    assert invalid_json["error_type"] == "invalid_json"
    assert invalid_shape["error_type"] == "invalid_response_shape"
    assert timeout["error_type"] == "timeout"
    assert wrapped_timeout["error_type"] == "timeout"


def test_summarize_samples_computes_recent_rank_percentiles():
    module = load_module("eth1_sign_benchmark", "scripts/bench_eth1_sign.py")
    samples = [
        {"success": True, "latency_ms": 10.0, "error_type": None},
        {"success": True, "latency_ms": 20.0, "error_type": None},
        {"success": False, "latency_ms": 30.0, "error_type": "http_error"},
        {"success": True, "latency_ms": 40.0, "error_type": None},
        {"success": False, "latency_ms": 50.0, "error_type": "timeout"},
    ]

    summary = module.summarize_samples(samples, elapsed_seconds=2.0)

    assert summary["total_requests"] == 5
    assert summary["successful_requests"] == 3
    assert summary["failed_requests"] == 2
    assert summary["tps"] == 1.5
    assert summary["latency_ms_avg"] == 30.0
    assert summary["latency_ms_p50"] == 30.0
    assert summary["latency_ms_p95"] == 50.0
    assert summary["latency_ms_p99"] == 50.0
    assert summary["latency_ms_min"] == 10.0
    assert summary["latency_ms_max"] == 50.0
    assert summary["error_breakdown"] == {"http_error": 1, "timeout": 1}


def test_main_returns_non_zero_when_failures_exist_and_writes_report(tmp_path):
    module = load_module("eth1_sign_benchmark", "scripts/bench_eth1_sign.py")
    report_path = tmp_path / "bench-report.json"
    stage_calls = []

    def fake_create_wallets(base_url, wallet_count, timeout_seconds, request_fn):
        assert base_url == "http://127.0.0.1:8080"
        assert wallet_count == 2
        assert timeout_seconds == 4
        return ["wallet-1", "wallet-2"]

    def fake_run_stage(wallet_ids, args, stage_name, request_fn):
        stage_calls.append((tuple(wallet_ids), stage_name, args.concurrency))
        if stage_name == "warmup":
            return []
        return [
            {"success": True, "latency_ms": 10.0, "error_type": None},
            {"success": False, "latency_ms": 12.0, "error_type": "http_error"},
        ]

    exit_code = module.main(
        [
            "--concurrency",
            "2",
            "--wallet-count",
            "2",
            "--warmup-seconds",
            "0",
            "--duration-seconds",
            "1",
            "--timeout-seconds",
            "4",
            "--report-json",
            str(report_path),
        ],
        request_fn=lambda *args, **kwargs: (200, {}),
        create_wallets_fn=fake_create_wallets,
        run_stage_fn=fake_run_stage,
    )

    report = json.loads(report_path.read_text())

    assert exit_code == 1
    assert stage_calls == [
        (("wallet-1", "wallet-2"), "warmup", 2),
        (("wallet-1", "wallet-2"), "measure", 2),
    ]
    assert report["failed_requests"] == 1
    assert report["error_breakdown"] == {"http_error": 1}
