#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import math
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class TransactionTemplate:
    chain_id: int
    gas: int
    to: str
    value_ether: str
    max_fee_per_gas: int
    max_priority_fee_per_gas: int


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Benchmark eth1 wallet signing throughput and latency via the local HTTP gateway."
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--duration-seconds", type=float, default=30.0)
    parser.add_argument("--warmup-seconds", type=float, default=5.0)
    parser.add_argument("--wallet-count", type=int)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    parser.add_argument("--chain-id", type=int, default=11155111)
    parser.add_argument("--gas", type=int, default=21000)
    parser.add_argument("--to", default="0x1111111111111111111111111111111111111111")
    parser.add_argument("--value-ether", default="0.001")
    parser.add_argument("--max-fee-per-gas", type=int, default=2_000_000_000)
    parser.add_argument("--max-priority-fee-per-gas", type=int, default=1_000_000_000)
    parser.add_argument("--report-json")

    args = parser.parse_args(argv)
    if args.wallet_count is None:
        args.wallet_count = args.concurrency

    parsed_base_url = urllib.parse.urlparse(args.base_url)
    if parsed_base_url.scheme not in {"http", "https"}:
        parser.error("--base-url must start with http:// or https://")
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    if args.wallet_count < args.concurrency:
        parser.error("--wallet-count must be greater than or equal to --concurrency")
    if args.duration_seconds <= 0:
        parser.error("--duration-seconds must be greater than 0")
    if args.warmup_seconds < 0:
        parser.error("--warmup-seconds must be greater than or equal to 0")
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be greater than 0")

    return args


def build_url(base_url, path):
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def request_json(method, url, body=None, timeout_seconds=10):
    payload = None
    headers = {}
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url=url, method=method, data=payload, headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            response_status = response.getcode()
            response_body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        response_status = exc.code
        response_body = exc.read().decode("utf-8")

    return response_status, json.loads(response_body)


def create_wallets(base_url, wallet_count, timeout_seconds, request_fn=request_json):
    wallet_ids = []
    wallet_url = build_url(base_url, "/wallets")

    for _ in range(wallet_count):
        status, payload = request_fn("POST", wallet_url, None, timeout_seconds)
        if status != 201 or "wallet_id" not in payload:
            raise RuntimeError(
                "wallet creation failed with status={} payload={}".format(
                    status, payload
                )
            )
        wallet_ids.append(payload["wallet_id"])

    return wallet_ids


def build_transaction_payload(template, nonce):
    return {
        "chainId": template.chain_id,
        "nonce": nonce,
        "type": 2,
        "to": template.to,
        "value": template.value_ether,
        "gas": template.gas,
        "maxFeePerGas": template.max_fee_per_gas,
        "maxPriorityFeePerGas": template.max_priority_fee_per_gas,
    }


def measure_request(
    wallet_id,
    request_fn,
    base_url,
    timeout_seconds,
    perf_counter_ns_fn,
    transaction_payload,
):
    sign_url = build_url(base_url, f"/wallets/{wallet_id}/sign")
    request_body = {"transaction_payload": transaction_payload}
    started_ns = perf_counter_ns_fn()

    try:
        status, payload = request_fn("POST", sign_url, request_body, timeout_seconds)
        latency_ms = (perf_counter_ns_fn() - started_ns) / 1_000_000
        if status != 200:
            return {
                "success": False,
                "latency_ms": latency_ms,
                "error_type": "http_error",
            }
        required_fields = {"wallet_id", "signed_tx", "tx_hash"}
        if not required_fields.issubset(payload):
            return {
                "success": False,
                "latency_ms": latency_ms,
                "error_type": "invalid_response_shape",
            }
        return {"success": True, "latency_ms": latency_ms, "error_type": None}
    except json.JSONDecodeError:
        latency_ms = (perf_counter_ns_fn() - started_ns) / 1_000_000
        return {
            "success": False,
            "latency_ms": latency_ms,
            "error_type": "invalid_json",
        }
    except socket.timeout:
        latency_ms = (perf_counter_ns_fn() - started_ns) / 1_000_000
        return {"success": False, "latency_ms": latency_ms, "error_type": "timeout"}
    except urllib.error.URLError as exc:
        latency_ms = (perf_counter_ns_fn() - started_ns) / 1_000_000
        error_type = (
            "timeout" if isinstance(exc.reason, socket.timeout) else "network_error"
        )
        return {
            "success": False,
            "latency_ms": latency_ms,
            "error_type": error_type,
        }
    except OSError:
        latency_ms = (perf_counter_ns_fn() - started_ns) / 1_000_000
        return {
            "success": False,
            "latency_ms": latency_ms,
            "error_type": "network_error",
        }
    except Exception:
        latency_ms = (perf_counter_ns_fn() - started_ns) / 1_000_000
        return {
            "success": False,
            "latency_ms": latency_ms,
            "error_type": "unexpected_exception",
        }


def run_worker(
    wallet_id,
    request_fn,
    base_url,
    timeout_seconds,
    run_until_fn,
    perf_counter_ns_fn,
    transaction_template,
):
    deadline = run_until_fn()
    nonce = 0
    samples = []

    while True:
        transaction_payload = build_transaction_payload(transaction_template, nonce)
        samples.append(
            measure_request(
                wallet_id=wallet_id,
                request_fn=request_fn,
                base_url=base_url,
                timeout_seconds=timeout_seconds,
                perf_counter_ns_fn=perf_counter_ns_fn,
                transaction_payload=transaction_payload,
            )
        )
        nonce += 1
        if run_until_fn() > deadline:
            break

    return samples


def _run_worker_until_deadline(
    wallet_id,
    request_fn,
    base_url,
    timeout_seconds,
    deadline,
    transaction_template,
):
    nonce = 0
    samples = []

    while time.monotonic() < deadline:
        transaction_payload = build_transaction_payload(transaction_template, nonce)
        samples.append(
            measure_request(
                wallet_id=wallet_id,
                request_fn=request_fn,
                base_url=base_url,
                timeout_seconds=timeout_seconds,
                perf_counter_ns_fn=time.perf_counter_ns,
                transaction_payload=transaction_payload,
            )
        )
        nonce += 1

    return samples


def run_stage(wallet_ids, args, stage_name, request_fn=request_json):
    duration_seconds = (
        args.warmup_seconds if stage_name == "warmup" else args.duration_seconds
    )
    selected_wallet_ids = wallet_ids[: args.concurrency]
    transaction_template = TransactionTemplate(
        chain_id=args.chain_id,
        gas=args.gas,
        to=args.to,
        value_ether=args.value_ether,
        max_fee_per_gas=args.max_fee_per_gas,
        max_priority_fee_per_gas=args.max_priority_fee_per_gas,
    )

    if duration_seconds <= 0:
        return []

    deadline = time.monotonic() + duration_seconds
    all_samples = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=args.concurrency
    ) as executor:
        futures = [
            executor.submit(
                _run_worker_until_deadline,
                wallet_id,
                request_fn,
                args.base_url,
                args.timeout_seconds,
                deadline,
                transaction_template,
            )
            for wallet_id in selected_wallet_ids
        ]
        for future in concurrent.futures.as_completed(futures):
            all_samples.extend(future.result())

    return all_samples


def nearest_rank_percentile(sorted_values, percentile):
    if not sorted_values:
        return None
    rank = max(1, math.ceil((percentile / 100) * len(sorted_values)))
    return sorted_values[rank - 1]


def summarize_samples(samples, elapsed_seconds):
    latencies = sorted(sample["latency_ms"] for sample in samples)
    errors = Counter(
        sample["error_type"]
        for sample in samples
        if sample.get("error_type") is not None
    )
    successful_requests = sum(1 for sample in samples if sample["success"])
    failed_requests = len(samples) - successful_requests

    if latencies:
        latency_avg = round(sum(latencies) / len(latencies), 3)
        latency_p50 = nearest_rank_percentile(latencies, 50)
        latency_p95 = nearest_rank_percentile(latencies, 95)
        latency_p99 = nearest_rank_percentile(latencies, 99)
        latency_min = latencies[0]
        latency_max = latencies[-1]
    else:
        latency_avg = None
        latency_p50 = None
        latency_p95 = None
        latency_p99 = None
        latency_min = None
        latency_max = None

    return {
        "total_requests": len(samples),
        "successful_requests": successful_requests,
        "failed_requests": failed_requests,
        "elapsed_seconds": round(elapsed_seconds, 3),
        "tps": (
            round(successful_requests / elapsed_seconds, 3)
            if elapsed_seconds > 0
            else 0.0
        ),
        "latency_ms_avg": latency_avg,
        "latency_ms_p50": latency_p50,
        "latency_ms_p95": latency_p95,
        "latency_ms_p99": latency_p99,
        "latency_ms_min": latency_min,
        "latency_ms_max": latency_max,
        "error_breakdown": dict(errors),
    }


def emit_report(args, summary, stdout):
    print("Benchmark configuration", file=stdout)
    print(f"base_url: {args.base_url}", file=stdout)
    print(f"concurrency: {args.concurrency}", file=stdout)
    print(f"wallet_count: {args.wallet_count}", file=stdout)
    print(f"warmup_seconds: {args.warmup_seconds}", file=stdout)
    print(f"duration_seconds: {args.duration_seconds}", file=stdout)
    print("", file=stdout)
    print("Benchmark results", file=stdout)
    print(f"total_requests: {summary['total_requests']}", file=stdout)
    print(f"successful_requests: {summary['successful_requests']}", file=stdout)
    print(f"failed_requests: {summary['failed_requests']}", file=stdout)
    print(f"elapsed_seconds: {summary['elapsed_seconds']}", file=stdout)
    print(f"tps: {summary['tps']}", file=stdout)
    print(f"latency_ms_avg: {summary['latency_ms_avg']}", file=stdout)
    print(f"latency_ms_p50: {summary['latency_ms_p50']}", file=stdout)
    print(f"latency_ms_p95: {summary['latency_ms_p95']}", file=stdout)
    print(f"latency_ms_p99: {summary['latency_ms_p99']}", file=stdout)
    print(f"latency_ms_min: {summary['latency_ms_min']}", file=stdout)
    print(f"latency_ms_max: {summary['latency_ms_max']}", file=stdout)
    print(f"error_breakdown: {summary['error_breakdown']}", file=stdout)


def main(
    argv=None,
    request_fn=request_json,
    create_wallets_fn=create_wallets,
    run_stage_fn=run_stage,
    stdout=None,
):
    args = parse_args(argv)
    stdout = stdout or sys.stdout

    wallet_ids = create_wallets_fn(
        base_url=args.base_url,
        wallet_count=args.wallet_count,
        timeout_seconds=args.timeout_seconds,
        request_fn=request_fn,
    )

    run_stage_fn(wallet_ids, args, "warmup", request_fn)

    started = time.perf_counter()
    measured_samples = run_stage_fn(wallet_ids, args, "measure", request_fn)
    elapsed_seconds = time.perf_counter() - started

    summary = summarize_samples(measured_samples, elapsed_seconds)
    emit_report(args, summary, stdout)

    if args.report_json:
        report_payload = {
            "config": {
                "base_url": args.base_url,
                "concurrency": args.concurrency,
                "wallet_count": args.wallet_count,
                "warmup_seconds": args.warmup_seconds,
                "duration_seconds": args.duration_seconds,
                "timeout_seconds": args.timeout_seconds,
            },
            **summary,
        }
        with open(args.report_json, "w", encoding="utf-8") as handle:
            json.dump(report_payload, handle, indent=2, sort_keys=True)
            handle.write("\n")

    return 1 if summary["failed_requests"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
