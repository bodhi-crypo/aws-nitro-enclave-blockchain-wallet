# Repository Guidelines

## Project Structure & Module Organization

- `application/eth1/` contains the active QingTian wallet-core v1 path:
  - `enclave/server.py` is the TEE wallet core.
  - `server/app.py` is the host local HTTP gateway and vsock bridge.
  - `lambda/lambda_function.py` is a legacy compatibility client.
- `tests/` holds Python regression tests. Keep new behavior covered here.
- `docs/` stores design notes and migration plans.
- `nitro_wallet/` and large parts of `README.md` remain legacy AWS/CDK material; do not treat them as the primary `eth1` runtime path unless explicitly working on legacy flows.
- `scripts/` contains helper scripts for older Nitro-based workflows.

## Build, Test, and Development Commands

- `python3 -m pytest -q`  
  Run the full Python test suite.
- `python3 -m py_compile application/eth1/lambda/lambda_function.py application/eth1/server/app.py application/eth1/enclave/server.py`  
  Quick syntax check for the active wallet-core path.
- `python3 -m black .`  
  Format Python sources.
- `python3 -m bandit -r application/eth1`  
  Run a basic security scan on the active application code.
- `docker build -f application/eth1/server/Dockerfile application/eth1`  
  Build the local HTTP gateway image.
- `docker build -f application/eth1/enclave/Dockerfile application/eth1`  
  Build the enclave image.

## Coding Style & Naming Conventions

- Use 4-space indentation and standard Python style.
- Prefer small, testable functions over large handlers.
- Use `snake_case` for functions, variables, and file-local helpers.
- Keep transport code thin; wallet logic belongs in `application/eth1/enclave/server.py`.
- When behavior changes, update `README.md`, `TUTORIAL.md`, and any affected files in `docs/`.

## Testing Guidelines

- Use `pytest`; name tests `test_<behavior>()`.
- Add or update tests before changing runtime behavior.
- Cover both success paths and explicit error cases such as invalid payloads or missing `wallet_id`.
- If a change affects the documented API, add at least one regression test and re-run the full suite.

## Commit & Pull Request Guidelines

- Prefer short, imperative commit subjects, for example: `Fix IMDSv2 token handling` or `Update eth1 wallet flow`.
- Keep commits focused; separate runtime refactors from documentation-only changes when practical.
- PRs should include:
  - a brief summary of behavior changes,
  - test evidence (`pytest`, syntax checks, or build output),
  - doc updates when APIs, flows, or operational assumptions changed.

## Security & Configuration Notes

- Never log private keys, encrypted blobs, or credential material.
- Treat attestation values and wallet IDs as runtime data, not hard-coded constants.
- The root `README.md` contains local TODO items for future external storage; preserve those when evolving the wallet core.
