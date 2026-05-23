#!/usr/bin/env bash
set -euo pipefail

PYTEST_WORKERS="${PYTEST_WORKERS:-auto}"
export UV_CACHE_DIR="${UV_CACHE_DIR:-${PWD}/.uv-cache}"

uv run python tests/detector_validation.py --pytest-workers "${PYTEST_WORKERS}"
