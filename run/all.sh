#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="${repo_root}/source"
preset="${1:-default}"

cd "${source_dir}"

echo "==> configuring (${preset})"
cmake --preset "${preset}"

echo "==> building (${preset})"
cmake --build --preset "${preset}"

echo "==> running tests (${preset})"
ctest --test-dir "${source_dir}/build/${preset}" --output-on-failure

echo "==> starting atomwall (Ctrl+C to stop)"
exec "${source_dir}/build/${preset}/atomwall"
