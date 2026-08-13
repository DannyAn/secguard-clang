#!/usr/bin/env bash
# One-command benchmark gate: scan the benchmark source, then validate the
# convergence pipeline's precision/recall against expected-results.json.
#
# Usage:
#   scripts/validate-benchmark.sh            # scan the committed benchmark src
#
# Exits non-zero when the scan fails or precision/recall fall below the
# thresholds in validate-benchmark.py.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src_dir="$repo_root/examples/c-vuln-benchmark/src"
expected="$repo_root/examples/c-vuln-benchmark/expected-results.json"
scan_json="$(mktemp -t sg-bench-scan.XXXXXX.json)"

cleanup() { rm -f "$scan_json"; }
trap cleanup EXIT

echo "[validate-benchmark] scanning $src_dir ..." >&2
(
  cd "$repo_root/sgre"
  go run ./cmd/secguard scan "$src_dir" --output-dir "$(mktemp -d -t sg-bench-scan.XXXXXX)"
) > "$scan_json"

echo "[validate-benchmark] validating against $expected ..." >&2
python3 "$repo_root/scripts/validate-benchmark.py" \
  --scan "$scan_json" \
  --expected "$expected"
