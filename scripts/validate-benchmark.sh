#!/usr/bin/env bash
# Scan the committed benchmark source, then run the benchmark gate.
#
# NOTE ON THE TWO PHASES: the gate reads the verdict-stage `result.sarif`, which
# only exists after an AI agent has classified the candidates and
# `secguard report --audit` has run. A bare scan writes `candidates.sarif`
# (unclassified leads) and no `result.sarif`, so on a cold tree this script
# scans and then reports that the AI stage is still pending. Run `/secguard`
# over `examples/c-vuln-benchmark/src` and re-invoke it to get a real verdict.
#
# Usage:
#   scripts/validate-benchmark.sh            # scan + validate the newest run
#
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bench="$repo_root/examples/c-vuln-benchmark"
db="$(mktemp -t sg-bench-db.XXXXXX)"

cleanup() { rm -f "$db"; }
trap cleanup EXIT

echo "[validate-benchmark] scanning $bench/src ..." >&2
(
  cd "$bench"
  secguard scan src --db "$db" > /dev/null
)

echo "[validate-benchmark] validating against $bench/expected-results.json ..." >&2
python3 "$bench/scripts/validate-benchmark.py" --root "$bench"
