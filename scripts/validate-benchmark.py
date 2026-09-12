#!/usr/bin/env python3
"""Deprecated shim — the canonical benchmark gate lives with the benchmark.

Two files named ``validate-benchmark.py`` used to exist and had drifted apart:
this root copy implemented an older, pre-SARIF contract (it read the JSON that
``secguard scan`` printed to stdout and applied its own precision/recall
thresholds), while the benchmark's own copy reads the **verdict-stage**
``result.sarif`` written by ``secguard report --audit`` and compares
(type, file, line ± tolerance). Running this path therefore reported numbers
that did not describe the gate the project actually ships.

Everything now delegates to ``examples/c-vuln-benchmark/scripts/validate-benchmark.py``
(``--expected`` defaults to the benchmark ground truth, ``--root`` to the
benchmark directory, so no arguments are required).

Usage:
  python3 scripts/validate-benchmark.py                     # newest result.sarif
  python3 scripts/validate-benchmark.py --coverage          # per-type case inventory
  python3 scripts/validate-benchmark.py --selftest          # label-map coverage
  python3 scripts/validate-benchmark.py --help              # all flags
"""

import os
import runpy
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CANONICAL = os.path.join(
    os.path.dirname(HERE), "examples", "c-vuln-benchmark", "scripts", "validate-benchmark.py"
)

if not os.path.exists(CANONICAL):
    print(f"canonical benchmark validator not found: {CANONICAL}", file=sys.stderr)
    sys.exit(2)

# run_path executes the canonical module as __main__ with the caller's argv, so
# every flag (--sarif/--expected/--coverage/--selftest/...) keeps working and no
# translation layer can drift again.
runpy.run_path(CANONICAL, run_name="__main__")
