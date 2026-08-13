#!/usr/bin/env python3
"""Validate a SecGuard scan against the FP-verification benchmark ground truth.

The benchmark (examples/c-vuln-benchmark/expected-results.json) lists 30 test
cases. Each case carries a machine-readable ``expect`` field:

  * ``"finding"``     — a true positive / suspected edge case; a finding SHOULD
                         be reported for this (file, line).
  * ``"no_finding"``   — a safe function / safe wrapper / counter-evidence case;
                         the convergence pipeline SHOULD suppress it.

The validator reads the JSON that ``secguard scan`` writes to stdout (the
``evidence_packages`` array, each candidate carrying ``target.file`` and
``target.line``) and cross-references it against the ground truth by
(basename, line). It prints a per-case report and a precision/recall summary,
then exits non-zero when precision or recall falls below the thresholds.

Usage:
  secguard scan <src> > scan.json        # capture scan stdout
  python3 scripts/validate-benchmark.py \
      --scan scan.json \
      --expected examples/c-vuln-benchmark/expected-results.json
"""

import argparse
import json
import os
import sys


def basename(path):
    return os.path.basename(path) if path else ""


def load_scan(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    findings = set()
    for pkg in data.get("evidence_packages", []):
        for cand in (pkg.get("candidates") or []):
            target = cand.get("target", {})
            findings.add((basename(target.get("file", "")), target.get("line", 0)))
    return findings


def load_expected(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def classify(case):
    """Return True when the case is expected to produce a finding."""
    expect = case.get("expect")
    if expect in ("finding", "no_finding"):
        return expect == "finding"
    # Fall back to category when `expect` is absent (older files).
    category = case.get("category", "")
    if category in ("p0_safe_function", "p1_semantic", "p2_counter_evidence"):
        return False
    if "false-positive" in case.get("expected", ""):
        return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", required=True, help="path to `secguard scan` stdout JSON")
    ap.add_argument("--expected", required=True, help="path to expected-results.json")
    ap.add_argument("--min-precision", type=float, default=0.7)
    ap.add_argument("--min-recall", type=float, default=0.7)
    args = ap.parse_args()

    findings = load_scan(args.scan)
    expected = load_expected(args.expected)
    cases = expected.get("test_cases", [])

    tp = fp = tn = fn = 0
    rows = []
    for case in cases:
        cid = case.get("id", "?")
        want_finding = classify(case)
        key = (basename(case.get("file", "")), case.get("line", 0))
        found = key in findings

        if want_finding and found:
            tp += 1
            status = "TP"
        elif want_finding and not found:
            fn += 1
            status = "FN (miss)"
        elif not want_finding and found:
            fp += 1
            status = "FP"
        else:
            tn += 1
            status = "TN"
        rows.append((cid, key[0], key[1], "finding" if want_finding else "no_finding", status))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    print(f"{'case':<8} {'file':<28} {'line':>5} {'expect':<11} {'result'}")
    print("-" * 64)
    for cid, fname, line, want, status in rows:
        print(f"{cid:<8} {fname:<28} {line:>5} {want:<11} {status}")

    print()
    print(f"cases      : {len(cases)}")
    print(f"findings   : {len(findings)}")
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"precision  : {precision:.1%}")
    print(f"recall     : {recall:.1%}")
    print(f"false-pos  : {fpr:.1%}")

    ok = precision >= args.min_precision and recall >= args.min_recall
    if not ok:
        print(
            f"FAIL: precision {precision:.1%} < {args.min_precision:.0%} "
            f"or recall {recall:.1%} < {args.min_recall:.0%}"
        )
        sys.exit(1)
    print("PASS")
    sys.exit(0)


if __name__ == "__main__":
    main()
