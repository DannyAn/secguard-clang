#!/usr/bin/env python3
"""Validate a SecGuard scan of this benchmark against expected-results.json.

Why a type-aware, tolerance-aware comparison
--------------------------------------------
`benchmark.md` used to describe the check as a cross-reference "by (file, line)".
That cannot work as written, for two reasons found by running the benchmark:

1. SecGuard reports the **sink / call** line, while several ground-truth cases
   label the **function definition** or the **formatting** line:
     RL-13 label 153 vs reported 155 (mkstemp call), RL-14 label 163 vs 165,
     TP-02 label 49 vs 50 (sqlite3_exec sink after the sprintf).
   A pure equality check therefore scores DETECTED cases as false negatives.
2. A line can legitimately carry more than one vulnerability type. P10-02 is a
   path-traversal `no_finding` case at p10_interproc_taint.c:31, but SecGuard
   reports an unchecked-return (CWE-252) at that same line — correct, and out of
   scope for that case. A type-agnostic check scores it as a false positive.

So a case matches a finding only when BOTH the vulnerability type and the file
agree and the line is within `--line-tolerance` (default 3). Matches carry their
line offset into the report, so convention drift stays visible instead of being
silently swallowed.

What counts as a verdict
------------------------
The input is the **verdict-stage** `result.sarif` (written by
`secguard report --audit`), which contains only actionable verdicts
(confirmed + suspected). A case the AI *dismissed* is therefore not reported and
is not a false positive — which is exactly the benchmark's intent.

Exit status: non-zero when any case fails. A false positive on a `no_finding`
case ALWAYS fails. A false negative fails unless the case is tagged
`known_gap` (the benchmark documents those as expected gaps) or
`--allow-fn` is passed.
"""

import argparse
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)

# Ground-truth `detector` name -> SecGuard vuln type. Both the dotted
# (`memory.buffer_overflow`) and the bare (`buffer_overflow`) spellings are
# normalised to the kebab-case type `secguard types` reports.
#
# `concurrency.lock` maps to `race-condition`, NOT `deadlock`: its only two cases
# are P2-02 (a counter under a lock guard — must not be reported) and P3-02 (a
# TOCTOU on a shared balance), and SecGuard reports the latter as CWE-362
# race-condition. `deadlock` (CWE-667) has its own separate detector label.
DETECTOR_TO_TYPE = {
    "resource.resource_leak": "resource-leak",
    "resource.resource-leak": "resource-leak",
    "memory.buffer_overflow": "buffer-overflow",
    "buffer_overflow": "buffer-overflow",
    "boundary.integer_overflow": "integer-overflow",
    "integer_overflow": "integer-overflow",
    "crypto_misuse": "crypto-misuse",
    "input.path_traversal": "path-traversal",
    "path_traversal": "path-traversal",
    "input.injection": "injection",
    "injection.command_injection": "injection",
    "concurrency.lock": "race-condition",
    "race_condition": "race-condition",
    "null_deref": "null-deref",
    "memory.use_after_free": "use-after-free",
    "memory.memory_leak": "memory-leak",
    "unchecked_return": "unchecked-return",
    "hardcoded_secret": "hardcoded-secret",
    "divide_by_zero": "divide-by-zero",
    "sizeof_misuse": "sizeof-misuse",
    "signed_compare": "signed-compare",
    "out_of_bounds": "out-of-bounds",
    "deadlock": "deadlock",
    "uninit": "uninit",
}

CWE_TO_TYPE = {
    "CWE-476": "null-deref",
    "CWE-787": "buffer-overflow",
    "CWE-190": "integer-overflow",
    "CWE-327": "crypto-misuse",
    "CWE-78": "injection",
    "CWE-22": "path-traversal",
    "CWE-457": "uninit",
    "CWE-362": "race-condition",
    "CWE-798": "hardcoded-secret",
    "CWE-369": "divide-by-zero",
    "CWE-667": "deadlock",
    "CWE-415": "double-free",
    "CWE-134": "format-string",
    "CWE-401": "memory-leak",
    "CWE-404": "resource-leak",
    "CWE-125": "out-of-bounds",
    "CWE-252": "unchecked-return",
    "CWE-467": "sizeof-misuse",
    "CWE-681": "signed-compare",
    "CWE-416": "use-after-free",
}


def case_type(case):
    """The SecGuard vuln type a ground-truth case belongs to, or None when the
    case carries no detector label (then any type counts)."""
    det = (case.get("detector") or "").strip()
    if det:
        if det in DETECTOR_TO_TYPE:
            return DETECTOR_TO_TYPE[det]
        # Fall back to the underscore->kebab normalisation of the last segment.
        return det.split(".")[-1].replace("_", "-")
    cwe = (case.get("cwe") or "").strip().upper()
    if cwe in CWE_TO_TYPE:
        return CWE_TO_TYPE[cwe]
    return None


def rel_key(path):
    """Compare on the last two path components, so an absolute SARIF URI matches
    the benchmark's relative `src/x.c` without depending on the checkout path."""
    parts = [p for p in re.split(r"[\\/]+", path or "") if p]
    return "/".join(parts[-2:]) if len(parts) >= 2 else (parts[-1] if parts else "")


def file_uri_to_path(uri):
    if uri.startswith("file://"):
        uri = uri[len("file://"):]
    return uri


def load_sarif_findings(path):
    with open(path, encoding="utf-8") as f:
        sarif = json.load(f)
    findings = []
    for run in sarif.get("runs", []):
        for res in run.get("results", []):
            rule = (res.get("ruleId") or "").strip()
            vtype = CWE_TO_TYPE.get(rule.upper(), rule)
            for loc in res.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri = file_uri_to_path(
                    phys.get("artifactLocation", {}).get("uri", "")
                )
                line = phys.get("region", {}).get("startLine", 0) or 0
                findings.append(
                    {"type": vtype, "file": rel_key(uri), "line": line,
                     "rule": rule, "level": res.get("level", "")}
                )
    return findings


def discover_sarif(root):
    """Newest `result.sarif` under the project's scan output, if any."""
    pats = [
        os.path.join(root, ".codeagent/secguard-clang/scans/*/result.sarif"),
        os.path.join(root, ".codeagent/secguard-clang/reviews/*/result.sarif"),
    ]
    hits = [p for pat in pats for p in glob.glob(pat)]
    if not hits:
        return None
    return max(hits, key=os.path.getmtime)


def evaluate(cases, findings, tol):
    by_type = defaultdict(list)
    for f in findings:
        by_type[f["type"]].append(f)

    results = []
    for c in cases:
        want = (c.get("expect") or "").strip()
        ctype = case_type(c)
        key = rel_key(c["file"])
        line = int(c["line"])
        pool = findings if ctype is None else by_type.get(ctype, [])
        near = [
            f for f in pool
            if f["file"] == key and abs(f["line"] - line) <= tol
        ]
        exact = [f for f in near if f["line"] == line]
        offset = min((f["line"] - line for f in near), key=abs) if near else None
        known_gap = "known_gap" in (c.get("category") or "")
        if want == "finding":
            ok = bool(near)
            verdict = "PASS" if ok else ("FN-known-gap" if known_gap else "FN")
        else:
            ok = not near
            verdict = "PASS" if ok else "FP"
        # A same-line finding of a DIFFERENT type is not a verdict either way,
        # but it is useful triage context (P10-02).
        cross = [
            f for f in findings
            if f["file"] == key and f["line"] == line and f["type"] != ctype
        ]
        results.append({
            "id": c.get("id"), "expect": want, "type": ctype or "(any)",
            "file": key, "line": line, "verdict": verdict,
            "matched": [(f["type"], f["line"]) for f in near],
            "exact": bool(exact), "offset": offset,
            "known_gap": known_gap, "cross_type": sorted({f["type"] for f in cross}),
        })
    return results


def selftest():
    """Exercise the comparison logic without touching a real scan, and assert that
    every `detector` label in the ground truth is mapped. A new label therefore
    fails the self-test until DETECTOR_TO_TYPE is updated, instead of silently
    scoring those cases as unmapped."""
    problems = []

    def check(name, got, want):
        if got != want:
            problems.append(f"{name}: got {got!r}, want {want!r}")

    cases = [
        {"id": "T-exact", "file": "src/a.c", "line": 10, "detector": "null_deref", "expect": "finding"},
        {"id": "T-offset", "file": "src/a.c", "line": 20, "detector": "null_deref", "expect": "finding"},
        {"id": "T-far", "file": "src/a.c", "line": 40, "detector": "null_deref", "expect": "finding"},
        {"id": "T-fp", "file": "src/b.c", "line": 5, "detector": "expression", "expect": "no_finding"},
        {"id": "T-ok", "file": "src/b.c", "line": 30, "detector": "input.path_traversal", "expect": "no_finding"},
        {"id": "T-gap", "file": "src/c.c", "line": 7, "category": "x_known_gap", "detector": "uninit", "expect": "finding"},
        {"id": "T-any", "file": "src/d.c", "line": 3, "expect": "finding"},
    ]
    findings = [
        {"type": "null-deref", "file": "src/a.c", "line": 10, "rule": "CWE-476", "level": "error"},
        {"type": "null-deref", "file": "src/a.c", "line": 22, "rule": "CWE-476", "level": "error"},
        {"type": "path-traversal", "file": "src/b.c", "line": 5, "rule": "CWE-22", "level": "error"},
        {"type": "unchecked-return", "file": "src/b.c", "line": 30, "rule": "CWE-252", "level": "error"},
        {"type": "race-condition", "file": "src/d.c", "line": 3, "rule": "CWE-362", "level": "error"},
    ]
    got = {r["id"]: r for r in evaluate(cases, findings, 3)}
    check("exact", got["T-exact"]["verdict"], "PASS")
    check("exact offset", got["T-exact"]["offset"], 0)
    check("within tolerance", got["T-offset"]["verdict"], "PASS")
    check("within tolerance offset", got["T-offset"]["offset"], 2)
    check("outside tolerance", got["T-far"]["verdict"], "FN")
    check("typed FP (other type only)", got["T-fp"]["verdict"], "PASS")
    check("cross-type recorded", got["T-fp"]["cross_type"], ["path-traversal"])
    check("clean negative", got["T-ok"]["verdict"], "PASS")
    check("known-gap FN tag", got["T-gap"]["verdict"], "FN-known-gap")
    check("untyped case matches any type", got["T-any"]["verdict"], "PASS")

    # A same-type finding on the no_finding line must be an FP.
    fp = evaluate(
        [{"id": "T", "file": "src/e.c", "line": 1, "detector": "memory.buffer_overflow",
          "expect": "no_finding"}],
        [{"type": "buffer-overflow", "file": "src/e.c", "line": 2, "rule": "CWE-787", "level": "error"}],
        3,
    )
    check("same-type FP detected", fp[0]["verdict"], "FP")

    # Ground-truth coverage: every detector label must be mapped.
    with open(os.path.join(BENCH, "expected-results.json"), encoding="utf-8") as f:
        labels = {(c.get("detector") or "").strip() for c in json.load(f)["test_cases"]}
    unmapped = sorted(l for l in labels if l and l not in DETECTOR_TO_TYPE)
    if unmapped:
        problems.append(f"unmapped detector labels (add to DETECTOR_TO_TYPE): {unmapped}")

    if problems:
        print("SELFTEST FAILED", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"selftest OK ({len(labels) - 1} detector labels mapped, comparison logic verified)")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sarif", help="verdict-stage result.sarif (default: newest under --root)")
    ap.add_argument("--root", default=BENCH, help="benchmark project root (default: this example)")
    ap.add_argument("--expected", default=os.path.join(BENCH, "expected-results.json"))
    ap.add_argument("--line-tolerance", type=int, default=3,
                    help="allowed |finding.line - case.line| (default 3)")
    ap.add_argument("--allow-fn", action="store_true",
                    help="do not exit non-zero on false negatives")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--show-pass", action="store_true", help="list passing cases too")
    ap.add_argument("--selftest", action="store_true",
                    help="verify the comparison logic and the detector-label map, then exit")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    sarif = args.sarif or discover_sarif(args.root)
    if not sarif:
        print("no result.sarif found — run the scan and `secguard report --audit` first",
              file=sys.stderr)
        return 2
    if not os.path.exists(sarif):
        print(f"no such sarif: {sarif}", file=sys.stderr)
        return 2

    with open(args.expected, encoding="utf-8") as f:
        cases = json.load(f)["test_cases"]
    findings = load_sarif_findings(sarif)
    results = evaluate(cases, findings, args.line_tolerance)

    fp = [r for r in results if r["verdict"] == "FP"]
    fn = [r for r in results if r["verdict"] in ("FN", "FN-known-gap")]
    fn_real = [r for r in fn if r["verdict"] == "FN"]
    passed = [r for r in results if r["verdict"] == "PASS"]
    pos = [r for r in results if r["expect"] == "finding"]
    neg = [r for r in results if r["expect"] == "no_finding"]
    offsets = Counter(r["offset"] for r in passed if r["offset"] is not None)

    if args.json:
        print(json.dumps({
            "sarif": sarif, "line_tolerance": args.line_tolerance,
            "expected_findings": len(pos), "expected_no_finding": len(neg),
            "sarif_findings": len(findings),
            "passed": len(passed),
            "recall": f"{len([r for r in pos if r['verdict'] == 'PASS'])}/{len(pos)}",
            "false_positives": len(fp), "false_negatives": len(fn_real),
            "known_gap_fn": len([r for r in fn if r["known_gap"]]),
            "results": results,
        }, indent=1))
    else:
        print(f"sarif: {sarif}")
        print(f"line tolerance: ±{args.line_tolerance}")
        print(f"ground truth: {len(pos)} expect-finding, {len(neg)} expect-no_finding"
              f" | sarif findings: {len(findings)}")
        print()
        print(f"  PASS  {len(passed)}/{len(results)}")
        print(f"  recall on expect-finding : {len([r for r in pos if r['verdict'] == 'PASS'])}/{len(pos)}")
        print(f"  false positives          : {len(fp)}/{len(neg)}")
        print(f"  false negatives          : {len(fn_real)} (known-gap FN: {len(fn) - len(fn_real)})")
        if offsets:
            print("  line offsets on passes   : "
                  + ", ".join(f"{o:+d}×{n}" for o, n in sorted(offsets.items())))
        if fp:
            print("\n--- FALSE POSITIVES (a finding on a no_finding case) ---")
            for r in fp:
                print(f"  {r['id']:<7} {r['type']:<16} {r['file']}:{r['line']} -> {r['matched']}")
        if fn:
            print("\n--- FALSE NEGATIVES ---")
            for r in fn:
                tag = " [known-gap]" if r["known_gap"] else ""
                print(f"  {r['id']:<7} {r['type']:<16} {r['file']}:{r['line']}{tag}")
        cross = [r for r in results
                 if r["expect"] == "no_finding" and r["cross_type"] and r["verdict"] == "PASS"]
        if cross:
            print("\n--- info: other-type findings on no_finding cases (not failures) ---")
            for r in cross:
                print(f"  {r['id']:<7} {r['file']}:{r['line']} has {r['cross_type']} (case is {r['type']})")
        if args.show_pass:
            print("\n--- PASSING ---")
            for r in passed:
                print(f"  {r['id']:<7} {r['type']:<16} {r['file']}:{r['line']} offset={r['offset']:+d}"
                      if r["offset"] is not None else
                      f"  {r['id']:<7} {r['type']:<16} {r['file']}:{r['line']}")

    failed = bool(fp) or (bool(fn_real) and not args.allow_fn)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
