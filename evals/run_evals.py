"""Golden evals for prompt-injection-firewall.

Loads evals/cases.json (38 hand-verified cases), runs each through the
default-policy Firewall, and asserts the expected action:

 1. Every attack case gets the expected action (block or sanitize).
 2. Every benign control gets ALLOW (false-positive rate on controls == 0).
 3. Per-category precision/recall are reported.
 4. Determinism: two full runs produce byte-identical reports.

Writes evals/eval_report.json (committed). Fully offline.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from firewall import Firewall  # noqa: E402

CASES_PATH = os.path.join(HERE, "cases.json")
REPORT_PATH = os.path.join(HERE, "eval_report.json")

PASS = "PASS"
FAIL = "FAIL"
results: list[tuple[str, str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((PASS if cond else FAIL, name, detail))


def _grade_all() -> list[dict]:
    fw = Firewall()
    with open(CASES_PATH, encoding="utf-8") as fh:
        cases = json.load(fh)
    graded = []
    for case in cases:
        decision = fw.scan_output(case.get("tool", "eval"), case["text"])
        graded.append(
            {
                "id": case["id"],
                "category": case["category"],
                "expected": case["expected"],
                "actual": decision.action,
                "passed": decision.action == case["expected"],
                "n_findings": len(decision.findings),
                "finding_categories": sorted(
                    {f.category for f in decision.findings}
                ),
                "max_severity": decision.max_severity,
            }
        )
    return graded


def _build_report() -> dict:
    graded = _grade_all()
    by_cat: dict[str, dict] = {}
    for g in graded:
        cat = g["category"]
        d = by_cat.setdefault(cat, {"total": 0, "correct": 0, "ids": []})
        d["total"] += 1
        d["ids"].append(g["id"])
        if g["passed"]:
            d["correct"] += 1
    per_category = {}
    for cat, d in sorted(by_cat.items()):
        # For attack categories, "detected" = action was block/sanitize.
        # Precision here = correct / total (no cross-category FP possible
        # beyond the benign controls, which are measured separately).
        per_category[cat] = {
            "total": d["total"],
            "correct": d["correct"],
            "accuracy": round(d["correct"] / d["total"], 4),
            "case_ids": d["ids"],
        }
    benign = [g for g in graded if g["category"] == "benign-control"]
    fp = [g for g in benign if g["actual"] != "allow"]
    attacks = [g for g in graded if g["category"] != "benign-control"]
    report = {
        "n_cases": len(graded),
        "n_attack_cases": len(attacks),
        "n_benign_controls": len(benign),
        "attack_detection_rate": round(
            sum(1 for g in attacks if g["passed"]) / len(attacks), 4
        ),
        "benign_false_positive_rate": round(len(fp) / len(benign), 4),
        "false_positives": [g["id"] for g in fp],
        "per_category": per_category,
        "failures": [
            {"id": g["id"], "expected": g["expected"], "actual": g["actual"]}
            for g in graded
            if not g["passed"]
        ],
        "cases": graded,
    }
    return report


def _report_bytes() -> bytes:
    return json.dumps(_build_report(), indent=2, sort_keys=True).encode("utf-8")


def main() -> int:
    report = _build_report()

    # 1-2. Per-case expectations.
    for g in report["cases"]:
        check(
            f"{g['id']} -> {g['expected']}",
            g["passed"],
            f"got {g['actual']}, findings={g['finding_categories']}",
        )

    # 3. Aggregate gates.
    check("attack detection rate == 1.0",
          report["attack_detection_rate"] == 1.0,
          str(report["attack_detection_rate"]))
    check("benign false-positive rate == 0.0",
          report["benign_false_positive_rate"] == 0.0,
          str(report["benign_false_positive_rate"]))
    for cat, stats in report["per_category"].items():
        check(f"category {cat} accuracy == 1.0",
              stats["accuracy"] == 1.0,
              f"{stats['correct']}/{stats['total']}")

    # 4. Determinism: byte-identical across two runs.
    first = _report_bytes()
    second = _report_bytes()
    check("report byte-identical across runs", first == second)
    md5 = hashlib.md5(first).hexdigest()
    check("md5 stable", hashlib.md5(second).hexdigest() == md5, md5)

    with open(REPORT_PATH, "wb") as fh:
        fh.write(first)

    n_pass = sum(1 for r in results if r[0] == PASS)
    n_fail = sum(1 for r in results if r[0] == FAIL)
    print(f"evals: {n_pass}/{len(results)} passed, md5={md5}")
    for status, name, detail in results:
        if status == FAIL:
            print(f"  FAIL {name} {detail}")
    print(f"wrote {REPORT_PATH}")
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
