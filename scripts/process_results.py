#!/usr/bin/env python3
"""
VulTool result processor — reads result JSONs from the `results` branch
and produces a confusion matrix, per-package breakdown, and rescan summary.

Usage:
    python process_results.py [results-dir]

results-dir defaults to ./results  (check out the `results` branch of
AnatoliManolidou/Dummy, then run this from that directory or pass the path).
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

# Ground truth for the Dummy app — manually verified exploitability.
# Key: GHSA ID. Value: True = exploitable in Dummy, False = not exploitable.
# Packages not in Dummy's package.json (e.g. astro) are excluded.
GROUND_TRUTH = {
    "GHSA-f2jv-r9rf-7988": True,   # handlebars  — prototype pollution / RCE
    "GHSA-phwq-j96m-2c2q": True,   # ejs         — RCE via outputFunctionName injection
    "GHSA-36jr-mh4h-2g58": True,   # d3-color    — ReDoS
    "GHSA-hjrf-2m68-5959": True,   # jsonwebtoken — algorithm bypass
    "GHSA-wc9g-mqfw-jrwm": True,   # multer      — DoS via crafted field name
    "GHSA-2x7j-588g-ccc2": True,   # nodemailer  — ReDoS in addressparser
    "GHSA-2883-xcg3-v3hh": True,   # js-yaml     — CPU exhaustion via merge keys
    "GHSA-rgj7-g3m4-5g8c": True,   # sharp       — heap overflow in libheif
    "GHSA-7w5x-hrqm-74c2": True,   # smol-toml   — infinite loop
    "GHSA-j95f-988m-3j2f": True,   # @tiptap/core — ReDoS
    "GHSA-jxfw-x594-9x9m": True,   # morgan      — log injection
    "GHSA-r683-j2x4-v87g": False,  # node-fetch  — no credentials to forward
    "GHSA-c2qf-rxjj-qqgw": False,  # semver      — not called with user input
    "GHSA-g6gw-c38x-mqfc": False,  # hono        — no direct usage in app
    "GHSA-pfrx-2q88-qq97": True,   # got         — SSRF via user-controlled URL to unix socket
    "GHSA-9c47-m6qq-7p4h": True,   # json5       — prototype pollution via parse()
    "GHSA-x5rq-j2xg-h7qm": True,   # lodash      — prototype pollution via _.merge()
    "GHSA-72xf-g2v4-qvf3": True,   # tough-cookie — prototype pollution via Cookie.parse()
    "GHSA-cf4h-3jhx-xvhq": True,   # underscore  — RCE via _.template()
}

EXPLOITABLE_VERDICTS = {"EXPLOITABLE", "CONDITIONALLY_EXPLOITABLE"}


def classify_verdict(verdict_str):
    if verdict_str in EXPLOITABLE_VERDICTS:
        return True
    if verdict_str == "NOT_EXPLOITABLE":
        return False
    return None


def process_main(data):
    rows = []
    for t in data.get("threats", []):
        ghsa = t.get("ghsaId")
        if ghsa not in GROUND_TRUTH:
            continue

        gt          = GROUND_TRUTH[ghsa]
        verdict_str = t.get("verdict")
        verdict     = classify_verdict(verdict_str)
        has_ctx     = t.get("hasExploitContext", t.get("hasDirectUsage", False))
        timed_out   = t.get("llmTimedOut", False)

        if not has_ctx:
            category = "no_exploit_context"
        elif timed_out:
            category = "llm_timeout"
        elif verdict is None:
            category = "no_verdict"
        elif verdict and gt:
            category = "TP"
        elif not verdict and not gt:
            category = "TN"
        elif verdict and not gt:
            category = "FP"
        else:
            category = "FN"

        rows.append({
            "run_id":    data.get("runId"),
            "ts":        (data.get("timestamp") or "")[:10],
            "ghsa":      ghsa,
            "package":   t.get("package", ""),
            "severity":  t.get("severity", ""),
            "verdict":   verdict_str,
            "gt":        "EXPLOITABLE" if gt else "NOT_EXPLOITABLE",
            "category":  category,
            "has_ctx":   has_ctx,
            "timed_out": timed_out,
            "fix_branch": t.get("fixBranch"),
            "rescan":    t.get("rescanTriggered", False),
            "entry_pt":  t.get("entryPointType"),
        })
    return rows


def process_rescan(data):
    return {
        "run_id":    data.get("runId"),
        "ts":        (data.get("timestamp") or "")[:10],
        "ghsa":      data.get("ghsaId"),
        "package":   data.get("packageName", ""),
        "severity":  data.get("severity", ""),
        "verdict":   data.get("patchVerdict"),
        "timed_out": data.get("llmTimedOut", False),
    }


def pct(n, d):
    return f"{100*n/d:.1f}%" if d > 0 else "N/A"


def hr(char="─", w=70):
    print(char * w)


def main():
    results_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results")
    if not results_dir.exists():
        print(f"Directory not found: {results_dir}")
        sys.exit(1)

    files = sorted(results_dir.glob("*.json"))
    if not files:
        print("No result JSON files found.")
        sys.exit(1)

    main_rows, rescan_rows = [], []
    for f in files:
        try:
            data = json.loads(f.read_text())
        except Exception as e:
            print(f"  [skip] {f.name}: {e}")
            continue
        if data.get("mode") == "main":
            main_rows.extend(process_main(data))
        elif data.get("mode") == "rescan":
            rescan_rows.append(process_rescan(data))

    # ── MAIN RUN ANALYSIS ────────────────────────────────────────────────────
    print()
    hr("═")
    print("  MAIN RUNS — LLM EXPLOIT DETECTION")
    hr("═")

    buckets = defaultdict(list)
    for r in main_rows:
        buckets[r["category"]].append(r)

    tp = len(buckets["TP"])
    tn = len(buckets["TN"])
    fp = len(buckets["FP"])
    fn = len(buckets["FN"])
    total = tp + tn + fp + fn

    print(f"\n  Total observations (all categories):  {len(main_rows)}")
    print(f"  Verdict-producing (TP+TN+FP+FN):      {total}")
    print(f"  LLM timeouts (excluded):               {len(buckets['llm_timeout'])}")
    print(f"  No exploit context / C7–C8 filtered:  {len(buckets['no_exploit_context'])}")

    print(f"\n  TP (correctly flagged as exploitable)  {tp:>4}")
    print(f"  TN (correctly cleared as not exploitable) {tn:>4}")
    print(f"  FP (false positive)                    {fp:>4}")
    print(f"  FN (false negative — missed vuln)      {fn:>4}")

    print(f"\n  Accuracy  : {pct(tp+tn, total)}")
    print(f"  Precision : {pct(tp, tp+fp)}")
    print(f"  Recall    : {pct(tp, tp+fn)}")
    f1_num = 2*tp
    f1_den = 2*tp + fp + fn
    print(f"  F1 score  : {f1_num/f1_den:.3f}" if f1_den else "  F1 score  : N/A")

    # Per-package summary
    pkg_data = defaultdict(lambda: {"TP":0,"TN":0,"FP":0,"FN":0,"T/O":0,"no_ctx":0,"gt":"","package":""})
    for r in main_rows:
        k = r["ghsa"]
        d = pkg_data[k]
        d["package"] = r["package"]
        d["gt"]      = r["gt"]
        cat = r["category"]
        if   cat == "TP": d["TP"] += 1
        elif cat == "TN": d["TN"] += 1
        elif cat == "FP": d["FP"] += 1
        elif cat == "FN": d["FN"] += 1
        elif cat == "llm_timeout":      d["T/O"] += 1
        elif cat == "no_exploit_context": d["no_ctx"] += 1

    print(f"\n  {'Package':<26} {'Ground truth':<18} {'TP':>3} {'TN':>3} {'FP':>3} {'FN':>3} {'T/O':>4} {'No ctx':>6}")
    print(f"  {'─'*26} {'─'*18} {'─'*3} {'─'*3} {'─'*3} {'─'*3} {'─'*4} {'─'*6}")
    for ghsa, d in sorted(pkg_data.items(), key=lambda x: x[1]["package"]):
        print(f"  {d['package']:<26} {d['gt']:<18} {d['TP']:>3} {d['TN']:>3} {d['FP']:>3} {d['FN']:>3} {d['T/O']:>4} {d['no_ctx']:>6}")

    if buckets["FN"]:
        print("\n  ── False Negatives ──────────────────────────────────────")
        for r in buckets["FN"]:
            print(f"  [{r['ts']}] {r['package']} ({r['ghsa']}) verdict={r['verdict']}")

    if buckets["FP"]:
        print("\n  ── False Positives ──────────────────────────────────────")
        for r in buckets["FP"]:
            print(f"  [{r['ts']}] {r['package']} ({r['ghsa']}) verdict={r['verdict']}")

    if buckets["llm_timeout"]:
        print("\n  ── LLM Timeouts (excluded from confusion matrix) ────────")
        for r in buckets["llm_timeout"]:
            print(f"  [{r['ts']}] {r['package']} ({r['ghsa']})")

    if buckets["no_exploit_context"]:
        print("\n  ── No Exploit Context (C7/C8 filtered — not in matrix) ──")
        for r in buckets["no_exploit_context"]:
            exp = "(correct — ground truth: NOT EXPLOITABLE)" if r["gt"] == "NOT_EXPLOITABLE" else "(MISSED — ground truth: EXPLOITABLE)"
            print(f"  {r['package']} ({r['ghsa']}) {exp}")

    # ── RESCAN ANALYSIS ──────────────────────────────────────────────────────
    if rescan_rows:
        print()
        hr("═")
        print("  RESCANS — PATCH VERIFICATION")
        hr("═")
        confirmed   = sum(1 for r in rescan_rows if r["verdict"] == "PATCH_CONFIRMED")
        failed      = sum(1 for r in rescan_rows if r["verdict"] == "PATCH_FAILED")
        inconclusive = sum(1 for r in rescan_rows if r["verdict"] == "PATCH_INCONCLUSIVE")
        timed_out   = sum(1 for r in rescan_rows if r["timed_out"])

        print(f"\n  Total rescans:       {len(rescan_rows)}")
        print(f"  PATCH_CONFIRMED:     {confirmed}")
        print(f"  PATCH_FAILED:        {failed}")
        print(f"  PATCH_INCONCLUSIVE:  {inconclusive}  (of which LLM timed out: {timed_out})")

        print(f"\n  {'GHSA':<32} {'Package':<22} {'Verdict':<20} T/O")
        print(f"  {'─'*32} {'─'*22} {'─'*20} ───")
        for r in sorted(rescan_rows, key=lambda x: x["ts"]):
            to = "yes" if r["timed_out"] else "no"
            print(f"  {(r['ghsa'] or ''):<32} {(r['package'] or ''):<22} {(r['verdict'] or ''):<20} {to}")

    print()
    hr("═")
    print()


if __name__ == "__main__":
    main()
