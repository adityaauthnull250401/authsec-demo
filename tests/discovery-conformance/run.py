#!/usr/bin/env python3
"""
Discovery collector conformance suite.

Applies the case manifests, collects what the collector actually reported, and
asserts it against the expectations each manifest declares in its own
annotations. Prints a scorecard and exits non-zero if any assertion fails.

Expectations live on the manifests, not here, so there is no second source of
truth to drift. This file only knows how to compare.

Usage:
    python3 run.py                 # full run: apply, assert, report, clean up
    python3 run.py --keep          # leave the workloads up for inspection
    python3 run.py --no-apply      # assert against what is already deployed
"""

import argparse
import json
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

CASES_DIR = Path(__file__).parent / "cases"
COLLECTOR_NS = "authsec-system"
CASE_NAMESPACES = ["conformance", "conformance-alt", "conformance-optout"]
SETTLE_SECONDS = 25

# ANSI, disabled when not a tty
_tty = sys.stdout.isatty()
def _c(code, s): return f"\033[{code}m{s}\033[0m" if _tty else s
def green(s): return _c("32", s)
def red(s): return _c("31", s)
def yellow(s): return _c("33", s)
def bold(s): return _c("1", s)
def dim(s): return _c("2", s)


def sh(*args, check=True):
    r = subprocess.run(args, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(args)}\n{r.stderr}")
    return r.stdout


def kubectl(*args, check=True):
    return sh("kubectl", *args, check=check)


# --------------------------------------------------------------------------
# collector interaction
# --------------------------------------------------------------------------

def collector_pods():
    """Collector pod names.

    The chart's app.kubernetes.io/name has varied ("discovery-agent" vs
    "authsec-discovery-agent"), so match on substring rather than pinning a
    label value that a chart rename would silently break.
    """
    out = kubectl("get", "pods", "-n", COLLECTOR_NS,
                  "-o", "jsonpath={.items[*].metadata.name}", check=False)
    return [p for p in out.split() if "discovery-agent" in p]


def require_collector():
    pods = collector_pods()
    if not pods:
        raise SystemExit(
            "No discovery-agent pods found in namespace '%s'.\n"
            "Install the collector first — see README.md." % COLLECTOR_NS)
    return pods


def webhook_config():
    out = kubectl("get", "validatingwebhookconfigurations", "-o", "json", check=False)
    try:
        items = json.loads(out).get("items", [])
    except json.JSONDecodeError:
        return None
    for it in items:
        if "discovery-agent" in it["metadata"]["name"]:
            return it
    return None


def collected_sightings(pods):
    """Every sighting the collector emitted, keyed by (namespace, workload, container).

    Handles both dry-run output (a full JSON payload under "sighting") and live
    output (the "agent sighted" summary line).
    """
    found = {}
    for pod in pods:
        logs = kubectl("logs", "-n", COLLECTOR_NS, pod, check=False)
        for line in logs.splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            if "sighting" in rec:                       # dry-run: full payload
                try:
                    s = json.loads(rec["sighting"])
                except json.JSONDecodeError:
                    continue
                m = s.get("metadata", {})
                k8s = m.get("kubernetes", {})
                key = (k8s.get("namespace"), k8s.get("workload_name"),
                       k8s.get("container_name"))
                entry = {
                    "fingerprint": s.get("fingerprint", ""),
                    "origin": s.get("deployment_origin", ""),
                    "confidence": m.get("detection", {}).get("confidence", ""),
                    "frameworks": m.get("detection", {}).get("frameworks", []) or [],
                    "signals": [x.get("kind") for x in m.get("detection", {}).get("signals", [])],
                    "container_kind": k8s.get("container_kind", ""),
                    "workload_kind": k8s.get("workload_kind", ""),
                    "host_network": bool(k8s.get("host_network", False)),
                    "sighted_via": k8s.get("sighted_via", ""),
                    "secret_refs": m.get("provisioning_hints", {}).get("secret_refs", []) or [],
                    "raw": rec["sighting"],
                }
            elif rec.get("msg") == "agent sighted":     # live mode: summary line
                wk = rec.get("workload", "/")
                key = (rec.get("namespace"), wk.split("/", 1)[-1], rec.get("container"))
                entry = {
                    "fingerprint": rec.get("fingerprint", ""),
                    "origin": rec.get("origin", ""),
                    "confidence": rec.get("confidence", ""),
                    "frameworks": rec.get("frameworks") or [],
                    "signals": [], "container_kind": "", "workload_kind": "",
                    "host_network": False, "sighted_via": "",
                    "secret_refs": [], "raw": line,
                }
            else:
                continue

            # Prefer the workload-channel sighting: its actor is the human who
            # applied the object, where a Pod-channel one is the controller.
            prev = found.get(key)
            if prev is None or entry.get("sighted_via") not in ("Pod", ""):
                found[key] = entry
    return found


# --------------------------------------------------------------------------
# cases
# --------------------------------------------------------------------------

def declared_cases():
    """Read expectations from annotations on the live objects."""
    cases = {}
    for kind in ("deployments", "statefulsets", "daemonsets", "jobs", "cronjobs", "pods"):
        out = kubectl("get", kind, "-A", "-o", "json", check=False)
        try:
            items = json.loads(out).get("items", [])
        except json.JSONDecodeError:
            continue
        for it in items:
            ann = it["metadata"].get("annotations", {}) or {}
            cid = ann.get("conformance/id")
            if not cid:
                continue
            # A Job created by a CronJob inherits annotations; skip those so the
            # CronJob case is not double-counted under a generated Job name.
            if it["metadata"].get("ownerReferences") and kind != "pods":
                continue
            cases[cid] = {
                "id": cid,
                "kind": it["kind"],
                "name": it["metadata"]["name"],
                "namespace": it["metadata"]["namespace"],
                "desc": ann.get("conformance/desc", ""),
                "expect": ann.get("conformance/expect", "detected"),
                "confidence": ann.get("conformance/confidence"),
                "signal": ann.get("conformance/signal"),
                "framework": ann.get("conformance/framework"),
                "origin": ann.get("conformance/origin"),
                "workload_kind": ann.get("conformance/workload-kind"),
                "container_kind": ann.get("conformance/container-kind"),
                "gap": ann.get("conformance/gap"),
                "distinct_fps": ann.get("conformance/assert-distinct-fingerprints"),
                "fp_count": ann.get("conformance/assert-fingerprint-count"),
                "differs_from": ann.get("conformance/assert-differs-from"),
                "host_network": ann.get("conformance/assert-host-network"),
                "secret_ref": ann.get("conformance/assert-secret-ref"),
                "no_value": ann.get("conformance/assert-no-value"),
                "inject_ephemeral": ann.get("conformance/inject-ephemeral"),
            }
    return cases


def sightings_for(case, sightings):
    return {k: v for k, v in sightings.items()
            if k[0] == case["namespace"] and k[1] == case["name"]}


def check(case, sightings, by_id):
    """Return (verdict, [notes]). verdict in pass/fail/gap."""
    mine = sightings_for(case, sightings)
    notes = []
    expect = case["expect"]

    if expect == "not-detected":
        if mine:
            return "fail", ["expected no sighting, got %d (%s)"
                            % (len(mine), ", ".join(sorted(k[2] for k in mine)))]
        return "pass", []

    if expect == "blind-spot":
        if mine:
            # Detected despite being a known gap — genuinely good news.
            return "pass", ["blind spot CLOSED: now detected (%s)"
                            % ",".join(sorted(k[2] for k in mine))]
        return "gap", [case["gap"] or "not detected"]

    # expect == detected
    if not mine:
        return "fail", ["expected a sighting, got none"]

    fps = {v["fingerprint"] for v in mine.values()}

    if case["fp_count"] and len(fps) != int(case["fp_count"]):
        notes.append("expected %s distinct fingerprint(s), got %d"
                     % (case["fp_count"], len(fps)))
    if case["distinct_fps"]:
        want = [c.strip() for c in case["distinct_fps"].split(",")]
        got = {k[2]: v["fingerprint"] for k, v in mine.items()}
        missing = [c for c in want if c not in got]
        if missing:
            notes.append("containers not reported: %s" % ",".join(missing))
        elif len({got[c] for c in want}) != len(want):
            notes.append("containers %s share a fingerprint — they must not"
                         % ",".join(want))

    rep = max(mine.values(), key=lambda v: {"high": 3, "medium": 2, "low": 1}
              .get(v["confidence"], 0))

    if case["confidence"] and rep["confidence"] != case["confidence"]:
        notes.append("confidence %s, expected %s" % (rep["confidence"], case["confidence"]))
    if case["signal"] and rep["signals"] and case["signal"] not in rep["signals"]:
        notes.append("signals %s, expected %s" % (rep["signals"], case["signal"]))
    if case["framework"] and case["framework"] not in rep["frameworks"]:
        notes.append("frameworks %s, expected %s" % (rep["frameworks"], case["framework"]))
    if case["origin"] and rep["origin"] != case["origin"]:
        notes.append("origin %s, expected %s" % (rep["origin"], case["origin"]))
    if case["workload_kind"] and rep["workload_kind"] and rep["workload_kind"] != case["workload_kind"]:
        notes.append("workload_kind %s, expected %s" % (rep["workload_kind"], case["workload_kind"]))
    if case["container_kind"]:
        kinds = {v["container_kind"] for v in mine.values()}
        if case["container_kind"] not in kinds:
            notes.append("container_kind %s, expected %s" % (kinds, case["container_kind"]))
    if case["host_network"] == "true" and not rep["host_network"]:
        notes.append("host_network not recorded on a hostNetwork pod")
    if case["secret_ref"]:
        want_name, want_key = case["secret_ref"].split("/", 1)
        ok = any(r.get("name") == want_name and r.get("key") == want_key
                 for r in rep["secret_refs"])
        if not ok:
            notes.append("secret_ref %s missing (got %s)" % (case["secret_ref"], rep["secret_refs"]))
    if case["no_value"] and case["no_value"] in rep["raw"]:
        notes.append("LEAKED SECRET VALUE into the sighting payload")
    if case["differs_from"]:
        other = by_id.get(case["differs_from"])
        if other:
            other_fps = {v["fingerprint"] for v in sightings_for(other, sightings).values()}
            if fps & other_fps:
                notes.append("fingerprint collides with %s — must be distinct"
                             % case["differs_from"])

    return ("fail" if notes else "pass"), notes


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def apply_cases():
    print(bold("applying cases"))
    kubectl("create", "namespace", "conformance", check=False)
    for f in sorted(CASES_DIR.glob("*.yaml")):
        kubectl("apply", "-f", str(f))
        print("  " + dim(f.name))


def inject_ephemeral(cases):
    """E5: attach an agent-shaped ephemeral container to a running pod."""
    for c in cases.values():
        if c.get("inject_ephemeral") != "true":
            continue
        pods = kubectl("get", "pods", "-n", c["namespace"],
                       "-l", "c=e5", "-o", "jsonpath={.items[*].metadata.name}",
                       check=False).split()
        if not pods:
            continue
        kubectl("debug", "-n", c["namespace"], pods[0],
                "--image=busybox:1.36", "--container=injected-agent",
                "--", "sleep", "infinity", check=False)
        print("  " + dim("injected ephemeral container into %s" % pods[0]))


def cleanup():
    print(bold("\ncleaning up"))
    for ns in CASE_NAMESPACES:
        kubectl("delete", "namespace", ns, "--wait=false", check=False)
        print("  " + dim("deleted namespace %s" % ns))


def structural_checks():
    """Assertions about the collector's own configuration, not about a workload."""
    rows = []
    wh = webhook_config()
    if wh is None:
        rows.append(("S1", "webhook configuration present", "fail", "not found"))
        return rows
    hook = wh["webhooks"][0]

    rows.append(("S1", "failurePolicy is Ignore (cannot block a deployment)",
                 "pass" if hook.get("failurePolicy") == "Ignore" else "fail",
                 hook.get("failurePolicy", "?")))
    rows.append(("S2", "sideEffects is None",
                 "pass" if hook.get("sideEffects") == "None" else "fail",
                 hook.get("sideEffects", "?")))
    to = hook.get("timeoutSeconds", 30)
    rows.append(("S3", "timeoutSeconds <= 5", "pass" if to <= 5 else "fail", str(to)))

    # kube-system and the collector's own namespace must be out of scope.
    sel = json.dumps(hook.get("namespaceSelector", {}))
    for name, ns in (("S4", "kube-system"), ("S5", COLLECTOR_NS)):
        rows.append((name, "%s excluded from scope" % ns,
                     "pass" if ns in sel else "fail",
                     "present" if ns in sel else "MISSING from namespaceSelector"))

    # No write verb on workloads anywhere in the collector's RBAC.
    out = kubectl("get", "clusterroles", "-o", "json", check=False)
    bad = []
    try:
        for cr in json.loads(out).get("items", []):
            if "discovery-agent" not in cr["metadata"]["name"]:
                continue
            for rule in cr.get("rules", []):
                res = set(rule.get("resources", []))
                verbs = set(rule.get("verbs", []))
                if res & {"pods", "deployments", "statefulsets", "daemonsets",
                          "jobs", "cronjobs", "namespaces"}:
                    if verbs & {"create", "update", "patch", "delete", "deletecollection", "*"}:
                        bad.append("%s: %s on %s" % (cr["metadata"]["name"],
                                                     sorted(verbs), sorted(res)))
    except json.JSONDecodeError:
        pass
    rows.append(("S6", "no write verb on workloads in RBAC",
                 "fail" if bad else "pass", "; ".join(bad) if bad else "read-only"))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="leave workloads deployed")
    ap.add_argument("--no-apply", action="store_true", help="assert against what is deployed")
    args = ap.parse_args()

    pods = require_collector()
    print(dim("collector pods: %s\n" % ", ".join(pods)))

    if not args.no_apply:
        apply_cases()
        print(dim("\nwaiting %ds for admission + pod creation to settle" % SETTLE_SECONDS))
        time.sleep(SETTLE_SECONDS)
        inject_ephemeral(declared_cases())
        time.sleep(5)

    cases = declared_cases()
    if not cases:
        raise SystemExit("no conformance cases found in the cluster")
    sightings = collected_sightings(pods)

    results = {}
    for cid, case in sorted(cases.items()):
        results[cid] = check(case, sightings, cases)

    # ---- report ----------------------------------------------------------
    groups = defaultdict(list)
    for cid, case in sorted(cases.items()):
        groups[cid[0]].append((cid, case, results[cid]))

    titles = {"A": "Signal coverage", "B": "Workload kinds",
              "C": "Fingerprint semantics", "D": "Origin classification",
              "E": "Evasion / known blind spots", "F": "False-positive guards",
              "G": "Scope and safety"}

    print(bold("\n" + "=" * 78))
    print(bold("DISCOVERY COLLECTOR CONFORMANCE"))
    print(bold("=" * 78))

    for letter in sorted(groups):
        print("\n" + bold(titles.get(letter, letter)))
        for cid, case, (verdict, notes) in groups[letter]:
            mark = {"pass": green("PASS"), "fail": red("FAIL"), "gap": yellow("GAP ")}[verdict]
            print("  %s %-4s %s" % (mark, cid, case["desc"]))
            for n in notes:
                print("           %s" % dim(n))

    print("\n" + bold("Collector configuration"))
    for cid, desc, verdict, detail in structural_checks():
        mark = {"pass": green("PASS"), "fail": red("FAIL")}[verdict]
        print("  %s %-4s %s" % (mark, cid, desc))
        if verdict == "fail":
            print("           %s" % dim(detail))
        results[cid] = (verdict, [])

    n_pass = sum(1 for v, _ in results.values() if v == "pass")
    n_fail = sum(1 for v, _ in results.values() if v == "fail")
    n_gap = sum(1 for v, _ in results.values() if v == "gap")

    print(bold("\n" + "-" * 78))
    print("%s   %s   %s   (%d checks)" % (
        green("%d passed" % n_pass),
        red("%d failed" % n_fail) if n_fail else dim("0 failed"),
        yellow("%d known gaps" % n_gap) if n_gap else dim("0 known gaps"),
        len(results)))
    print(dim("agents the collector reported: %d" % len(sightings)))
    if n_gap:
        print(dim("\nGAP = a real agent the collector cannot see. Not a failure — a\n"
                  "measured coverage limit. Watch this number; it must not grow."))
    print(bold("-" * 78))

    if not args.keep and not args.no_apply:
        cleanup()

    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
