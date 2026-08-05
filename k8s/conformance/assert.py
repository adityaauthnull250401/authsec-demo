#!/usr/bin/env python3
"""Evaluate discovery-collector conformance results.

Reads the collector's structured logs on stdin (one JSON object per line, as
emitted with dryRun=true) plus expectations.json, and prints a pass/fail report.

Exit status:
  0  every expectation met (documented gaps do not fail the run)
  1  at least one real failure
  2  usage / input error

Standard library only, so it runs anywhere kubectl does.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict

GREEN, RED, YELLOW, BLUE, DIM, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[34m", "\033[2m", "\033[0m",
)


class Result:
    def __init__(self) -> None:
        self.passed: list[tuple[str, str]] = []
        self.failed: list[tuple[str, str]] = []
        self.gaps: list[tuple[str, str]] = []
        self.skipped: list[tuple[str, str]] = []

    def ok(self, name: str, detail: str = "") -> None:
        self.passed.append((name, detail))

    def fail(self, name: str, detail: str) -> None:
        self.failed.append((name, detail))

    def gap(self, name: str, detail: str) -> None:
        self.gaps.append((name, detail))

    def skip(self, name: str, detail: str) -> None:
        self.skipped.append((name, detail))


def parse_sightings(stream) -> list[dict]:
    """Pull sighting payloads out of the collector's log stream.

    Handles both dry-run lines (full JSON payload under "sighting") and normal
    "agent sighted" lines, which carry only summary fields.
    """
    out = []
    for line in stream:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "sighting" in rec:
            try:
                out.append(json.loads(rec["sighting"]))
            except (json.JSONDecodeError, TypeError):
                continue
    return out


def index(sightings: list[dict]) -> dict[str, dict]:
    """Index by workload/container.

    A workload is sighted once via its own CREATE and again via the Pod's CREATE.
    Prefer the workload-kind sighting: it is the one whose actor is the human who
    ran apply, rather than the replicaset-controller.
    """
    best: dict[str, dict] = {}
    for s in sightings:
        k8s = s.get("metadata", {}).get("kubernetes") or {}
        name, container = k8s.get("workload_name"), k8s.get("container_name")
        if not name or not container:
            continue
        key = f"{name}/{container}"
        prev = best.get(key)
        if prev is None or k8s.get("sighted_via") != "Pod":
            best[key] = s
    return best


def check_cases(exp: dict, seen: dict[str, dict], r: Result) -> None:
    for key, want in exp["cases"].items():
        got = seen.get(key)
        is_gap = want.get("gap", False)
        why = want.get("why", "")

        if want["detect"]:
            if got is None:
                r.fail(key, f"expected DETECTED, got nothing — {why}")
                continue
            det = got.get("metadata", {}).get("detection", {})
            problems = []
            if "confidence" in want and det.get("confidence") != want["confidence"]:
                problems.append(f"confidence {det.get('confidence')!r} != {want['confidence']!r}")
            if "framework" in want and want["framework"] not in (det.get("frameworks") or []):
                problems.append(f"framework {want['framework']!r} not in {det.get('frameworks')}")
            if "signal" in want:
                kinds = {sig.get("kind") for sig in det.get("signals") or []}
                if want["signal"] not in kinds:
                    problems.append(f"signal {want['signal']!r} not in {sorted(kinds)}")
            if "origin" in want and got.get("deployment_origin") != want["origin"]:
                problems.append(f"origin {got.get('deployment_origin')!r} != {want['origin']!r}")
            if problems:
                r.fail(key, "; ".join(problems))
            else:
                bits = [det.get("confidence", "?")]
                if det.get("frameworks"):
                    bits.append(",".join(det["frameworks"]))
                r.ok(key, " ".join(bits))
        else:
            if got is None:
                (r.gap if is_gap else r.ok)(key, ("not detected — " + why) if is_gap else "correctly not detected")
            elif is_gap:
                # A gap that closed is good news, but it changes documented
                # behaviour, so surface it loudly rather than silently passing.
                r.fail(key, f"GAP CLOSED — this is now detected. Update expectations.json. ({why})")
            else:
                det = got.get("metadata", {}).get("detection", {})
                r.fail(key, f"FALSE POSITIVE: detected at {det.get('confidence')} via "
                            f"{[s.get('kind') for s in det.get('signals') or []]} — {why}")


def check_invariants(exp: dict, sightings: list[dict], seen: dict[str, dict], r: Result) -> None:
    inv = exp["invariants"]

    # --- one fingerprint per container, not per pod -------------------------
    name = "invariant: fingerprint unique per container"
    p, e = seen.get("c-c5-two-agents/planner"), seen.get("c-c5-two-agents/executor")
    if not p or not e:
        r.skip(name, "c-c5 containers not both sighted")
    elif p["fingerprint"] == e["fingerprint"]:
        r.fail(name, "planner and executor share a fingerprint — two agents in one pod are "
                     "indistinguishable, and no later schema change can recover the difference")
    else:
        r.ok(name, f"{p['fingerprint'][:8]} != {e['fingerprint'][:8]}")

    # --- namespace is part of the key --------------------------------------
    name = "invariant: fingerprint unique per namespace"
    fps = {
        s["fingerprint"]
        for s in sightings
        if (s.get("metadata", {}).get("kubernetes") or {}).get("workload_name") == "c-c6-samename"
    }
    if not fps:
        r.skip(name, "c-c6 not sighted")
    elif len(fps) < 2:
        r.fail(name, "identical workload+container in two namespaces produced ONE fingerprint — "
                     "namespace is missing from the key and the two would collapse into one agent")
    else:
        r.ok(name, f"{len(fps)} distinct fingerprints")

    # --- no secret values, anywhere ---------------------------------------
    name = "invariant: no secret values in any sighting"
    sentinel = inv["no_secret_values"]["sentinel"]
    blob = json.dumps(sightings)
    if sentinel in blob:
        leaks = [
            (s.get("metadata", {}).get("kubernetes") or {}).get("workload_name")
            for s in sightings if sentinel in json.dumps(s)
        ]
        r.fail(name, f"SECRET VALUE LEAKED in sightings for {sorted(set(leaks))} — "
                     f"the collector is exfiltrating credentials")
    else:
        r.ok(name, "sentinel absent from every payload")

    # --- secret refs recorded by name/key ---------------------------------
    name = "invariant: secret_refs recorded (name + key, no value)"
    got = seen.get("c-a6-generic-env/app")
    if not got:
        r.skip(name, "c-a6 not sighted")
    else:
        refs = got.get("metadata", {}).get("provisioning_hints", {}).get("secret_refs") or []
        match = [x for x in refs if x.get("name") == "c-creds" and x.get("key") == "openai"]
        if match:
            r.ok(name, f"{match[0]['kind']} {match[0]['name']}/{match[0]['key']}")
        else:
            r.fail(name, f"expected a secret_ref for c-creds/openai, got {refs} — "
                         f"provisioning cannot broker a credential it was never told about")

    # --- identity anchor --------------------------------------------------
    name = "invariant: identity_anchor on every sighting"
    missing = [
        k for k, s in seen.items()
        if not (s.get("metadata", {}).get("provisioning_hints") or {}).get("identity_anchor")
    ]
    if missing:
        r.fail(name, f"absent on {len(missing)}: {sorted(missing)[:4]}")
    else:
        r.ok(name, f"present on all {len(seen)}")

    # --- admission actor: the differentiator ------------------------------
    name = "invariant: admission sightings carry the authenticated actor"
    adm = [s for s in sightings
           if (s.get("metadata", {}).get("discovery") or {}).get("channel") == "admission"]
    if not adm:
        r.skip(name, "no admission-channel sightings")
    else:
        noactor = [s for s in adm if not (s.get("metadata", {}).get("actor") or {}).get("username")]
        if noactor:
            r.fail(name, f"{len(noactor)}/{len(adm)} admission sightings have no actor — "
                         f"deployer attribution is the one thing an after-the-fact scan cannot do")
        else:
            users = sorted({s["metadata"]["actor"]["username"] for s in adm})
            r.ok(name, f"{len(adm)} sightings, actors: {users[:3]}")

    # --- resync must never claim manual -----------------------------------
    name = "invariant: resync never claims manual origin"
    res = [s for s in sightings
           if (s.get("metadata", {}).get("discovery") or {}).get("channel") == "resync"]
    if not res:
        r.skip(name, "resync disabled or no resync sightings in this run")
    else:
        bad = [s for s in res if s.get("deployment_origin") == "manual"]
        withactor = [s for s in res if s.get("metadata", {}).get("actor")]
        if bad:
            r.fail(name, f"{len(bad)} resync sightings claim origin=manual — unknowable after the "
                         f"fact, so this is a fabrication")
        elif withactor:
            r.fail(name, f"{len(withactor)} resync sightings carry an actor block — there is no "
                         f"actor for a workload merely observed to exist")
        else:
            r.ok(name, f"{len(res)} resync sightings, none claim manual, none carry an actor")

    # --- schema version ---------------------------------------------------
    name = "invariant: schema_version on every sighting"
    missing = [k for k, s in seen.items() if not (s.get("metadata") or {}).get("schema_version")]
    if missing:
        r.fail(name, f"absent on {sorted(missing)[:4]}")
    else:
        r.ok(name, "present on all")


def report(r: Result, seen: dict[str, dict], extra: list[str]) -> int:
    print()
    print(f"{BLUE}{'=' * 78}{RESET}")
    print(f"{BLUE}  DISCOVERY COLLECTOR — CONFORMANCE REPORT{RESET}")
    print(f"{BLUE}{'=' * 78}{RESET}")

    if r.passed:
        print(f"\n{GREEN}PASS{RESET} ({len(r.passed)})")
        for n, d in r.passed:
            print(f"  {GREEN}✓{RESET} {n:<44} {DIM}{d}{RESET}")

    if r.gaps:
        print(f"\n{YELLOW}KNOWN GAPS{RESET} ({len(r.gaps)}) {DIM}— expected misses, not failures{RESET}")
        for n, d in r.gaps:
            print(f"  {YELLOW}○{RESET} {n}")
            print(f"    {DIM}{d}{RESET}")

    if r.skipped:
        print(f"\n{DIM}SKIPPED ({len(r.skipped)}){RESET}")
        for n, d in r.skipped:
            print(f"  {DIM}– {n}: {d}{RESET}")

    if r.failed:
        print(f"\n{RED}FAIL{RESET} ({len(r.failed)})")
        for n, d in r.failed:
            print(f"  {RED}✗{RESET} {n}")
            print(f"    {RED}{d}{RESET}")

    if extra:
        print(f"\n{BLUE}NOTES{RESET}")
        for line in extra:
            print(f"  • {line}")

    total = len(r.passed) + len(r.failed)
    print()
    print(f"{BLUE}{'-' * 78}{RESET}")
    print(f"  agents sighted: {len(seen)}   "
          f"asserted: {total}   "
          f"{GREEN}pass {len(r.passed)}{RESET}   "
          f"{RED}fail {len(r.failed)}{RESET}   "
          f"{YELLOW}gaps {len(r.gaps)}{RESET}   "
          f"{DIM}skipped {len(r.skipped)}{RESET}")
    verdict = f"{RED}FAILED{RESET}" if r.failed else f"{GREEN}PASSED{RESET}"
    print(f"  verdict: {verdict}")
    print(f"{BLUE}{'-' * 78}{RESET}\n")
    return 1 if r.failed else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--expectations", required=True)
    ap.add_argument("--logs", default="-", help="collector log file, or - for stdin")
    ap.add_argument("--note", action="append", default=[],
                    help="extra finding from run.sh phases, shown under NOTES")
    ap.add_argument("--json-out", help="write machine-readable results here")
    args = ap.parse_args()

    try:
        with open(args.expectations) as fh:
            exp = json.load(fh)
    except OSError as err:
        print(f"cannot read expectations: {err}", file=sys.stderr)
        return 2

    stream = sys.stdin if args.logs == "-" else open(args.logs)
    sightings = parse_sightings(stream)
    if not sightings:
        print(f"{RED}no sightings parsed from the collector log.{RESET}", file=sys.stderr)
        print("Is the collector running with dryRun=true, and did the cases apply?", file=sys.stderr)
        return 2

    seen = index(sightings)
    r = Result()
    check_cases(exp, seen, r)
    check_invariants(exp, sightings, seen, r)
    code = report(r, seen, args.note)

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump({
                "passed": r.passed, "failed": r.failed,
                "gaps": r.gaps, "skipped": r.skipped,
                "agents_sighted": len(seen),
            }, fh, indent=2)

    return code


if __name__ == "__main__":
    sys.exit(main())
