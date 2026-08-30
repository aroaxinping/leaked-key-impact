#!/usr/bin/env python3
"""Pre-flight checklist for the honeypot fleet — run AFTER build_repos.py, BEFORE pushing.

Confirms, without touching the network:

    1. Registry integrity
       - 50 rows (10 blocks x 5 conditions); 10 control, 40 non-control.
       - every assigned repo (block_assignment.csv) has exactly one registry row;
       - condition/placement agree between assignment and registry.

    2. Token identity (non-control repos)
       - non-empty access_key_id AND non-empty canarytoken_id AND alert_channel.

    3. Control hygiene
       - control rows have NO canarytoken_id / alert_channel and an obviously
         fake access_key_id.

    4. Build completeness
       - experiment/build/<repo_name>/ exists for every assigned repo;
       - it contains the expected placement file;
       - NO unresolved placeholders remain (__CANARY_ACCESS_KEY_ID__ /
         __CANARY_SECRET_ACCESS_KEY__);
       - a real-looking live AWS key ID (AKIA... that is not the control fake)
         actually landed in each non-control repo's placement file.

Prints a readiness summary and exits non-zero if anything would block a safe
deploy. This never makes network calls, and never runs git/gh.

Usage:
    python validate_deploy.py
    python validate_deploy.py --quiet      # summary + failures only
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(HERE)
ASSIGNMENT_CSV = os.path.join(EXPERIMENT_DIR, "block_assignment.csv")
REGISTRY_CSV = os.path.join(EXPERIMENT_DIR, "token_registry.csv")
BUILD_DIR = os.path.join(EXPERIMENT_DIR, "build")

ACCESS_KEY_PLACEHOLDER = "__CANARY_ACCESS_KEY_ID__"
SECRET_PLACEHOLDER = "__CANARY_SECRET_ACCESS_KEY__"
CONTROL_FAKE_ACCESS_KEY = "AKIAEXAMPLEFAKE00000"

EXPECTED_TOTAL = 50
EXPECTED_CONTROL = 10
AKIA_RE = re.compile(r"AKIA[0-9A-Z]{12,}")


def truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y", "t"}


class Report:
    """Collects PASS/FAIL/WARN lines and tracks overall readiness."""

    def __init__(self, quiet: bool):
        self.quiet = quiet
        self.failures = 0
        self.warnings = 0

    def ok(self, msg: str):
        if not self.quiet:
            print(f"  PASS  {msg}")

    def fail(self, msg: str):
        self.failures += 1
        print(f"  FAIL  {msg}")

    def warn(self, msg: str):
        self.warnings += 1
        print(f"  WARN  {msg}")

    def section(self, title: str):
        if not self.quiet:
            print(f"\n{title}")


def load_csv(path: str, label: str):
    if not os.path.exists(path):
        sys.exit(f"ERROR: {label} not found: {path}")
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def check_registry_integrity(assignment, registry, rep: Report):
    rep.section("1. Registry integrity")

    n = len(registry)
    (rep.ok if n == EXPECTED_TOTAL else rep.fail)(
        f"registry has {n} rows (expected {EXPECTED_TOTAL}).")

    controls = [r for r in registry if truthy(r.get("is_control", ""))]
    nc = len(controls)
    (rep.ok if nc == EXPECTED_CONTROL else rep.fail)(
        f"{nc} control rows (expected {EXPECTED_CONTROL}).")

    non_controls = len(registry) - nc
    (rep.ok if non_controls == EXPECTED_TOTAL - EXPECTED_CONTROL else rep.fail)(
        f"{non_controls} non-control rows "
        f"(expected {EXPECTED_TOTAL - EXPECTED_CONTROL}).")

    assign_names = {r["repo_name"] for r in assignment}
    reg_names = [r["repo_name"] for r in registry]
    reg_set = set(reg_names)

    if len(reg_names) != len(reg_set):
        dupes = sorted({x for x in reg_names if reg_names.count(x) > 1})
        rep.fail(f"duplicate repo_name(s) in registry: {dupes}")
    else:
        rep.ok("no duplicate repo_name in registry.")

    missing = sorted(assign_names - reg_set)
    extra = sorted(reg_set - assign_names)
    (rep.ok if not missing else rep.fail)(
        "every assigned repo is in the registry."
        if not missing else f"assigned repos missing from registry: {missing}")
    if extra:
        rep.warn(f"registry has repos not in the assignment: {extra}")

    by_name = {r["repo_name"]: r for r in registry}
    mismatched = []
    for a in assignment:
        r = by_name.get(a["repo_name"])
        if not r:
            continue
        if r.get("condition") != a.get("condition") or \
           r.get("placement") != a.get("placement"):
            mismatched.append(a["repo_name"])
    (rep.ok if not mismatched else rep.fail)(
        "condition/placement agree between assignment and registry."
        if not mismatched else f"condition/placement mismatch: {mismatched}")


def check_token_identity(registry, rep: Report):
    rep.section("2. Token identity (non-control)")
    bad = []
    for r in registry:
        if truthy(r.get("is_control", "")):
            continue
        repo = r["repo_name"]
        if not r.get("access_key_id", "").strip():
            bad.append(f"{repo}: empty access_key_id")
        if not r.get("canarytoken_id", "").strip():
            bad.append(f"{repo}: empty canarytoken_id")
        if not r.get("alert_channel", "").strip():
            bad.append(f"{repo}: empty alert_channel")
    if bad:
        for b in bad:
            rep.fail(b)
    else:
        rep.ok("all non-control repos have access_key_id + canarytoken_id + "
               "alert_channel.")


def check_control_hygiene(registry, rep: Report):
    rep.section("3. Control hygiene")
    problems = []
    for r in registry:
        if not truthy(r.get("is_control", "")):
            continue
        repo = r["repo_name"]
        if r.get("canarytoken_id", "").strip():
            problems.append(f"{repo}: control has a canarytoken_id (should be empty)")
        if r.get("alert_channel", "").strip():
            problems.append(f"{repo}: control has an alert_channel (should be empty)")
        akid = r.get("access_key_id", "").strip()
        if akid and akid != CONTROL_FAKE_ACCESS_KEY:
            # A control must never carry a live-looking key.
            problems.append(
                f"{repo}: control access_key_id is not the fake value "
                f"({akid!r}); a live key in a control would corrupt the design.")
    if problems:
        for p in problems:
            rep.fail(p)
    else:
        rep.ok("controls carry no live token and use the fake access key.")


def check_build_completeness(assignment, registry, rep: Report):
    rep.section("4. Build completeness")
    by_name = {r["repo_name"]: r for r in registry}

    if not os.path.isdir(BUILD_DIR):
        rep.fail(f"build dir does not exist: {BUILD_DIR} — run build_repos.py.")
        return

    for a in assignment:
        repo = a["repo_name"]
        out_dir = os.path.join(BUILD_DIR, repo)
        r = by_name.get(repo, {})
        is_control = truthy(r.get("is_control", ""))

        if not os.path.isdir(out_dir):
            rep.fail(f"{repo}: no built directory ({out_dir}).")
            continue

        # Expected placement file present?
        placement = a.get("placement", "")
        placement_path = os.path.join(out_dir, placement)
        if placement and not os.path.exists(placement_path):
            rep.fail(f"{repo}: placement file missing ({placement}).")

        # Scan all text files for unresolved placeholders and stray live keys.
        unresolved = False
        live_key_seen = False
        for dirpath, _dn, filenames in os.walk(out_dir):
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        content = f.read()
                except (UnicodeDecodeError, OSError):
                    continue
                if ACCESS_KEY_PLACEHOLDER in content or \
                   SECRET_PLACEHOLDER in content:
                    unresolved = True
                for m in AKIA_RE.findall(content):
                    if m != CONTROL_FAKE_ACCESS_KEY:
                        live_key_seen = True

        if unresolved:
            rep.fail(f"{repo}: unresolved placeholder(s) remain in built repo.")
        else:
            rep.ok(f"{repo}: no unresolved placeholders.")

        if is_control:
            if live_key_seen:
                rep.fail(f"{repo}: live-looking AWS key found in a CONTROL repo.")
        else:
            if not live_key_seen:
                rep.fail(f"{repo}: no live-looking AWS key ID landed in the repo.")


def summary(assignment, registry, rep: Report):
    print("\n" + "=" * 60)
    print("READINESS SUMMARY")
    print("=" * 60)
    print(f"  assigned repos : {len(assignment)}")
    print(f"  registry rows  : {len(registry)}")
    controls = sum(1 for r in registry if truthy(r.get('is_control', '')))
    print(f"  control / live : {controls} / {len(registry) - controls}")
    print(f"  build dir      : {BUILD_DIR}")
    print(f"  warnings       : {rep.warnings}")
    print(f"  failures       : {rep.failures}")
    print("-" * 60)
    if rep.failures == 0:
        print("  RESULT: READY to deploy. Proceed per ROLLOUT.md.")
    else:
        print(f"  RESULT: NOT READY — resolve {rep.failures} failure(s) first.")
    print("=" * 60)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quiet", action="store_true",
                    help="print only failures, warnings and the summary.")
    args = ap.parse_args()

    assignment = load_csv(ASSIGNMENT_CSV, "block_assignment.csv")
    registry = load_csv(REGISTRY_CSV, "token_registry.csv")

    rep = Report(quiet=args.quiet)
    check_registry_integrity(assignment, registry, rep)
    check_token_identity(registry, rep)
    check_control_hygiene(registry, rep)
    check_build_completeness(assignment, registry, rep)
    summary(assignment, registry, rep)

    return 1 if rep.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
