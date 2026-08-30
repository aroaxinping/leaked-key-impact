#!/usr/bin/env python3
"""Assemble ready-to-push honeypot repositories from templates + the token registry.

For each assigned repo this script:

    1. Copies the matching condition template
       (experiment/templates/<condition>/) into a fresh output directory
       (experiment/build/<repo_name>/).
    2. Substitutes the credential placeholders

           __CANARY_ACCESS_KEY_ID__      -> registry access_key_id
           __CANARY_SECRET_ACCESS_KEY__  -> the secret for that token

       in the credential-bearing file (and anywhere else they appear).

The access key ID comes from experiment/token_registry.csv. The AWS *secret*
access key is intentionally NOT stored in the registry or anywhere in the repo;
it is supplied at build time out-of-band:

    - per repo via env var  CANARY_SECRET__<REPO_NAME>   (repo name upper-cased,
      non-alphanumerics -> '_'), or
    - interactively, when --prompt-secrets is passed and stdin is a TTY.

Control repos are the exception: they carry an obviously fake, non-live key and
need no real secret, so they are built with fixed fake values and never prompt.

This is pure filesystem work. It performs NO network calls, NO git, NO gh.

Usage
-----
    python build_repos.py                 # build every assigned repo
    python build_repos.py --dry-run       # show what would happen, write nothing
    python build_repos.py --only feature-store-sync churn-model-service
    python build_repos.py --prompt-secrets # ask for each live secret at the prompt
    python build_repos.py --clean          # remove build/ dirs before building

Exit codes: 0 = success, non-zero = a guard failed (nothing partial is pushed).
"""

from __future__ import annotations

import argparse
import csv
import getpass
import os
import re
import shutil
import sys

# ---------------------------------------------------------------------------
# Paths (all resolved relative to this file, so cwd does not matter)
# ---------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
EXPERIMENT_DIR = os.path.dirname(HERE)                       # experiment/
ASSIGNMENT_CSV = os.path.join(EXPERIMENT_DIR, "block_assignment.csv")
REGISTRY_CSV = os.path.join(EXPERIMENT_DIR, "token_registry.csv")
TEMPLATES_DIR = os.path.join(EXPERIMENT_DIR, "templates")
BUILD_DIR = os.path.join(EXPERIMENT_DIR, "build")

ACCESS_KEY_PLACEHOLDER = "__CANARY_ACCESS_KEY_ID__"
SECRET_PLACEHOLDER = "__CANARY_SECRET_ACCESS_KEY__"

# Obviously-fake values baked into control repos (never a live key/secret).
CONTROL_FAKE_ACCESS_KEY = "AKIAEXAMPLEFAKE00000"
CONTROL_FAKE_SECRET = "wFAKEwFAKEwFAKEwFAKEwFAKEwFAKEwFAKE00000"

# Files we never rewrite/copy content into as text (leave binaries untouched).
TEXT_SUBSTITUTION_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf",
    ".zip", ".gz", ".parquet", ".pyc", ".so", ".dylib",
}


def truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y", "t"}


def load_rows() -> list[dict]:
    """Load the registry and join it against the assignment on repo_name.

    The registry is the source of truth for what gets built (it carries the
    credentials). The assignment is used to cross-check that every planned repo
    is present and that condition/placement agree between the two files.
    """
    if not os.path.exists(REGISTRY_CSV):
        sys.exit(f"ERROR: token registry not found: {REGISTRY_CSV}\n"
                 f"       Fill it in at deploy time (see token_registry_schema.md).")
    if not os.path.exists(ASSIGNMENT_CSV):
        sys.exit(f"ERROR: block assignment not found: {ASSIGNMENT_CSV}\n"
                 f"       Run plan_blocks.py first.")

    with open(ASSIGNMENT_CSV, newline="") as f:
        assignment = {r["repo_name"]: r for r in csv.DictReader(f)}
    with open(REGISTRY_CSV, newline="") as f:
        registry = list(csv.DictReader(f))

    reg_names = {r["repo_name"] for r in registry}
    missing = sorted(set(assignment) - reg_names)
    if missing:
        sys.exit("ERROR: these assigned repos are absent from the registry:\n  "
                 + "\n  ".join(missing))

    # Cross-check condition/placement agreement where both files have the repo.
    for r in registry:
        a = assignment.get(r["repo_name"])
        if a is None:
            sys.exit(f"ERROR: registry repo '{r['repo_name']}' is not in the "
                     f"assignment plan.")
        for col in ("condition", "placement"):
            if r.get(col) != a.get(col):
                sys.exit(f"ERROR: '{r['repo_name']}' {col} mismatch: "
                         f"registry={r.get(col)!r} assignment={a.get(col)!r}")
    return registry


def secret_env_var(repo_name: str) -> str:
    key = re.sub(r"[^A-Za-z0-9]", "_", repo_name).upper()
    return f"CANARY_SECRET__{key}"


def resolve_secret(row: dict, prompt: bool) -> str:
    """Return the AWS secret for a repo, out-of-band. Never read from registry."""
    if truthy(row.get("is_control", "")):
        return CONTROL_FAKE_SECRET

    env_var = secret_env_var(row["repo_name"])
    secret = os.environ.get(env_var)
    if secret:
        return secret

    if prompt and sys.stdin.isatty():
        secret = getpass.getpass(
            f"  secret for {row['repo_name']} ({env_var} unset): ")
        if secret:
            return secret

    # No secret available. Caller decides whether this is fatal (real build) or
    # tolerable (dry run).
    return ""


def iter_template_files(template_dir: str):
    for dirpath, _dirnames, filenames in os.walk(template_dir):
        for name in filenames:
            src = os.path.join(dirpath, name)
            rel = os.path.relpath(src, template_dir)
            yield src, rel


def build_one(row: dict, secret: str, dry_run: bool) -> list[str]:
    """Materialize one repo into build/<repo_name>/. Returns a list of notes."""
    repo = row["repo_name"]
    condition = row["condition"]
    template_dir = os.path.join(TEMPLATES_DIR, condition)
    out_dir = os.path.join(BUILD_DIR, repo)
    notes = []

    if not os.path.isdir(template_dir):
        sys.exit(f"ERROR: template dir missing for condition '{condition}': "
                 f"{template_dir}")

    access_key = (CONTROL_FAKE_ACCESS_KEY
                  if truthy(row.get("is_control", ""))
                  else row.get("access_key_id", "").strip())

    replacements = {
        ACCESS_KEY_PLACEHOLDER: access_key,
        SECRET_PLACEHOLDER: secret,
    }

    placement_hit = False
    for src, rel in iter_template_files(template_dir):
        dst = os.path.join(out_dir, rel)
        ext = os.path.splitext(src)[1].lower()

        if ext in TEXT_SUBSTITUTION_SKIP_EXT:
            notes.append(f"copy (binary)   {rel}")
            if not dry_run:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
            continue

        try:
            with open(src, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            notes.append(f"copy (non-utf8) {rel}")
            if not dry_run:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
            continue

        subbed = content
        for placeholder, value in replacements.items():
            if placeholder in subbed:
                subbed = subbed.replace(placeholder, value)
                if placeholder == ACCESS_KEY_PLACEHOLDER:
                    placement_hit = True

        tag = "substitute" if subbed != content else "copy (text)  "
        notes.append(f"{tag}    {rel}")
        if not dry_run:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w", encoding="utf-8") as f:
                f.write(subbed)

    if not placement_hit:
        notes.append(f"[WARN] no {ACCESS_KEY_PLACEHOLDER} found in template "
                     f"'{condition}' — check the template.")
    return notes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be built; write nothing.")
    ap.add_argument("--only", nargs="+", metavar="REPO",
                    help="build only these repo_name(s).")
    ap.add_argument("--prompt-secrets", action="store_true",
                    help="prompt for each live secret not found in the environment.")
    ap.add_argument("--clean", action="store_true",
                    help="remove each repo's build dir before rebuilding.")
    args = ap.parse_args()

    rows = load_rows()
    if args.only:
        wanted = set(args.only)
        rows = [r for r in rows if r["repo_name"] in wanted]
        unknown = wanted - {r["repo_name"] for r in rows}
        if unknown:
            sys.exit(f"ERROR: --only names not in registry: {sorted(unknown)}")

    # ------------------------------------------------------------------
    # GUARD: refuse to run if any non-control repo lacks a token identity,
    # or (for a real build) lacks a resolvable secret. Collect ALL problems
    # first so the operator sees the full picture, then bail.
    # ------------------------------------------------------------------
    problems = []
    warnings = []
    secrets = {}
    for r in rows:
        repo = r["repo_name"]
        is_control = truthy(r.get("is_control", ""))
        if not is_control:
            if not r.get("access_key_id", "").strip():
                problems.append(f"{repo}: empty access_key_id (non-control).")
            # canarytoken_id is analysis metadata only — it maps alerts back to
            # this repo and is back-filled from the first alert email (the memo
            # is a unique per-repo key). It is NOT needed to build the repo, so
            # its absence is a warning, not a fatal error.
            if not r.get("canarytoken_id", "").strip():
                warnings.append(f"{repo}: canarytoken_id not yet known "
                                "(back-fill from first alert).")
        secret = resolve_secret(r, prompt=args.prompt_secrets)
        secrets[repo] = secret
        if not is_control and not secret and not args.dry_run:
            problems.append(
                f"{repo}: no secret available (set {secret_env_var(repo)} "
                f"or use --prompt-secrets).")

    if warnings:
        print("Warnings (non-fatal):", file=sys.stderr)
        for w in warnings:
            print(f"  - {w}", file=sys.stderr)
    if problems:
        print("Refusing to build — guard failed:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        if args.dry_run:
            print("\n(--dry-run: missing secrets are tolerated above, but the "
                  "empty token-identity errors are still fatal.)", file=sys.stderr)
        return 2

    # ------------------------------------------------------------------
    # Build.
    # ------------------------------------------------------------------
    mode = "DRY RUN — nothing will be written" if args.dry_run else "BUILDING"
    print(f"{mode}: {len(rows)} repo(s) -> {BUILD_DIR}\n")

    for r in rows:
        repo = r["repo_name"]
        flag = "control" if truthy(r.get("is_control", "")) else r["condition"]
        out_dir = os.path.join(BUILD_DIR, repo)

        if args.clean and not args.dry_run and os.path.isdir(out_dir):
            shutil.rmtree(out_dir)

        print(f"[{flag:>16}] {repo}")
        notes = build_one(r, secrets[repo], args.dry_run)
        for n in notes:
            print(f"      {n}")
        print()

    print(f"Done. {len(rows)} repo(s) "
          f"{'previewed' if args.dry_run else 'written to ' + BUILD_DIR}.")
    if not args.dry_run:
        print("Next: run validate_deploy.py, then push per ROLLOUT.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
