#!/usr/bin/env python3
"""Descriptive pilot analysis of the A/B placement experiment.

Reads ``experiment/data/experiment_alerts.csv`` (written by
``ingest_experiment.py``) and, per condition, reports the repo, event and
unique-IP counts, the first AWS-quarantine action, the first genuine attacker
hit, the time between them, and the kill-chain actions seen.

    uv run python experiment/scripts/analyze_pilot.py

IMPORTANT — this is a *pilot*. With a single repo per condition, "condition" is
perfectly confounded with that one repo (its exact leak minute, which crawler
saw it first, which credential-abuse feed it landed in). Nothing here is a
causal effect of placement and no significance test is warranted. The output is
purely descriptive: a smoke-test that the pipeline attributes alerts correctly
and a first look at attacker behavior. The full 50-repo, matched-block, two-wave
design (experiment/DESIGN.md) is what powers the survival / log-rank comparison.
"""

import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from canary_token_analytics.taxonomy import classify_intent  # noqa: E402

ALERTS = ROOT / "experiment" / "data" / "experiment_alerts.csv"

# Order conditions along the DESIGN.md "how infra-flavored" gradient.
CONDITION_ORDER = ["env", "config_ini", "terraform_tfvars", "ci_deploy", "control"]


def _dt(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


def _fmt_delta(seconds):
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h{m:02d}m"
    return f"{m}m{s:02d}s"


def main():
    if not ALERTS.exists():
        sys.exit(f"missing {ALERTS} — run ingest_experiment.py first")
    df = pd.read_csv(ALERTS, dtype=str, keep_default_na=False)
    df["dt"] = df["datetime_utc"].map(_dt)

    print("=" * 72)
    print("A/B PLACEMENT EXPERIMENT — PILOT (descriptive only)")
    print("=" * 72)
    print(f"{len(df)} attributed alerts across "
          f"{df['repo_name'].nunique()} repos / "
          f"{df['condition'].nunique()} conditions "
          f"({df['date_utc'].min()} .. {df['date_utc'].max()})")

    present = [c for c in CONDITION_ORDER if c in set(df["condition"])]
    for cond in present:
        sub = df[df["condition"] == cond].sort_values("dt")
        repo = ", ".join(sorted(sub["repo_name"].unique()))
        attackers = sub[sub["alert_type"] == "ip_triggered"]
        quarantine = sub[(sub["event_name"] == "AttachUserPolicy") |
                         (sub["alert_type"] == "aws_internal")]

        print("\n" + "-" * 72)
        print(f"CONDITION: {cond}   (placement: {sub['placement'].iloc[0]})")
        print("-" * 72)
        print(f"  repo:                {repo}")
        print(f"  events:              {len(sub)}")
        print(f"  unique attacker IPs: {attackers['source_ip'].nunique()}"
              f"  ({', '.join(sorted(attackers['source_ip'].unique())) or '-'})")

        q_first = quarantine["dt"].min() if len(quarantine) else None
        a_first = attackers["dt"].min() if len(attackers) else None
        print(f"  first AWS quarantine (AttachUserPolicy/aws_internal): "
              f"{q_first.strftime('%H:%M UTC') if q_first is not None else '— none —'}")
        print(f"  first ATTACKER hit (ip_triggered):                    "
              f"{a_first.strftime('%H:%M UTC') if a_first is not None else '— none —'}")

        if q_first is not None and a_first is not None:
            delta = (a_first - q_first).total_seconds()
            if delta >= 0:
                print(f"  time quarantine -> first attacker hit: "
                      f"{_fmt_delta(delta)}")
            else:
                print(f"  attacker hit PRECEDED AWS quarantine by "
                      f"{_fmt_delta(-delta)}")

        # Kill-chain: phases/actions seen, in the order they first appeared.
        seen, order = set(), []
        for _, r in sub.iterrows():
            phase, _ = classify_intent(r["event_name"], r["source_ip"])
            key = (phase, r["event_name"])
            if key not in seen:
                seen.add(key)
                order.append(key)
        print("  kill-chain actions seen:")
        for phase, event in order:
            print(f"      [{phase}] {event}")

    print("\n" + "=" * 72)
    print("Pilot caveat: 1 repo per condition => placement is confounded with")
    print("repo/feed/leak-time. These are descriptive smoke-test numbers, not a")
    print("causal placement effect. The 50-repo matched-block design (2 waves)")
    print("is what enables the survival analysis and log-rank test.")
    print("=" * 72)


if __name__ == "__main__":
    main()
