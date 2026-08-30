#!/usr/bin/env python3
"""Generate the randomized block assignment for the placement A/B experiment.

This script builds the master assignment table that maps 50 honeypot repositories
(10 matched blocks x 5 conditions) to experimental conditions, waves, and the
credential-bearing file ("placement") that defines each condition.

Design summary
--------------
Factor under test: PLACEMENT of a leaked AWS access key, an ordered gradient of
"how infrastructure/production-flavored the key looks":

    1. env               -> .env                            (generic app secret, baseline)
    2. config_ini        -> config.ini                      (service/cloud config)
    3. terraform_tfvars  -> terraform.tfvars                (infrastructure-as-code)
    4. ci_deploy         -> .github/workflows/deploy.yml     (CI/CD deploy credentials)
    5. control           -> .env (OBVIOUSLY FAKE key)        (baseline scanning noise)

Blocking: 10 matched blocks. Within a block the 5 repos are created together and
made as similar as possible (same day, same generation recipe, comparable size and
history), differing only in the credential-bearing file. Blocking removes
between-block nuisance variation (calendar effects, feed timing) from the
placement contrast, mirroring a randomized complete block design.

Temporal replication: 2 launch waves of 5 blocks each (blocks 1-5 = wave 1,
blocks 6-10 = wave 2). Wave lets us check that the placement effect replicates
across time rather than being an artifact of one credential-feed snapshot.

Randomization: a FIXED seed, random.Random(42), assigns the 5 conditions to the
5 repos within every block independently, and draws repo names from a shuffled
pool. Fixing the seed makes the whole allocation reproducible and auditable.

The credential placeholders written into the live (non-control) files elsewhere are
    __CANARY_ACCESS_KEY_ID__ / __CANARY_SECRET_ACCESS_KEY__
The control condition uses obviously fake, non-live placeholder values instead.

Output: block_assignment.csv with columns
    repo_name, block_id, wave, condition, placement, is_control
"""

import csv
import os
import random

SEED = 42

# Ordered gradient of conditions -> (condition key, placement filename, is_control)
# The order is meaningful: it is the "infra-flavored" gradient used for the trend test.
CONDITIONS = [
    ("env",              ".env",                          False),
    ("config_ini",       "config.ini",                    False),
    ("terraform_tfvars", "terraform.tfvars",              False),
    ("ci_deploy",        ".github/workflows/deploy.yml",  False),
    ("control",          ".env",                          True),
]

N_BLOCKS = 10
BLOCKS_PER_WAVE = 5  # blocks 1-5 -> wave 1, blocks 6-10 -> wave 2

# Pool of realistic, distinct data/ML/tech project names matching the owner's
# data-analyst / data-science creator brand. None reveals the condition it lands on.
# >= 50 names required (one per repo); extras give slack and are simply unused.
REPO_NAME_POOL = [
    "feature-store-sync",
    "churn-model-service",
    "etl-warehouse-loader",
    "embeddings-indexer",
    "recsys-batch",
    "ab-test-analyzer",
    "data-quality-monitor",
    "ml-registry-gateway",
    "customer-ltv-pipeline",
    "clickstream-aggregator",
    "cohort-retention-report",
    "propensity-scoring-api",
    "kafka-events-ingestor",
    "airflow-dag-catalog",
    "dbt-metrics-layer",
    "vector-search-service",
    "session-replay-parser",
    "anomaly-detect-daemon",
    "forecast-serving-api",
    "sentiment-scorer-batch",
    "lookalike-audience-builder",
    "attribution-model-runner",
    "spark-etl-orchestrator",
    "snowflake-sync-agent",
    "redshift-copy-loader",
    "bigquery-export-job",
    "delta-lake-compactor",
    "streaming-metrics-relay",
    "model-drift-tracker",
    "label-studio-connector",
    "experiment-tracker-svc",
    "hyperparam-sweep-runner",
    "batch-inference-worker",
    "onlinestore-cache-warmer",
    "training-data-validator",
    "reco-candidate-gen",
    "uplift-model-trainer",
    "nlp-topic-modeler",
    "image-embeddings-worker",
    "time-series-featurizer",
    "graph-features-builder",
    "user-segment-exporter",
    "funnel-analytics-engine",
    "pricing-elasticity-model",
    "fraud-signals-collector",
    "gdpr-anon-pipeline",
    "warehouse-schema-migrator",
    "notebook-scheduler-svc",
    "dataset-lineage-tracker",
    "geo-clustering-service",
    "churn-alert-dispatcher",
    "revenue-mix-reporter",
    "ml-feature-backfill",
    "eventlog-dedup-worker",
    "propensity-batch-scorer",
]


def build_assignment(seed: int = SEED):
    rng = random.Random(seed)

    # Draw a reproducible, shuffled pool of names, then hand them out in order.
    pool = list(REPO_NAME_POOL)
    if len(pool) < N_BLOCKS * len(CONDITIONS):
        raise ValueError(
            f"Need >= {N_BLOCKS * len(CONDITIONS)} names, pool has {len(pool)}."
        )
    rng.shuffle(pool)
    name_iter = iter(pool)

    rows = []
    for block_id in range(1, N_BLOCKS + 1):
        wave = 1 if block_id <= BLOCKS_PER_WAVE else 2

        # Randomize which condition each of the block's 5 repos receives.
        conditions = list(CONDITIONS)
        rng.shuffle(conditions)

        for condition, placement, is_control in conditions:
            repo_name = next(name_iter)
            rows.append(
                {
                    "repo_name": repo_name,
                    "block_id": block_id,
                    "wave": wave,
                    "condition": condition,
                    "placement": placement,
                    "is_control": is_control,
                }
            )
    return rows


def write_csv(rows, path):
    fieldnames = ["repo_name", "block_id", "wave", "condition", "placement", "is_control"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def print_summary(rows):
    print(f"Seed: {SEED}  (random.Random({SEED}))")
    print(f"Total repos: {len(rows)}  ({N_BLOCKS} blocks x {len(CONDITIONS)} conditions)")

    # Condition counts (should be 10 each).
    by_condition = {}
    for r in rows:
        by_condition[r["condition"]] = by_condition.get(r["condition"], 0) + 1
    print("\nRepos per condition:")
    for condition, placement, _ in CONDITIONS:
        print(f"  {condition:<18} {placement:<32} n={by_condition[condition]}")

    # Wave balance.
    by_wave = {}
    for r in rows:
        by_wave[r["wave"]] = by_wave.get(r["wave"], 0) + 1
    print("\nRepos per wave:")
    for wave in sorted(by_wave):
        print(f"  wave {wave}: n={by_wave[wave]}")

    # Sanity: every block has all 5 conditions exactly once.
    ok = True
    for block_id in range(1, N_BLOCKS + 1):
        conds = sorted(r["condition"] for r in rows if r["block_id"] == block_id)
        if conds != sorted(c[0] for c in CONDITIONS):
            ok = False
            print(f"  [WARN] block {block_id} malformed: {conds}")
    print(f"\nEach block holds all 5 conditions exactly once: {ok}")

    print("\nFirst block (block 1) assignment:")
    for r in rows:
        if r["block_id"] == 1:
            print(f"  {r['repo_name']:<28} -> {r['condition']:<18} ({r['placement']})")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(here, "block_assignment.csv")
    rows = build_assignment(SEED)
    write_csv(rows, out_path)
    print_summary(rows)
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()
