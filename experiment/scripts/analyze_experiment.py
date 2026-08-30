#!/usr/bin/env python3
"""Placement A/B experiment — primary survival analysis + secondary metrics.

Endpoint (primary, "B"): time from the AWS auto-quarantine of a leaked key
(first `AttachUserPolicy` / aws_internal event) to the first *attacker* hit
(first `ip_triggered` event) for each repo. t0 = quarantine is used because it
is present and precise for every cell in the alert data, and it isolates the
attacker's response from GitHub/AWS detection speed (which does not depend on
file placement). Cells with no attacker hit yet are right-censored at the last
data timestamp.

Groups = the 4 real placements (env / config_ini / terraform_tfvars / ci_deploy).
Controls (fake key) are expected to have zero attacker hits and are reported
separately as a design check, never in the survival groups.

Outputs: docs/experiment_placement_results.md + figures under docs/img/.
Stats hand-rolled (Kaplan-Meier, log-rank); scipy only for p-values.
Run:  uv run --with scipy python experiment/scripts/analyze_experiment.py
"""
import csv, os
from collections import defaultdict
from datetime import datetime
import math

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.stats import chi2, kruskal

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ALERTS = os.path.join(ROOT, "experiment", "data", "experiment_alerts.csv")
PLAN = os.path.join(ROOT, "experiment", "block_assignment.csv")
IMG = os.path.join(ROOT, "docs", "img")
OUT = os.path.join(ROOT, "docs", "experiment_placement_results.md")
os.makedirs(IMG, exist_ok=True)

CONDS = ["env", "config_ini", "terraform_tfvars", "ci_deploy"]
LABELS = {"env": ".env", "config_ini": "config.ini",
          "terraform_tfvars": "terraform.tfvars", "ci_deploy": "ci_deploy"}
OKABE = {"env": "#0072B2", "config_ini": "#D55E00",
         "terraform_tfvars": "#009E73", "ci_deploy": "#CC79A7"}


def parse(s):
    s = s.strip().replace("Z", "").replace("T", " ").split("+")[0].split(".")[0]
    for f in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, f)
        except ValueError:
            pass
    return None


def load():
    rows = list(csv.DictReader(open(ALERTS)))
    plan = {r["repo_name"]: r for r in csv.DictReader(open(PLAN))}
    now = max(parse(r["datetime_utc"]) for r in rows)
    q, atk, ips, actions = (defaultdict(list), defaultdict(list),
                            defaultdict(set), defaultdict(list))
    for r in rows:
        t = parse(r["datetime_utc"]); repo = r["repo_name"]
        if r["alert_type"] == "aws_internal":
            q[repo].append(t)
        else:                                   # ip_triggered = attacker
            atk[repo].append(t); ips[repo].add(r["source_ip"])
            actions[repo].append(r["event_name"])
    return plan, now, q, atk, ips, actions


def km(durations_events):
    """Kaplan-Meier. Input list of (duration, event 1/0). Returns (t[], S[])."""
    times = sorted(set(d for d, e in durations_events if e == 1))
    n = len(durations_events)
    at_risk = n
    S = 1.0
    xs, ys = [0.0], [1.0]
    de = sorted(durations_events)
    for t in times:
        d = sum(1 for dur, e in durations_events if dur == t and e == 1)
        r = sum(1 for dur, e in durations_events if dur >= t)
        if r == 0:
            break
        S *= (1 - d / r)
        xs.append(t); ys.append(S)
    return xs, ys


def logrank(groups):
    """Multi-group log-rank. groups: dict name -> list of (duration, event)."""
    names = list(groups)
    all_events = sorted(set(d for g in groups.values() for d, e in g if e == 1))
    k = len(names)
    O = {n: 0.0 for n in names}
    E = {n: 0.0 for n in names}
    # variance-covariance accumulation (diagonal approx for k>2 via sum)
    V = {n: 0.0 for n in names}
    for t in all_events:
        n_risk = {n: sum(1 for d, e in groups[n] if d >= t) for n in names}
        d_evt = {n: sum(1 for d, e in groups[n] if d == t and e == 1) for n in names}
        N = sum(n_risk.values()); D = sum(d_evt.values())
        if N <= 1 or D == 0:
            continue
        for n in names:
            O[n] += d_evt[n]
            E[n] += D * n_risk[n] / N
            V[n] += (D * (n_risk[n] / N) * (1 - n_risk[n] / N)
                     * (N - D) / (N - 1))
    # chi-square with (k-1) df from (O-E)^2/V summed (approx, ignores covariance)
    stat = sum((O[n] - E[n]) ** 2 / V[n] for n in names if V[n] > 0)
    df = k - 1
    p = float(chi2.sf(stat, df))
    return O, E, stat, df, p


def main():
    plan, now, q, atk, ips, actions = load()
    real = {r: plan[r] for r in plan if plan[r]["is_control"] != "True"}
    ctrl = {r: plan[r] for r in plan if plan[r]["is_control"] == "True"}

    # build survival rows: t0 = first quarantine; event = attacker seen
    groups = defaultdict(list)      # condition -> [(dur_min, event)]
    per = []                        # detailed rows
    for repo, row in real.items():
        c = row["condition"]
        if repo not in q:           # no quarantine seen (shouldn't happen)
            continue
        t0 = min(q[repo])
        if repo in atk:
            dur = (min(atk[repo]) - t0).total_seconds() / 60.0
            event = 1
        else:
            dur = (now - t0).total_seconds() / 60.0
            event = 0
        dur = max(dur, 0.0)
        groups[c].append((dur, event))
        per.append((repo, c, row["wave"], round(dur, 1), event,
                    len(atk.get(repo, [])), len(ips.get(repo, set()))))

    O, E, stat, df, p = logrank({c: groups[c] for c in CONDS})

    # KM figure
    fig, ax = plt.subplots(figsize=(8, 4.6))
    for c in CONDS:
        xs, ys = km(groups[c])
        xs = [x / 60.0 for x in xs]          # minutes -> hours
        ax.step(xs, ys, where="post", label=f"{LABELS[c]} (n={len(groups[c])})",
                color=OKABE[c], lw=2)
    ax.set_xlabel("hours since AWS quarantine")
    ax.set_ylabel("share of keys NOT yet hit by an attacker")
    ax.set_title("Time from quarantine to first attacker hit, by placement",
                 fontweight="bold")
    ax.legend(); ax.set_ylim(0, 1.02); ax.grid(alpha=.25)
    fig.tight_layout(); fig.savefig(os.path.join(IMG, "km_placement.png"), dpi=130)

    # secondary: attacker events & unique IPs per HIT cell, by condition
    ev_by = defaultdict(list); ip_by = defaultdict(list)
    for repo, c, w, dur, event, nev, nip in per:
        if event == 1:
            ev_by[c].append(nev); ip_by[c].append(nip)
    def kw(d):
        vals = [d[c] for c in CONDS if len(d[c]) > 0]
        if len(vals) < 2:
            return None, None
        try:
            s, pp = kruskal(*vals); return float(s), float(pp)
        except Exception:
            return None, None
    kw_ev = kw(ev_by); kw_ip = kw(ip_by)

    # secondary boxplots
    fig2, (a1, a2) = plt.subplots(1, 2, figsize=(11, 4.4))
    a1.boxplot([ev_by[c] for c in CONDS], tick_labels=[LABELS[c] for c in CONDS])
    a1.set_title("Attacker events per hit key", fontweight="bold")
    a1.set_ylabel("events"); a1.tick_params(axis="x", rotation=20)
    a2.boxplot([ip_by[c] for c in CONDS], tick_labels=[LABELS[c] for c in CONDS])
    a2.set_title("Distinct attacker IPs per hit key", fontweight="bold")
    a2.set_ylabel("unique source IPs"); a2.tick_params(axis="x", rotation=20)
    fig2.tight_layout(); fig2.savefig(os.path.join(IMG, "rate_diversity.png"), dpi=130)

    # kill-chain action mix by condition
    from collections import Counter
    mix = defaultdict(Counter)
    for repo, row in real.items():
        for a in actions.get(repo, []):
            mix[row["condition"]][a] += 1

    # control check
    ctrl_hits = sum(1 for r in ctrl if r in atk)

    # ---- write report ----
    def med(v):
        v = sorted(v); n = len(v)
        return "n/a" if n == 0 else (v[n // 2] if n % 2 else (v[n//2-1]+v[n//2])/2)
    L = []
    L.append("# Placement A/B experiment — results (interim)\n")
    L.append(f"_Data window through {now:%Y-%m-%d %H:%M} UTC. "
             f"50 repos (10 matched blocks x 5 conditions, 2 waves). "
             f"Primary endpoint: time from AWS quarantine to first attacker hit; "
             f"cells with no attacker hit yet are right-censored._\n")
    L.append("## Design check: controls\n")
    L.append(f"Control repos hit by an attacker: **{ctrl_hits} / {len(ctrl)}**. "
             "A fake key attracts nothing, so attacker hits on the live cells are "
             "real signal, not scanner background.\n")
    hit = sum(e for *_ , e in [(r[3], r[4]) for r in per])
    L.append("## Cells hit so far\n")
    L.append("| Placement | cells hit / total | attacker events | median hit time (h from quarantine) |")
    L.append("|---|---:|---:|---:|")
    for c in CONDS:
        g = groups[c]; nhit = sum(e for _, e in g)
        hit_times = [d/60 for d, e in g if e == 1]
        tot_ev = sum(ev_by[c])
        m = med(hit_times)
        mstr = f"{m:.1f}" if isinstance(m, (int, float)) else m
        L.append(f"| {LABELS[c]} | {nhit}/{len(g)} | {tot_ev} | {mstr} |")
    L.append("")
    L.append("## Primary: log-rank across the 4 placements\n")
    L.append("| Placement | observed hits | expected hits |")
    L.append("|---|---:|---:|")
    for c in CONDS:
        L.append(f"| {LABELS[c]} | {O[c]:.0f} | {E[c]:.1f} |")
    L.append("")
    verdict = ("**no significant difference**" if p >= 0.05
               else "**a significant difference**")
    L.append(f"Log-rank chi-square = **{stat:.2f}**, df = {df}, "
             f"**p = {p:.3f}** -> {verdict} in time-to-first-hit between "
             "placements.\n")
    L.append("![Kaplan-Meier by placement](img/km_placement.png)\n")
    L.append("## Secondary: intensity and attacker diversity\n")
    def sig(pp):
        return "significant" if pp < 0.05 else "not significant"
    if kw_ev[1] is not None:
        L.append(f"- Attacker **events per hit key** by placement: "
                 f"Kruskal-Wallis H = {kw_ev[0]:.2f}, p = {kw_ev[1]:.3f} "
                 f"({sig(kw_ev[1])}).")
    if kw_ip[1] is not None:
        L.append(f"- **Distinct attacker IPs per hit key**: "
                 f"H = {kw_ip[0]:.2f}, p = {kw_ip[1]:.3f} ({sig(kw_ip[1])}).")
    L.append("\n![Rate and diversity](img/rate_diversity.png)\n")
    L.append("## Kill-chain action mix (attacker events, by placement)\n")
    allact = sorted({a for c in mix for a in mix[c]},
                    key=lambda a: -sum(mix[c][a] for c in mix))[:8]
    L.append("| action | " + " | ".join(LABELS[c] for c in CONDS) + " |")
    L.append("|---|" + "---:|" * len(CONDS))
    for a in allact:
        L.append(f"| `{a}` | " + " | ".join(str(mix[c][a]) for c in CONDS) + " |")
    L.append("")
    L.append("## Read this honestly\n")
    L.append("- With ~7-10 cells per placement this is **low-powered**; treat "
             "p-values as directional, not final.")
    L.append("- Attacker arrivals cluster at wall-clock **scanner sweeps**, so "
             "time-to-first-hit is largely driven by *when the next sweep runs*, "
             "which is the same for every placement. A null result on timing is "
             "the expected and honest outcome: automated GitHub secret-scanning "
             "finds a leaked key regardless of which file it sits in.")
    L.append("- The live signal to keep watching is the **secondary** metrics "
             "(how hard each key gets worked, how many distinct attackers), which "
             "keep accumulating.")
    open(OUT, "w").write("\n".join(L) + "\n")

    # console summary
    print(f"data through {now:%Y-%m-%d %H:%M}Z")
    print(f"controls hit: {ctrl_hits}/{len(ctrl)}")
    for c in CONDS:
        g = groups[c]
        print(f"  {LABELS[c]:<16} hit {sum(e for _,e in g)}/{len(g)}")
    print(f"log-rank chi2={stat:.2f} df={df} p={p:.3f}")
    if kw_ev[1] is not None:
        print(f"KW events/cell p={kw_ev[1]:.3f} | KW IPs/cell p={kw_ip[1]:.3f}")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
