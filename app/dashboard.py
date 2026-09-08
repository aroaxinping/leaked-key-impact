"""Canary Token Analytics — Threat Intelligence Dashboard."""

from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import pycountry
import streamlit as st

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "processed"
MITRE_PATH = PROJECT_ROOT / "docs" / "mitre_attack.md"

PHASE_ORDER = [
    "validation",
    "reconnaissance",
    "abuse-prep",
    "resource-abuse",
    "persistence",
]

PHASE_COLORS = {
    "validation": "#7ba7cc",
    "reconnaissance": "#4a7fa5",
    "abuse-prep": "#2d5f8a",
    "resource-abuse": "#dc2626",
    "persistence": "#9b6fd4",
    "defense": "#3a5a3a",
}

DARK_BG = "#000000"
DARK_PAPER = "#060a10"
DARK_GRID = "#111820"
DARK_TEXT = "#8899aa"
ACCENT = "#5b8fb9"
DANGER = "#dc2626"

PLOTLY_LAYOUT = dict(
    paper_bgcolor=DARK_PAPER,
    plot_bgcolor=DARK_BG,
    font=dict(color=DARK_TEXT, size=12),
    margin=dict(l=40, r=20, t=40, b=40),
    xaxis=dict(gridcolor=DARK_GRID, zerolinecolor=DARK_GRID),
    yaxis=dict(gridcolor=DARK_GRID, zerolinecolor=DARK_GRID),
)

_ALPHA2_TO_ALPHA3 = {c.alpha_2: c.alpha_3 for c in pycountry.countries}

# ---------------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Leaked Key Impact",
    page_icon="🍯",
    layout="wide",
)

st.markdown(
    """
    <style>
    .stApp { background-color: #000000; }
    .block-container { padding-top: 1.5rem; }
    .metric-card {
        background: #060a10;
        border: 1px solid #111820;
        border-radius: 4px;
        padding: 1.4rem 1rem;
        text-align: center;
    }
    .metric-card .value {
        font-size: 2rem;
        font-weight: 700;
        color: #5b8fb9;
    }
    .metric-card .label {
        font-size: 0.75rem;
        color: #4a5568;
        margin-top: 0.3rem;
        text-transform: uppercase;
        letter-spacing: 0.1em;
    }
    h2, h3 { color: #8899aa !important; font-weight: 400 !important; }
    .stCaption { color: #3a4555 !important; }
    .story-block {
        color: #5a6a7a;
        font-size: 0.85rem;
        line-height: 1.6;
        max-width: 800px;
        margin-bottom: 1rem;
    }
    .story-block strong { color: #8899aa; }
    hr { border-color: #111820 !important; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------


@st.cache_data
def load_data() -> pd.DataFrame:
    df = pd.read_csv(DATA_DIR / "alerts_enriched.csv", parse_dates=["datetime_utc"])
    df["date"] = pd.to_datetime(df["date_utc"])
    return df


@st.cache_data
def load_mitre() -> list[dict]:
    rows = []
    text = MITRE_PATH.read_text()
    in_table = False
    for line in text.splitlines():
        if line.startswith("| Tactic") and "Technique" in line:
            in_table = True
            continue
        if in_table and line.startswith("|---"):
            continue
        if in_table and line.startswith("|"):
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 4:
                rows.append(
                    {
                        "tactic": parts[0],
                        "technique": parts[1],
                        "technique_id": parts[2].strip("`"),
                        "events": int(parts[3]),
                    }
                )
        elif in_table and not line.startswith("|"):
            break
    return rows


df = load_data()
mitre_rows = load_mitre()
attacker_df = df[~df["intent_phase"].isin(["defense"])].copy()

n_events = len(df)
n_ips = df["source_ip"].nunique()
n_countries = df["country"].dropna().nunique()
n_tokens = df["token_id"].nunique()
date_min = df["date_utc"].min()
date_max = df["date_utc"].max()

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown("### leaked-key-impact")

st.markdown(
    '<div class="story-block">'
    "Five fake AWS credentials were deliberately planted across public GitHub repositories. "
    "They grant <strong>zero access</strong> — their only purpose is to fire an alert the moment "
    "someone tries to use them. Every row in this dashboard is a <strong>real intrusion attempt</strong> "
    "by an automated bot or a hands-on operator, captured in the wild."
    "<br><br>"
    f"Over <strong>{(pd.to_datetime(date_max) - pd.to_datetime(date_min)).days} days</strong>, "
    f"the fleet recorded <strong>{n_events:,} events</strong> from "
    f"<strong>{n_ips} unique IPs</strong> across <strong>{n_countries} countries</strong>. "
    "AWS quarantined each key within minutes — every subsequent attempt hit a credential "
    "that was already dead."
    "</div>",
    unsafe_allow_html=True,
)

cols = st.columns(4)

metrics = [
    ("events", f"{n_events:,}"),
    ("unique ips", f"{n_ips:,}"),
    ("countries", f"{n_countries:,}"),
    ("active tokens", f"{n_tokens:,}"),
]

for col, (label, value) in zip(cols, metrics):
    col.markdown(
        f'<div class="metric-card">'
        f'<div class="value">{value}</div>'
        f'<div class="label">{label}</div>'
        f"</div>",
        unsafe_allow_html=True,
    )

st.divider()

# ---------------------------------------------------------------------------
# 1. Timeline
# ---------------------------------------------------------------------------

st.markdown("### timeline")
st.markdown(
    '<div class="story-block">'
    "Each bar is one day. The color shows <strong>what stage of the kill chain</strong> "
    "the attackers reached — from initial validation (is this key alive?) through "
    "reconnaissance (what can it access?) to resource abuse (LLMjacking on Bedrock)."
    "</div>",
    unsafe_allow_html=True,
)

timeline = (
    attacker_df.groupby([attacker_df["date"].dt.date, "intent_phase"])
    .size()
    .reset_index(name="events")
)
timeline.rename(columns={timeline.columns[0]: "date"}, inplace=True)
timeline["intent_phase"] = pd.Categorical(
    timeline["intent_phase"], categories=PHASE_ORDER, ordered=True
)
timeline = timeline.sort_values(["date", "intent_phase"])

fig_timeline = px.bar(
    timeline,
    x="date",
    y="events",
    color="intent_phase",
    color_discrete_map=PHASE_COLORS,
    category_orders={"intent_phase": PHASE_ORDER},
    labels={"date": "", "events": "Events", "intent_phase": "Phase"},
)
fig_timeline.update_layout(**PLOTLY_LAYOUT, barmode="stack", legend_title_text="Phase")
st.plotly_chart(fig_timeline, use_container_width=True)

# ---------------------------------------------------------------------------
# 2. Kill chain + Placement
# ---------------------------------------------------------------------------

col_left, col_right = st.columns(2)

with col_left:
    st.markdown("### kill chain")
    st.markdown(
        '<div class="story-block">'
        "The attacker lifecycle mapped from this data. "
        "<strong>Abuse-prep dominates</strong> — most bots check SES email quotas "
        "and Bedrock model access before attempting the money move."
        "</div>",
        unsafe_allow_html=True,
    )
    phase_counts = (
        attacker_df["intent_phase"]
        .value_counts()
        .reindex(PHASE_ORDER)
        .reset_index()
    )
    phase_counts.columns = ["phase", "events"]

    fig_phases = px.bar(
        phase_counts,
        x="events",
        y="phase",
        orientation="h",
        color="phase",
        color_discrete_map=PHASE_COLORS,
        text="events",
    )
    fig_phases.update_layout(**PLOTLY_LAYOUT, showlegend=False)
    fig_phases.update_traces(textposition="outside")
    st.plotly_chart(fig_phases, use_container_width=True)

with col_right:
    st.markdown("### placement")
    st.markdown(
        '<div class="story-block">'
        "Where the fake key was planted matters. <strong>.env draws volume</strong>, "
        "but <strong>terraform.tfvars draws depth</strong> — deeper kill-chain "
        "penetration from infrastructure-aware scanners."
        "</div>",
        unsafe_allow_html=True,
    )
    placement_counts = df["placement"].value_counts().reset_index()
    placement_counts.columns = ["placement", "events"]

    fig_placement = px.bar(
        placement_counts,
        x="events",
        y="placement",
        orientation="h",
        color="placement",
        color_discrete_sequence=["#5b8fb9", "#4a7fa5", "#2d5f8a", "#1e3a5f"],
        text="events",
    )
    fig_placement.update_layout(**PLOTLY_LAYOUT, showlegend=False)
    fig_placement.update_traces(textposition="outside")
    st.plotly_chart(fig_placement, use_container_width=True)

# ---------------------------------------------------------------------------
# 3. World map
# ---------------------------------------------------------------------------

st.markdown("### attack origins")
st.markdown(
    '<div class="story-block">'
    f"Traffic from <strong>{n_countries} countries</strong>. Most IPs resolve to "
    "datacenter and hosting providers — not end users. The geographic spread reflects "
    "where proxy infrastructure is rented, not where operators sit."
    "</div>",
    unsafe_allow_html=True,
)

map_data = (
    attacker_df.dropna(subset=["country"])
    .groupby("country")
    .agg(events=("country", "size"), ips=("source_ip", "nunique"))
    .reset_index()
)
map_data["iso3"] = map_data["country"].map(_ALPHA2_TO_ALPHA3)
map_data = map_data.dropna(subset=["iso3"])

fig_map = px.choropleth(
    map_data,
    locations="iso3",
    locationmode="ISO-3",
    color="events",
    hover_name="country",
    hover_data={"ips": True, "events": True, "country": False, "iso3": False},
    color_continuous_scale=["#000000", "#0a1a2a", "#1e3a5f", "#4a7fa5", "#dc2626"],
)
fig_map.update_layout(
    paper_bgcolor=DARK_PAPER,
    plot_bgcolor=DARK_BG,
    font=dict(color=DARK_TEXT, size=12),
    margin=dict(l=0, r=0, t=10, b=0),
    geo=dict(
        bgcolor=DARK_BG,
        lakecolor=DARK_BG,
        landcolor="#0a0a0a",
        showframe=False,
        showcoastlines=True,
        coastlinecolor="#1a1a1a",
        countrycolor="#1a1a1a",
        projection_type="natural earth",
    ),
    coloraxis_colorbar=dict(title="Events"),
    height=400,
)
st.plotly_chart(fig_map, use_container_width=True)

# ---------------------------------------------------------------------------
# 4. Countries + Infrastructure
# ---------------------------------------------------------------------------

col_left2, col_right2 = st.columns(2)

with col_left2:
    st.markdown("### top countries")
    country_counts = (
        df["country"]
        .dropna()
        .value_counts()
        .head(15)
        .reset_index()
    )
    country_counts.columns = ["country", "events"]

    fig_geo = px.bar(
        country_counts,
        x="events",
        y="country",
        orientation="h",
        color_discrete_sequence=["#4a7fa5"],
        text="events",
    )
    layout_geo = {k: v for k, v in PLOTLY_LAYOUT.items() if k != "yaxis"}
    fig_geo.update_layout(**layout_geo, yaxis=dict(autorange="reversed", gridcolor=DARK_GRID))
    fig_geo.update_traces(textposition="outside")
    st.plotly_chart(fig_geo, use_container_width=True)

with col_right2:
    st.markdown("### infrastructure type")
    st.markdown(
        '<div class="story-block">'
        "Where the traffic comes from. <strong>86% is datacenter/hosting</strong> — "
        "rented servers running automated tools. The residential slice is mostly "
        "mobile proxies rotating through carrier NAT."
        "</div>",
        unsafe_allow_html=True,
    )
    infra_counts = df["infra_type"].dropna().value_counts().reset_index()
    infra_counts.columns = ["type", "events"]

    fig_infra = px.pie(
        infra_counts,
        values="events",
        names="type",
        color_discrete_sequence=["#5b8fb9", "#4a7fa5", "#2d5f8a", "#1e3a5f", "#111820"],
        hole=0.45,
    )
    fig_infra.update_layout(
        paper_bgcolor=DARK_PAPER,
        plot_bgcolor=DARK_BG,
        font=dict(color=DARK_TEXT, size=12),
        margin=dict(l=20, r=20, t=40, b=20),
        legend=dict(orientation="h", y=-0.15),
    )
    st.plotly_chart(fig_infra, use_container_width=True)

# ---------------------------------------------------------------------------
# 5. MITRE ATT&CK
# ---------------------------------------------------------------------------

st.markdown("### MITRE ATT&CK")
st.markdown(
    '<div class="story-block">'
    "Every observed AWS API action mapped to the "
    "<strong>MITRE ATT&CK for Cloud</strong> framework — the industry standard "
    "vocabulary for attacker behavior. <strong>T1496 Resource Hijacking</strong> "
    "(LLMjacking on Bedrock) is the money move."
    "</div>",
    unsafe_allow_html=True,
)

if mitre_rows:
    mitre_df = pd.DataFrame(mitre_rows)
    mitre_df = mitre_df.sort_values("events", ascending=True)

    TACTIC_COLORS = {
        "Discovery": "#4a7fa5",
        "Impact": "#dc2626",
        "Credential Access": "#5b8fb9",
        "Persistence": "#9b6fd4",
        "Privilege Escalation": "#7ba7cc",
    }

    fig_mitre = px.bar(
        mitre_df,
        x="events",
        y="technique",
        orientation="h",
        color="tactic",
        color_discrete_map=TACTIC_COLORS,
        text="events",
        hover_data=["technique_id"],
    )
    fig_mitre.update_layout(
        **PLOTLY_LAYOUT,
        legend_title_text="Tactic",
        height=420,
    )
    fig_mitre.update_traces(textposition="outside")
    st.plotly_chart(fig_mitre, use_container_width=True)
else:
    st.info("MITRE ATT&CK data not found.")

# ---------------------------------------------------------------------------
# 6. Top API calls
# ---------------------------------------------------------------------------

st.markdown("### top API calls")
st.markdown(
    '<div class="story-block">'
    "The raw actions bots attempt. <strong>GetSendQuota</strong> (can I spam from this account?) "
    "leads by a wide margin. <strong>Converse / InvokeModel</strong> are Bedrock LLMjacking — "
    "running AI at the victim's expense."
    "</div>",
    unsafe_allow_html=True,
)

top_events = df["event_name"].value_counts().head(15).reset_index()
top_events.columns = ["event", "count"]
top_events = top_events.sort_values("count", ascending=True)

fig_events = px.bar(
    top_events,
    x="count",
    y="event",
    orientation="h",
    color_discrete_sequence=["#5b8fb9"],
    text="count",
)
fig_events.update_layout(**PLOTLY_LAYOUT, height=480)
fig_events.update_traces(textposition="outside")
st.plotly_chart(fig_events, use_container_width=True)

# ---------------------------------------------------------------------------
# 7. Cost Impact — what this would cost if the keys were real
# ---------------------------------------------------------------------------

st.divider()
st.markdown("### cost impact")
st.markdown(
    '<div class="story-block">'
    "If these keys had been real, what would the damage look like? "
    "These estimates use <strong>public AWS pricing</strong> and conservative assumptions "
    "about what each observed action would have consumed. "
    "The numbers below are <strong>per-incident minimums</strong> — a real compromise "
    "runs continuously until detected, multiplying the cost by hours or days."
    "</div>",
    unsafe_allow_html=True,
)

COST_MODEL = {
    "bedrock_llmjacking": {
        "label": "Bedrock LLMjacking",
        "events": ["InvokeModel", "InvokeModelWithResponseStream", "Converse", "ConverseStream"],
        "desc": "Each call runs an AI model at victim's expense",
        "unit_cost": 0.016,
        "unit_label": "per call (Claude Haiku, ~1K tokens)",
        "burst_per_hour": 500,
        "burst_label": "calls/hour (automated)",
        "daily_cost": 192.0,
    },
    "ec2_cryptomining": {
        "label": "EC2 cryptomining",
        "events": ["RunInstances"],
        "desc": "Launch GPU instances for mining",
        "unit_cost": 24.48,
        "unit_label": "per hour (p3.16xlarge)",
        "burst_per_hour": 10,
        "burst_label": "instances",
        "daily_cost": 5_875.0,
    },
    "ses_phishing": {
        "label": "SES email phishing",
        "events": ["GetSendQuota", "ListEmailIdentities"],
        "desc": "Send phishing using Amazon's email reputation",
        "unit_cost": 0.10,
        "unit_label": "per 1,000 emails",
        "burst_per_hour": 50_000,
        "burst_label": "emails/hour (SES default)",
        "daily_cost": 120.0,
    },
    "iam_backdoor": {
        "label": "IAM persistence",
        "events": ["CreateUser", "PutUserPolicy", "AddUserToGroup"],
        "desc": "Create backdoor user that survives key revocation",
        "unit_cost": None,
        "unit_label": "no direct cost",
        "burst_per_hour": None,
        "burst_label": "",
        "daily_cost": None,
    },
}

cost_rows = []
total_daily = 0.0

for key, model in COST_MODEL.items():
    n = attacker_df[attacker_df["event_name"].isin(model["events"])].shape[0]
    if n == 0:
        continue
    cost_rows.append({
        "Attack vector": model["label"],
        "Events observed": n,
        "Unit cost": model["unit_label"],
        "Sustained daily cost": f"${model['daily_cost']:,.0f}" if model["daily_cost"] else "full account takeover",
    })
    if model["daily_cost"]:
        total_daily += model["daily_cost"]

cost_df = pd.DataFrame(cost_rows)

col_table, col_total = st.columns([3, 1])

with col_table:
    st.dataframe(
        cost_df,
        use_container_width=True,
        hide_index=True,
    )

with col_total:
    st.markdown(
        '<div class="metric-card" style="margin-top: 0.5rem;">'
        f'<div class="value" style="color: #dc2626;">${total_daily:,.0f}</div>'
        '<div class="label">potential daily burn</div>'
        "</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="metric-card" style="margin-top: 0.8rem;">'
        f'<div class="value" style="color: #dc2626; font-size: 1.5rem;">${total_daily * 30:,.0f}</div>'
        '<div class="label">monthly if undetected</div>'
        "</div>",
        unsafe_allow_html=True,
    )

st.markdown(
    '<div class="story-block">'
    "<strong>The real cost of a leaked key isn't the API call — it's the time to detection.</strong> "
    "AWS quarantined these keys in ~17 minutes. Without that safety net, "
    f"a single compromised key burns <strong>${total_daily:,.0f}/day</strong> in compute alone. "
    "A company that takes 24 hours to notice loses "
    f"<strong>${total_daily:,.0f}</strong>. A company that takes a week loses "
    f"<strong>${total_daily * 7:,.0f}</strong>. "
    "IAM persistence (<code>CreateUser</code>) is not priced because the cost is "
    "<strong>total account takeover</strong> — the attacker survives key rotation "
    "and the bill becomes unlimited."
    "</div>",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

st.divider()
st.markdown(
    '<div class="story-block" style="text-align: center; margin-top: 0.5rem;">'
    f"<strong>{n_events:,}</strong> events · <strong>{n_ips}</strong> IPs · "
    f"<strong>{n_countries}</strong> countries · {date_min} — {date_max}"
    "<br><br>"
    'Canary tokens generated with <a href="https://canarytokens.org" '
    'style="color: #5b8fb9;" target="_blank">canarytokens.org</a> by '
    '<a href="https://thinkst.com" style="color: #5b8fb9;" target="_blank">Thinkst</a> · '
    'Attacker behavior mapped to <a href="https://attack.mitre.org/matrices/enterprise/cloud/" '
    'style="color: #5b8fb9;" target="_blank">MITRE ATT&CK for Cloud</a>'
    "</div>",
    unsafe_allow_html=True,
)
