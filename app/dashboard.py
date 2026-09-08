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
    "validation": "#4a9eff",
    "reconnaissance": "#36b5a0",
    "abuse-prep": "#e0a458",
    "resource-abuse": "#d94f4f",
    "persistence": "#9b6fd4",
    "defense": "#5a7a5a",
}

DARK_BG = "#000000"
DARK_PAPER = "#0a0a0a"
DARK_GRID = "#1a1a1a"
DARK_TEXT = "#a0a0a0"
ACCENT = "#4a9eff"

PLOTLY_LAYOUT = dict(
    paper_bgcolor=DARK_PAPER,
    plot_bgcolor=DARK_BG,
    font=dict(color=DARK_TEXT, family="JetBrains Mono, SF Mono, Menlo, monospace", size=11),
    margin=dict(l=40, r=20, t=40, b=40),
    xaxis=dict(gridcolor=DARK_GRID, zerolinecolor=DARK_GRID),
    yaxis=dict(gridcolor=DARK_GRID, zerolinecolor=DARK_GRID),
)

_ALPHA2_TO_ALPHA3 = {c.alpha_2: c.alpha_3 for c in pycountry.countries}

# ---------------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Canary Token Analytics",
    page_icon="🍯",
    layout="wide",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
    .stApp { background-color: #000000; }
    .block-container { padding-top: 1.5rem; }
    .metric-card {
        background: #0a0a0a;
        border: 1px solid #1a1a1a;
        border-radius: 4px;
        padding: 1.4rem 1rem;
        text-align: center;
    }
    .metric-card .value {
        font-size: 2rem;
        font-weight: 700;
        color: #4a9eff;
        font-family: 'JetBrains Mono', monospace;
    }
    .metric-card .label {
        font-size: 0.75rem;
        color: #555555;
        margin-top: 0.3rem;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        font-family: 'JetBrains Mono', monospace;
    }
    h2, h3 { color: #a0a0a0 !important; font-family: 'JetBrains Mono', monospace !important; font-weight: 400 !important; }
    .stCaption { color: #444444 !important; }
    .story-block {
        color: #666666;
        font-size: 0.85rem;
        line-height: 1.6;
        max-width: 800px;
        font-family: 'JetBrains Mono', monospace;
        margin-bottom: 1rem;
    }
    .story-block strong { color: #a0a0a0; }
    hr { border-color: #1a1a1a !important; }
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

st.markdown("### canary-token-analytics")

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
        color_discrete_sequence=["#4a9eff", "#36b5a0", "#e0a458", "#555555"],
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
    color_continuous_scale=["#000000", "#0a2a4a", "#4a9eff", "#e0a458", "#d94f4f"],
)
fig_map.update_layout(
    paper_bgcolor=DARK_PAPER,
    plot_bgcolor=DARK_BG,
    font=dict(color=DARK_TEXT, family="JetBrains Mono, monospace", size=11),
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
        color_discrete_sequence=["#4a9eff"],
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
        color_discrete_sequence=["#4a9eff", "#36b5a0", "#e0a458", "#d94f4f", "#555555"],
        hole=0.45,
    )
    fig_infra.update_layout(
        paper_bgcolor=DARK_PAPER,
        plot_bgcolor=DARK_BG,
        font=dict(color=DARK_TEXT, family="JetBrains Mono, monospace", size=11),
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
        "Discovery": "#36b5a0",
        "Impact": "#d94f4f",
        "Credential Access": "#e0a458",
        "Persistence": "#9b6fd4",
        "Privilege Escalation": "#4a9eff",
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
    color_discrete_sequence=["#e0a458"],
    text="count",
)
fig_events.update_layout(**PLOTLY_LAYOUT, height=480)
fig_events.update_traces(textposition="outside")
st.plotly_chart(fig_events, use_container_width=True)

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
    'style="color: #4a9eff;" target="_blank">canarytokens.org</a> by '
    '<a href="https://thinkst.com" style="color: #4a9eff;" target="_blank">Thinkst</a> · '
    'Attacker behavior mapped to <a href="https://attack.mitre.org/matrices/enterprise/cloud/" '
    'style="color: #4a9eff;" target="_blank">MITRE ATT&CK for Cloud</a>'
    "</div>",
    unsafe_allow_html=True,
)
