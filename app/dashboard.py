"""Canary Token Analytics — Threat Intelligence Dashboard."""

from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
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
    "validation": "#6366f1",
    "reconnaissance": "#06b6d4",
    "abuse-prep": "#f59e0b",
    "resource-abuse": "#ef4444",
    "persistence": "#a855f7",
    "defense": "#22c55e",
}

DARK_BG = "#0e1117"
DARK_PAPER = "#161b22"
DARK_GRID = "#21262d"
DARK_TEXT = "#c9d1d9"

PLOTLY_LAYOUT = dict(
    paper_bgcolor=DARK_PAPER,
    plot_bgcolor=DARK_BG,
    font=dict(color=DARK_TEXT, family="Inter, sans-serif"),
    margin=dict(l=40, r=20, t=40, b=40),
    xaxis=dict(gridcolor=DARK_GRID, zerolinecolor=DARK_GRID),
    yaxis=dict(gridcolor=DARK_GRID, zerolinecolor=DARK_GRID),
)

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
    .block-container { padding-top: 1.5rem; }
    .metric-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 1.2rem 1rem;
        text-align: center;
    }
    .metric-card .value {
        font-size: 2rem;
        font-weight: 700;
        color: #58a6ff;
    }
    .metric-card .label {
        font-size: 0.85rem;
        color: #8b949e;
        margin-top: 0.25rem;
    }
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
    """Parse the MITRE ATT&CK markdown table into a list of dicts."""
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

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown("## 🍯 Canary Token Analytics")
st.caption("Threat intelligence from deliberately leaked AWS credentials")

cols = st.columns(4)

metrics = [
    ("Events", f"{len(df):,}"),
    ("Unique IPs", f"{df['source_ip'].nunique():,}"),
    ("Countries", f"{df['country'].dropna().nunique():,}"),
    ("Active Tokens", f"{df['token_id'].nunique():,}"),
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
# 1. Timeline — events per day, colored by intent phase
# ---------------------------------------------------------------------------

st.markdown("### Timeline")

attacker_df = df[~df["intent_phase"].isin(["defense"])].copy()

timeline = (
    attacker_df.groupby([attacker_df["date"].dt.date, "intent_phase"])
    .size()
    .reset_index(name="events")
)
timeline.rename(columns={timeline.columns[0]: "date"}, inplace=True)

# Ensure consistent ordering
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
# 2. Kill chain + Placement (side by side)
# ---------------------------------------------------------------------------

col_left, col_right = st.columns(2)

with col_left:
    st.markdown("### Kill Chain Phases")
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
    st.markdown("### Events by Placement")
    placement_counts = df["placement"].value_counts().reset_index()
    placement_counts.columns = ["placement", "events"]

    fig_placement = px.bar(
        placement_counts,
        x="events",
        y="placement",
        orientation="h",
        color="placement",
        color_discrete_sequence=["#58a6ff", "#3fb950", "#d29922", "#8b949e"],
        text="events",
    )
    fig_placement.update_layout(**PLOTLY_LAYOUT, showlegend=False)
    fig_placement.update_traces(textposition="outside")
    st.plotly_chart(fig_placement, use_container_width=True)

# ---------------------------------------------------------------------------
# 3. World map
# ---------------------------------------------------------------------------

st.markdown("### Attack Origins")

import pycountry

map_data = (
    attacker_df.dropna(subset=["country"])
    .groupby("country")
    .agg(events=("country", "size"), ips=("source_ip", "nunique"))
    .reset_index()
)

_alpha2_to_alpha3 = {}
for c in pycountry.countries:
    _alpha2_to_alpha3[c.alpha_2] = c.alpha_3
map_data["iso3"] = map_data["country"].map(_alpha2_to_alpha3)
map_data = map_data.dropna(subset=["iso3"])

fig_map = px.choropleth(
    map_data,
    locations="iso3",
    locationmode="ISO-3",
    color="events",
    hover_name="country",
    hover_data={"ips": True, "events": True, "country": False, "iso3": False},
    color_continuous_scale=["#0d1117", "#1f3a5f", "#58a6ff", "#f59e0b", "#ef4444"],
)
fig_map.update_layout(
    paper_bgcolor=DARK_PAPER,
    plot_bgcolor=DARK_BG,
    font=dict(color=DARK_TEXT, family="Inter, sans-serif"),
    margin=dict(l=0, r=0, t=10, b=0),
    geo=dict(
        bgcolor=DARK_BG,
        lakecolor=DARK_BG,
        landcolor="#161b22",
        showframe=False,
        showcoastlines=True,
        coastlinecolor="#30363d",
        countrycolor="#30363d",
        projection_type="natural earth",
    ),
    coloraxis_colorbar=dict(title="Events"),
    height=400,
)
st.plotly_chart(fig_map, use_container_width=True)

# ---------------------------------------------------------------------------
# 4. Geography + Infrastructure (side by side)
# ---------------------------------------------------------------------------

col_left2, col_right2 = st.columns(2)

with col_left2:
    st.markdown("### Top Countries")
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
        color_discrete_sequence=["#58a6ff"],
        text="events",
    )
    layout_geo = {k: v for k, v in PLOTLY_LAYOUT.items() if k != "yaxis"}
    fig_geo.update_layout(**layout_geo, yaxis=dict(autorange="reversed", gridcolor=DARK_GRID))
    fig_geo.update_traces(textposition="outside")
    st.plotly_chart(fig_geo, use_container_width=True)

with col_right2:
    st.markdown("### Infrastructure Type")
    infra_counts = df["infra_type"].dropna().value_counts().reset_index()
    infra_counts.columns = ["type", "events"]

    fig_infra = px.pie(
        infra_counts,
        values="events",
        names="type",
        color_discrete_sequence=["#6366f1", "#06b6d4", "#f59e0b", "#ef4444", "#a855f7"],
        hole=0.45,
    )
    fig_infra.update_layout(
        paper_bgcolor=DARK_PAPER,
        plot_bgcolor=DARK_BG,
        font=dict(color=DARK_TEXT, family="Inter, sans-serif"),
        margin=dict(l=20, r=20, t=40, b=20),
        legend=dict(orientation="h", y=-0.15),
    )
    st.plotly_chart(fig_infra, use_container_width=True)

# ---------------------------------------------------------------------------
# 4. MITRE ATT&CK techniques
# ---------------------------------------------------------------------------

st.markdown("### MITRE ATT&CK Techniques")

if mitre_rows:
    mitre_df = pd.DataFrame(mitre_rows)
    mitre_df = mitre_df.sort_values("events", ascending=True)

    fig_mitre = px.bar(
        mitre_df,
        x="events",
        y="technique",
        orientation="h",
        color="tactic",
        color_discrete_sequence=["#06b6d4", "#ef4444", "#f59e0b", "#a855f7", "#22c55e"],
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
# 5. Top event names (what attackers actually try to do)
# ---------------------------------------------------------------------------

st.markdown("### Top API Calls")

top_events = df["event_name"].value_counts().head(15).reset_index()
top_events.columns = ["event", "count"]
top_events = top_events.sort_values("count", ascending=True)

fig_events = px.bar(
    top_events,
    x="count",
    y="event",
    orientation="h",
    color_discrete_sequence=["#d29922"],
    text="count",
)
fig_events.update_layout(**PLOTLY_LAYOUT, height=480)
fig_events.update_traces(textposition="outside")
st.plotly_chart(fig_events, use_container_width=True)

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

st.divider()
st.caption(
    f"Data: {len(df):,} events · {df['source_ip'].nunique():,} IPs · "
    f"{df['date_utc'].min()} — {df['date_utc'].max()}"
)
