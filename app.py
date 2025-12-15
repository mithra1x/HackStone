from datetime import datetime, timedelta
from typing import Dict

import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh
import requests

API_URL = "http://127.0.0.1:8000/events?limit=100"

# =============================================================
# Page config
# =============================================================
st.set_page_config(
    page_title="FIM Command Center",
    layout="wide",
    page_icon="🔐",
)

st.title("🔐 File Integrity Monitoring Command Center")


# =============================================================
# Auto-refresh (every 3 seconds)
# =============================================================
st_autorefresh(interval=3000, key="fim_refresh")


def load_events_from_api() -> pd.DataFrame:
    try:
        resp = requests.get(API_URL, timeout=2)
        resp.raise_for_status()
        data = resp.json()
        events = data.get("events", [])

        if not events:
            return pd.DataFrame()

        df = pd.DataFrame(events)

        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
        if "process_name" in df.columns:
            df = df.rename(columns={"process_name": "process"})
        if "hash_before" in df.columns:
            df = df.rename(columns={"hash_before": "old_hash"})
        if "hash_after" in df.columns:
            df = df.rename(columns={"hash_after": "new_hash"})

        return df
    except Exception as e:  # noqa: BLE001
        st.error(f"API error: {e}")
        return pd.DataFrame()


df = load_events_from_api()

if df.empty:
    st.info("Hələ API-dən event gəlmir.")
    st.stop()

df = df.sort_values("timestamp", ascending=False).reset_index(drop=True)

# Normalize expected columns and fallbacks
defaults: Dict[str, str | int] = {
    "event_type": "unknown",
    "file_path": "(unknown)",
    "mitre_technique": "unknown",
    "user": "unknown",
    "process": "unknown",
    "host": "unknown",
    "site": "unknown",
    "reason": "No description provided.",
    "old_hash": "-",
    "new_hash": "-",
}

for col, default in defaults.items():
    if col not in df.columns:
        df[col] = default
    else:
        df[col] = df[col].fillna(default)

df["ai_risk_score"] = pd.to_numeric(df.get("ai_risk_score", 0), errors="coerce").fillna(0).astype(int)

if "event_id" not in df.columns:
    df["event_id"] = [f"evt-{i:05d}" for i in range(len(df))]

# =============================================================
# Sidebar filters
# =============================================================
st.sidebar.header("Filters")

min_ts = df["timestamp"].min()
max_ts = df["timestamp"].max()
default_start = max(min_ts, max_ts - timedelta(hours=2))

if min_ts == max_ts:
    time_range = (min_ts.to_pydatetime(), max_ts.to_pydatetime())
else:
    time_range = st.sidebar.slider(
        "Time window",
        min_value=min_ts.to_pydatetime(),
        max_value=max_ts.to_pydatetime(),
        value=(default_start.to_pydatetime(), max_ts.to_pydatetime()),
        step=timedelta(minutes=5),
    )

event_types = sorted(df["event_type"].dropna().unique().tolist())
mitre_options = sorted(df["mitre_technique"].dropna().unique().tolist())
users = sorted(df["user"].dropna().unique().tolist())
processes = sorted(df["process"].dropna().unique().tolist())
hosts = sorted(df["host"].dropna().unique().tolist())

mitre_filter = st.sidebar.multiselect(
    "MITRE techniques",
    options=mitre_options,
    default=mitre_options,
)

event_type_filter = st.sidebar.multiselect(
    "Event type",
    options=event_types,
    default=event_types,
)

user_filter = st.sidebar.multiselect("User", options=users, default=users)
process_filter = st.sidebar.multiselect(
    "Process",
    options=processes,
    default=processes,
)

host_filter = st.sidebar.multiselect("Host", options=hosts, default=hosts)

min_risk = st.sidebar.slider(
    "Minimum AI risk score",
    min_value=0,
    max_value=100,
    value=40,
    step=5,
)

# Apply time window
start_ts, end_ts = time_range
df = df[(df["timestamp"] >= start_ts) & (df["timestamp"] <= end_ts)]

# Apply filters
df = df[
    (df["event_type"].isin(event_type_filter))
    & (df["ai_risk_score"] >= min_risk)
    & (df["mitre_technique"].isin(mitre_filter))
    & (df["user"].isin(user_filter))
    & (df["process"].isin(process_filter))
    & (df["host"].isin(host_filter))
]

if df.empty:
    st.info("No events match the current filters.")
    st.stop()

# =============================================================
# Helper utilities
# =============================================================
SEVERITY_COLORS = {
    "high": "#f77f00",
    "medium": "#ffd166",
    "low": "#4cc9f0",
}


def classify_risk(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def severity_badge(score: int) -> str:
    level = classify_risk(score)
    color = SEVERITY_COLORS[level]
    return f"<span style='color:{color}; font-weight:600;'>{level.upper()}</span>"


def mitre_badge(technique: str) -> str:
    return f"<span style='background:#111827;color:white;padding:2px 6px;border-radius:6px;font-size:12px;'>MITRE {technique}</span>"


def format_timestamp(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


# =============================================================
# KPI metrics
# =============================================================
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("Total events (filtered)", len(df))

with col2:
    high_risk_count = (df["ai_risk_score"] >= 80).sum()
    st.metric("High-risk (≥80)", int(high_risk_count))

with col3:
    st.metric("Unique files touched", df["file_path"].nunique())

with col4:
    st.metric("Hosts involved", df["host"].nunique())

with col5:
    last_event_time = df["timestamp"].max().strftime("%H:%M:%S")
    st.metric("Last event time", last_event_time)

# =============================================================
# Charts
# =============================================================
chart_col1, chart_col2, chart_col3 = st.columns(3)

with chart_col1:
    st.subheader("Event volume by type")
    by_type = df.groupby("event_type").size().reset_index(name="count")
    fig_type = px.bar(by_type, x="event_type", y="count", color="event_type", height=300)
    st.plotly_chart(fig_type, use_container_width=True)

with chart_col2:
    st.subheader("Risk score distribution")
    fig_risk = px.histogram(
        df,
        x="ai_risk_score",
        nbins=15,
        color=df["ai_risk_score"].apply(classify_risk),
        height=300,
        labels={"color": "severity"},
    )
    st.plotly_chart(fig_risk, use_container_width=True)

with chart_col3:
    st.subheader("Events over time (minute)")
    timeline = (
        df.copy()
        .assign(minute=df["timestamp"].dt.floor("T"))
        .groupby("minute")
        .size()
        .reset_index(name="count")
    )
    fig_time = px.line(timeline, x="minute", y="count", markers=True, height=300)
    st.plotly_chart(fig_time, use_container_width=True)

# =============================================================
# Hash change analytics
# =============================================================
hash_section = st.container()

with hash_section:
    st.subheader("🔁 File hash transitions")

    hash_df = df[(df["old_hash"] != "-") | (df["new_hash"] != "-")].copy()

    if hash_df.empty:
        st.info("No hash data available for the current filters.")
    else:
        chart_col_a, chart_col_b = st.columns([1.1, 1.9])

        with chart_col_a:
            transition_counts = (
                hash_df.groupby(["old_hash", "new_hash"]).size().reset_index(name="count")
            )

            fig_hash = px.density_heatmap(
                transition_counts,
                x="old_hash",
                y="new_hash",
                z="count",
                color_continuous_scale="Blues",
                height=380,
                text_auto=True,
            )
            fig_hash.update_layout(xaxis_title="Before hash", yaxis_title="After hash")
            st.plotly_chart(fig_hash, use_container_width=True)

        with chart_col_b:
            st.markdown("**Hash change table**")
            hash_table = (
                hash_df[["timestamp", "file_path", "old_hash", "new_hash", "ai_risk_score", "event_id"]]
                .sort_values("timestamp", ascending=False)
            )
            hash_table["timestamp"] = hash_table["timestamp"].apply(format_timestamp)

            st.dataframe(
                hash_table.rename(
                    columns={
                        "timestamp": "Time",
                        "file_path": "File path",
                        "old_hash": "Before hash",
                        "new_hash": "After hash",
                        "ai_risk_score": "Risk",
                        "event_id": "Event ID",
                    }
                ),
                use_container_width=True,
                height=380,
            )

# =============================================================
# Main layout: Table + Details + Timeline
# =============================================================
table_col, detail_col, timeline_col = st.columns([2.6, 1.6, 1.4])

with table_col:
    st.subheader("📄 Events table")

    df_display = df.copy()
    df_display["timestamp"] = df_display["timestamp"].apply(format_timestamp)
    df_display["severity"] = df_display["ai_risk_score"].apply(classify_risk).str.upper()
    df_display["mitre"] = df_display["mitre_technique"]

    st.dataframe(
        df_display[
            [
                "timestamp",
                "event_id",
                "event_type",
                "file_path",
                "ai_risk_score",
                "severity",
                "mitre",
                "user",
                "process",
                "host",
                "site",
            ]
        ]
        .style.format({"ai_risk_score": "{:.0f}"})
        .hide(axis="index"),
        use_container_width=True,
        height=520,
    )

with detail_col:
    st.subheader("🔍 Event details")

    # Choose event by ID for a stable selection key
    selected_id = st.selectbox("Select event", options=df["event_id"].tolist())
    event = df.loc[df["event_id"] == selected_id].iloc[0]

    badge = severity_badge(int(event["ai_risk_score"]))
    st.markdown(f"**Severity:** {badge}", unsafe_allow_html=True)
    st.markdown(
        f"**Event:** `{event['event_type']}` on `{event['file_path']}` @ {format_timestamp(event['timestamp'])}"
    )
    st.markdown(f"**Host / Site:** `{event['host']}` / `{event['site']}`")
    st.markdown(f"**Actor:** `{event['user']}` via `{event['process']}`")
    st.markdown(f"**MITRE:** {mitre_badge(event['mitre_technique'])}", unsafe_allow_html=True)

    st.progress(int(event["ai_risk_score"]), text="Risk score")

    st.markdown("---")
    st.markdown("**Hash change (demo):**")
    st.code(f"{event['old_hash']}  ->  {event['new_hash']}")

    st.markdown("**Why this triggered**")
    st.write(event["reason"])

    st.markdown("**Analyst playbook**")
    st.write(
        "- Validate change source (ticket, deployment window)\n"
        "- Correlate with identity telemetry (SSO, MFA logs)\n"
        "- Capture forensic copy before remediation (if high)\n"
        "- Escalate to IR on repeated unauthorized modifications"
    )

with timeline_col:
    st.subheader("🕒 Live feed (last 12)")
    timeline_df = df.sort_values("timestamp", ascending=True).tail(12)

    for _, row in timeline_df.iterrows():
        ts = row["timestamp"].strftime("%H:%M:%S")
        etype = row["event_type"]
        fpath = row["file_path"]
        score = row["ai_risk_score"]
        level = classify_risk(score)
        emoji = {
            "create": "🟩",
            "modify": "🟨",
            "delete": "🟥",
        }.get(etype, "⬜")
        st.markdown(
            f"**{ts}** — {emoji} `{etype}` on `{fpath}` | "
            f"Risk: <span style='color:{SEVERITY_COLORS[level]};'>{score}</span>"
            f" | {mitre_badge(row['mitre_technique'])}",
            unsafe_allow_html=True,
        )

st.caption("Data is pulled from the live /events API endpoint (limit=100).")
