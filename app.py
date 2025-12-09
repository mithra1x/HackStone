from datetime import datetime, timedelta
from typing import Dict

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

API_URL = "http://127.0.0.1:8000/events?limit=100"

# =============================================================
# Page config
# =============================================================
st.set_page_config(
    page_title="FIM Command Center",
    layout="wide",
    page_icon="🔐",
)

st.markdown(
    """
    <style>
    .app-bg {
        background: radial-gradient(circle at 20% 20%, #0f172a, #020617 60%);
        color: #e2e8f0;
        padding: 18px 28px;
        border-radius: 14px;
        box-shadow: 0 25px 50px -12px rgba(15, 23, 42, 0.85);
    }
    .metric-card {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 12px;
    }
    .section-divider {
        margin: 14px 0 2px 0;
        height: 1px;
        background: linear-gradient(90deg, #22d3ee, rgba(34, 211, 238, 0));
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    "<div class='app-bg'>\n"
    "<h1 style='margin-bottom:0;'>🔐 File Integrity Monitoring Command Center</h1>"
    "<p style='color:#cbd5e1;margin-top:4px;'>Unified timeline, KPIs, and response aids in a single view.</p>"
    "</div>",
    unsafe_allow_html=True,
)

# =============================================================
# Auto-refresh (every 3 seconds)
# =============================================================
st_autorefresh(interval=3000, key="fim_refresh")


# =============================================================
# Data loading
# =============================================================
def load_events_from_api() -> pd.DataFrame:
    """Return events from the API as a DataFrame with best-effort typing."""

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
    except Exception as exc:  # noqa: BLE001
        st.error(f"API error: {exc}")
        return pd.DataFrame()


# =============================================================
# Guard rails & defaults
# =============================================================
df = load_events_from_api()

if df.empty:
    st.info("Hələ API-dən event gəlmir.")
    st.stop()

df = df.sort_values("timestamp", ascending=False).reset_index(drop=True)

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

df["ai_risk_score"] = (
    pd.to_numeric(df.get("ai_risk_score", 0), errors="coerce").fillna(0).astype(int)
)

if "event_id" not in df.columns:
    df["event_id"] = [f"evt-{i:05d}" for i in range(len(df))]

# =============================================================
# Helper utilities
# =============================================================
SEVERITY_COLORS = {
    "critical": "#d7263d",
    "high": "#f77f00",
    "medium": "#ffd166",
    "low": "#4cc9f0",
}


def classify_risk(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def severity_badge(score: int) -> str:
    level = classify_risk(score)
    color = SEVERITY_COLORS[level]
    return f"<span style='color:{color}; font-weight:700;'>{level.upper()}</span>"


def mitre_badge(technique: str) -> str:
    return (
        "<span style='background:#111827;color:white;padding:2px 6px;border-radius:6px;"
        "font-size:12px;'>MITRE "
        f"{technique}</span>"
    )


def format_timestamp(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def priority_lane(events: pd.DataFrame) -> None:
    """Display the top risks first for rapid triage."""

    st.subheader("🚨 Priority incidents")
    top = events.sort_values("ai_risk_score", ascending=False).head(5)
    for _, row in top.iterrows():
        ts = format_timestamp(row["timestamp"])
        badge = severity_badge(int(row["ai_risk_score"]))
        st.markdown(
            f"{badge} — `{row['event_type']}` on `{row['file_path']}` "
            f"at {ts} | {mitre_badge(row['mitre_technique'])}",
            unsafe_allow_html=True,
        )


def mini_timeline(events: pd.DataFrame, *, title: str, limit: int = 12) -> None:
    st.subheader(title)
    subset = events.sort_values("timestamp", ascending=True).tail(limit)

    for _, row in subset.iterrows():
        ts = row["timestamp"].strftime("%H:%M:%S")
        etype = row["event_type"]
        fpath = row["file_path"]
        score = int(row["ai_risk_score"])
        level = classify_risk(score)
        emoji = {
            "create": "🟩",
            "modify": "🟨",
            "delete": "🟥",
        }.get(etype, "⬜")
        st.markdown(
            f"**{ts}** — {emoji} `{etype}` on `{fpath}` | "
            f"Risk: <span style='color:{SEVERITY_COLORS[level]};'>{score}</span> "
            f"| {mitre_badge(row['mitre_technique'])}",
            unsafe_allow_html=True,
        )


# =============================================================
# Filters (single-page layout)
# =============================================================
min_ts = df["timestamp"].min()
max_ts = df["timestamp"].max()
default_start = max(min_ts, max_ts - timedelta(hours=2))

st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
filter_col1, filter_col2, filter_col3 = st.columns([2.6, 1.6, 1.6])

with filter_col1:
    st.markdown("#### Filters")
    if min_ts == max_ts:
        time_range = (min_ts.to_pydatetime(), max_ts.to_pydatetime())
    else:
        time_range = st.slider(
            "Time window",
            min_value=min_ts.to_pydatetime(),
            max_value=max_ts.to_pydatetime(),
            value=(default_start.to_pydatetime(), max_ts.to_pydatetime()),
            step=timedelta(minutes=5),
        )

with filter_col2:
    event_types = sorted(df["event_type"].dropna().unique().tolist())
    mitre_options = sorted(df["mitre_technique"].dropna().unique().tolist())
    mitre_filter = st.multiselect("MITRE techniques", options=mitre_options, default=mitre_options)
    event_type_filter = st.multiselect("Event type", options=event_types, default=event_types)

with filter_col3:
    users = sorted(df["user"].dropna().unique().tolist())
    processes = sorted(df["process"].dropna().unique().tolist())
    hosts = sorted(df["host"].dropna().unique().tolist())
    user_filter = st.multiselect("User", options=users, default=users)
    process_filter = st.multiselect("Process", options=processes, default=processes)
    host_filter = st.multiselect("Host", options=hosts, default=hosts)

st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
col_focus, col_risk = st.columns([1, 2.5])
with col_focus:
    focus_high = st.checkbox("Focus on high & critical only", value=False)
with col_risk:
    min_risk = 70 if focus_high else st.slider(
        "Minimum AI risk score", min_value=0, max_value=100, value=40, step=5
    )

start_ts, end_ts = time_range
filtered = df[(df["timestamp"] >= start_ts) & (df["timestamp"] <= end_ts)]
filtered = filtered[
    (filtered["event_type"].isin(event_type_filter))
    & (filtered["mitre_technique"].isin(mitre_filter))
    & (filtered["user"].isin(user_filter))
    & (filtered["process"].isin(process_filter))
    & (filtered["host"].isin(host_filter))
    & (filtered["ai_risk_score"] >= min_risk)
]

if filtered.empty:
    st.info("No events match the current filters.")
    st.stop()

filtered["severity"] = filtered["ai_risk_score"].apply(classify_risk)

# Shared derived data
latest_event_time = filtered["timestamp"].max()
by_type = filtered.groupby("event_type").size().reset_index(name="count")
by_host = filtered.groupby("host").size().reset_index(name="count")
by_mitre = filtered.groupby("mitre_technique").size().reset_index(name="count")


# =============================================================
# Section builders
# =============================================================
def render_kpis(data: pd.DataFrame) -> None:
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total events (filtered)", len(data))

    with col2:
        high_risk_count = (data["ai_risk_score"] >= 80).sum()
        st.metric("High-risk (≥80)", int(high_risk_count))

    with col3:
        st.metric("Unique files touched", data["file_path"].nunique())

    with col4:
        st.metric("Hosts involved", data["host"].nunique())

    with col5:
        last_event_time = data["timestamp"].max().strftime("%H:%M:%S")
        st.metric("Last event time", last_event_time)


def render_overview() -> None:
    st.markdown("## Overview")
    st.caption("Critical insights up-front with real-time refresh and minimal clicks.")
    render_kpis(filtered)

    top_row_left, top_row_right = st.columns([2.3, 1.7])
    with top_row_left:
        st.subheader("Event volume by type")
        fig_type = px.bar(by_type, x="event_type", y="count", color="event_type", height=320)
        st.plotly_chart(fig_type, use_container_width=True)

    with top_row_right:
        st.subheader("Risk score distribution")
        fig_risk = px.histogram(
            filtered,
            x="ai_risk_score",
            nbins=15,
            color=filtered["severity"],
            height=320,
            labels={"color": "severity"},
        )
        st.plotly_chart(fig_risk, use_container_width=True)

    priority_lane(filtered)

    table_col, detail_col, timeline_col = st.columns([2.3, 1.4, 1.3])
    with table_col:
        st.subheader("📄 Events table")
        df_display = filtered.copy()
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
        selected_id = st.selectbox("Select event", options=filtered["event_id"].tolist())
        event = filtered.loc[filtered["event_id"] == selected_id].iloc[0]

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
            "- Capture forensic copy before remediation (if high/critical)\n"
            "- Escalate to IR on repeated unauthorized modifications"
        )

    with timeline_col:
        mini_timeline(filtered, title="🕒 Live feed (last 12)")


def render_assets() -> None:
    st.markdown("### Assets / Liabilities")
    st.caption("Surface hosts, files, and hotspots with the most business impact.")

    col1, col2, col3 = st.columns(3)
    with col1:
        busiest_host = by_host.sort_values("count", ascending=False).head(1)
        host_name = busiest_host["host"].iloc[0]
        st.metric("Busiest host", host_name, delta=int(busiest_host["count"].iloc[0]))
    with col2:
        st.metric("Files under watch", filtered["file_path"].nunique())
    with col3:
        st.metric("Sites represented", filtered["site"].nunique())

    st.subheader("Top file paths")
    file_heat = (
        filtered.groupby("file_path")
        .agg(events=("event_type", "count"), max_risk=("ai_risk_score", "max"))
        .sort_values(["events", "max_risk"], ascending=False)
        .reset_index()
        .head(15)
    )
    st.dataframe(file_heat, use_container_width=True)

    st.subheader("Host coverage")
    fig_host = px.bar(by_host, x="host", y="count", color="count", height=320)
    st.plotly_chart(fig_host, use_container_width=True)


def render_risk_indicators() -> None:
    st.markdown("### Risk Indicators")
    st.caption("Prioritize which techniques and users pose the most risk.")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("MITRE technique prevalence")
        fig_mitre = px.bar(by_mitre, x="mitre_technique", y="count", color="count", height=320)
        st.plotly_chart(fig_mitre, use_container_width=True)
    with col2:
        st.subheader("Top users by risk")
        by_user = (
            filtered.groupby("user")
            .agg(events=("event_type", "count"), max_risk=("ai_risk_score", "max"))
            .sort_values(["max_risk", "events"], ascending=False)
            .reset_index()
            .head(10)
        )
        st.dataframe(by_user, use_container_width=True)

    priority_lane(filtered)


def render_performance_yield() -> None:
    st.markdown("### Performance & Yield")
    st.caption("Change velocity and signal quality to validate monitoring coverage.")

    timeline = (
        filtered.copy()
        .assign(minute=filtered["timestamp"].dt.floor("T"))
        .groupby("minute")
        .size()
        .reset_index(name="count")
    )
    fig_time = px.line(timeline, x="minute", y="count", markers=True, height=320)
    st.plotly_chart(fig_time, use_container_width=True)

    st.subheader("Event-type efficiency")
    etype_detail = (
        filtered.groupby("event_type")
        .agg(avg_risk=("ai_risk_score", "mean"), volume=("event_type", "count"))
        .reset_index()
        .sort_values("volume", ascending=False)
    )
    st.dataframe(etype_detail, use_container_width=True)


def render_liquidity() -> None:
    st.markdown("## Liquidity Management")
    st.caption("See where activity is peaking so analysts can rebalance workload.")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Activity by host")
        st.bar_chart(by_host.set_index("host"))
    with col2:
        st.subheader("Last event timestamp")
        st.info(f"Latest recorded event: **{format_timestamp(latest_event_time)}**")

    mini_timeline(filtered, title="Latest actions")


def render_risk_management() -> None:
    st.markdown("## Risk Management")
    st.caption("VaR-like perspective on worst-case changes and stress scenarios.")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("VaR, Duration, Convexity")
        tail_risk = filtered.sort_values("ai_risk_score", ascending=False).head(5)
        st.dataframe(tail_risk[["timestamp", "file_path", "ai_risk_score", "mitre_technique"]], use_container_width=True)
    with col2:
        st.subheader("Stress Testing Results")
        stress = (
            filtered.assign(minute=filtered["timestamp"].dt.floor("T"))
            .groupby("minute")
            .agg(volume=("event_type", "count"), peak_risk=("ai_risk_score", "max"))
            .sort_values("volume", ascending=False)
            .reset_index()
            .head(10)
        )
        st.dataframe(stress, use_container_width=True)


def render_reports() -> None:
    st.markdown("## Reports & Data Export")
    st.caption("Download filtered evidence or pivot it for auditors in one click.")

    csv = filtered.to_csv(index=False).encode("utf-8")
    st.download_button("Download filtered events (CSV)", csv, "fim_events.csv", "text/csv")

    st.subheader("Filter summary")
    st.write(
        {
            "time_window": f"{format_timestamp(start_ts)} → {format_timestamp(end_ts)}",
            "event_types": event_type_filter,
            "mitre": mitre_filter,
            "users": user_filter,
            "processes": process_filter,
            "hosts": host_filter,
            "min_risk": min_risk,
        }
    )

    mini_timeline(filtered, title="Export preview")


def render_admin() -> None:
    st.markdown("## Administration / Settings")
    st.caption("Operational toggles and runbook notes for operators.")

    st.info(f"Events endpoint: `{API_URL}` (auto-refresh active)")
    st.markdown("- Logs stay on local disk; secure `events.log` with OS controls.")
    st.markdown("- Hidden files remain excluded unless the agent is started with `--include-hidden`.")
    st.markdown("- Keep server and UI on trusted segments to protect integrity chain.")

    st.subheader("Quick health checks")
    st.metric("Events loaded", len(filtered))
    st.metric("Latest timestamp", format_timestamp(latest_event_time))
    st.metric("Unique MITRE techniques", filtered["mitre_technique"].nunique())


st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
render_overview()

st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
st.markdown("## Portfolio & Risk")
portfolio_tabs = st.tabs([
    "Assets / Liabilities",
    "Risk Indicators",
    "Performance & Yield",
])
with portfolio_tabs[0]:
    render_assets()
with portfolio_tabs[1]:
    render_risk_indicators()
with portfolio_tabs[2]:
    render_performance_yield()

st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
st.markdown("## Liquidity & Risk Ops")
col_liq, col_risk_ops = st.columns([1.05, 1])
with col_liq:
    render_liquidity()
with col_risk_ops:
    render_risk_management()

st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
st.markdown("## Exports & Administration")
col_reports, col_admin = st.columns([1.3, 1])
with col_reports:
    render_reports()
with col_admin:
    render_admin()

st.caption("Data is pulled from the live /events API endpoint (limit=100).")
