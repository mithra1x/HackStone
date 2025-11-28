import random
from datetime import datetime, timedelta
from typing import Dict, List

import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# =============================================================
# Page config
# =============================================================
st.set_page_config(
    page_title="FIM Command Center",
    layout="wide",
    page_icon="🔐",
)

st.title("🔐 File Integrity Monitoring Command Center")
st.caption(
    "BLUE 3 – Enterprise demo with risk scores, MITRE mapping, live feed, and analyst playbooks"
)

# =============================================================
# Auto-refresh (every 3 seconds)
# =============================================================
st_autorefresh(interval=3000, key="fim_refresh")

# =============================================================
# Session state (store events here)
# =============================================================
if "events" not in st.session_state:
    st.session_state.events: List[Dict] = []

# =============================================================
# Random event generator (until an API arrives)
# =============================================================
EVENT_TYPES = ["create", "modify", "delete"]
FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/var/www/html/index.php",
    "/opt/app/config.yaml",
    "/usr/local/bin/backup.sh",
    "/home/deploy/.ssh/authorized_keys",
]
MITRE = ["T1070", "T1059", "T1098", "T1565", "T1110", "T1021"]
USERS = ["root", "www-data", "deploy", "backup", "unknown", "jenkins"]
PROCESSES = [
    "ssh",
    "apache2",
    "python3",
    "bash",
    "cron",
    "systemd",
    "rsync",
]
HOSTS = ["edge-gw-01", "db-02", "web-01", "web-02", "siem-forwarder"]
SITES = ["fra-1", "lon-3", "iad-5"]


def add_random_event() -> None:
    now = datetime.now()
    event_type = random.choices(EVENT_TYPES, weights=[0.35, 0.45, 0.2])[0]
    file_path = random.choice(FILES)
    ai_risk_score = random.randint(5, 100)
    mitre = random.choice(MITRE)
    user = random.choice(USERS)
    process = random.choice(PROCESSES)
    old_hash = f"old_{random.getrandbits(32):08x}"
    new_hash = f"new_{random.getrandbits(32):08x}"
    host = random.choice(HOSTS)
    site = random.choice(SITES)
    event_id = f"evt-{random.getrandbits(20):05x}"
    reason = (
        f"{event_type.title()} detected on {file_path} by {process}; "
        f"mapped to MITRE {mitre} and scored by AI risk engine."
    )

    st.session_state.events.append(
        {
            "event_id": event_id,
            "timestamp": now,
            "event_type": event_type,
            "file_path": file_path,
            "ai_risk_score": ai_risk_score,
            "mitre_technique": mitre,
            "user": user,
            "process": process,
            "old_hash": old_hash,
            "new_hash": new_hash,
            "host": host,
            "site": site,
            "reason": reason,
        }
    )

    # Keep the buffer small for demo purposes
    if len(st.session_state.events) > 150:
        st.session_state.events = st.session_state.events[-150:]


# Demo: add a new event on each refresh
add_random_event()

# DataFrame
if not st.session_state.events:
    st.warning("No events yet.")
    st.stop()

df = pd.DataFrame(st.session_state.events)
df = df.sort_values("timestamp", ascending=False).reset_index(drop=True)

# =============================================================
# Sidebar filters
# =============================================================
st.sidebar.header("Filters")

preset_start = datetime.now() - timedelta(hours=2)
time_range = st.sidebar.slider(
    "Time window",
    min_value=preset_start,
    max_value=datetime.now(),
    value=(preset_start, datetime.now()),
    step=timedelta(minutes=5),
)

mitre_filter = st.sidebar.multiselect(
    "MITRE techniques",
    options=sorted(MITRE),
    default=MITRE,
)

event_type_filter = st.sidebar.multiselect(
    "Event type",
    options=EVENT_TYPES,
    default=EVENT_TYPES,
)

user_filter = st.sidebar.multiselect("User", options=sorted(set(USERS)), default=USERS)
process_filter = st.sidebar.multiselect(
    "Process",
    options=sorted(set(PROCESSES)),
    default=PROCESSES,
)

host_filter = st.sidebar.multiselect("Host", options=sorted(set(HOSTS)), default=HOSTS)

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
# Main layout: Table + Details + Timeline
# =============================================================
table_col, detail_col, timeline_col = st.columns([2.6, 1.6, 1.4])

with table_col:
    st.subheader("📄 Events table")

    df_display = df.copy()
    df_display["timestamp"] = df_display["timestamp"].apply(format_timestamp)
    df_display["severity"] = df_display["ai_risk_score"].apply(severity_badge)
    df_display["mitre"] = df_display["mitre_technique"].apply(mitre_badge)

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
        .hide_index(),
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
        "- Capture forensic copy before remediation (if high/critical)\n"
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

st.caption(
    "Demo only – production would stream from /events, enrich with IAM + EDR context, and persist to SIEM."
)
