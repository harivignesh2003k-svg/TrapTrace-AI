
import os
import pandas as pd
import streamlit as st

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="TrapTrace-AI | Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --------------------------------------------------
# CUSTOM DARK THEME
# --------------------------------------------------

st.markdown("""
<style>
.stApp {
    background-color: #0b1120;
    color: #e5e7eb;
}

[data-testid="stSidebar"] {
    background-color: #111827;
    border-right: 1px solid #263449;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}

h1, h2, h3 {
    color: #f8fafc !important;
}

p, label, span {
    color: #cbd5e1;
}

[data-testid="stMetric"] {
    background: linear-gradient(145deg, #172337, #111827);
    border: 1px solid #263449;
    padding: 18px;
    border-radius: 12px;
}

[data-testid="stMetricValue"] {
    color: #38bdf8;
}

[data-testid="stMetricLabel"] {
    color: #cbd5e1;
}

hr {
    border-color: #263449;
}

div.stButton > button,
div.stDownloadButton > button {
    background-color: #0ea5e9;
    color: white;
    border: none;
    border-radius: 8px;
}

div.stButton > button:hover,
div.stDownloadButton > button:hover {
    background-color: #0284c7;
    color: white;
}

.alert-box {
    background-color: #351b25;
    border-left: 5px solid #ef4444;
    padding: 12px 16px;
    border-radius: 8px;
    margin-bottom: 10px;
}

.info-box {
    background-color: #14283a;
    border-left: 5px solid #38bdf8;
    padding: 14px 16px;
    border-radius: 8px;
}

.footer {
    text-align: center;
    color: #64748b;
    font-size: 12px;
    padding-top: 25px;
}
</style>
""", unsafe_allow_html=True)

# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.markdown(
    "<h1>🛡️ TrapTrace-AI</h1>",
    unsafe_allow_html=True
)

st.markdown(
    "### CYBERSECURITY THREAT MONITORING CENTER"
)

st.caption(
    "Security Event Analysis | Threat Detection | Event Correlation"
)

st.markdown("---")

# --------------------------------------------------
# LOAD SECURITY EVENTS
# --------------------------------------------------

file_path = "security_events.csv"

if not os.path.exists(file_path):
    st.error("Security events file not found.")
    st.info("Run the project first using: python run_project.py")
    st.stop()

try:
    df = pd.read_csv(file_path)
except Exception as error:
    st.error(f"Could not read security events: {error}")
    st.stop()

required_columns = [
    "timestamp",
    "source",
    "event_type",
    "description",
    "severity"
]

missing_columns = [
    column for column in required_columns
    if column not in df.columns
]

if missing_columns:
    st.error(f"Missing required columns: {missing_columns}")
    st.stop()

df["severity"] = df["severity"].fillna("unknown").astype(str)
df["source"] = df["source"].fillna("Unknown").astype(str)

# --------------------------------------------------
# SIDEBAR CONTROLS
# --------------------------------------------------

st.sidebar.title("⚙️ Dashboard Controls")
st.sidebar.markdown("---")

sources = ["All"] + sorted(df["source"].unique().tolist())

selected_source = st.sidebar.selectbox(
    "Filter by Source",
    sources
)

severities = ["All"] + sorted(df["severity"].unique().tolist())

selected_severity = st.sidebar.selectbox(
    "Filter by Severity",
    severities
)

search_text = st.sidebar.text_input(
    "🔎 Search Events",
    placeholder="Search event details..."
)

st.sidebar.markdown("---")
st.sidebar.caption("TrapTrace-AI | Prototype v1.0")

# --------------------------------------------------
# APPLY FILTERS
# --------------------------------------------------

filtered_df = df.copy()

if selected_source != "All":
    filtered_df = filtered_df[
        filtered_df["source"] == selected_source
    ]

if selected_severity != "All":
    filtered_df = filtered_df[
        filtered_df["severity"].str.lower()
        == selected_severity.lower()
    ]

if search_text:
    search_mask = filtered_df.astype(str).apply(
        lambda column: column.str.contains(
            search_text,
            case=False,
            na=False
        )
    ).any(axis=1)

    filtered_df = filtered_df[search_mask]

# --------------------------------------------------
# KPI METRICS
# --------------------------------------------------

total_events = len(filtered_df)

high_risk_events = filtered_df[
    filtered_df["severity"].str.lower().isin(
        ["high", "critical"]
    )
]

high_risk_count = len(high_risk_events)

critical_count = (
    filtered_df["severity"].str.lower() == "critical"
).sum()

source_count = filtered_df["source"].nunique()

st.subheader("📊 Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", total_events)
col2.metric("High Risk Events", high_risk_count)
col3.metric("Critical Events", int(critical_count))
col4.metric("Sources Monitored", source_count)

st.markdown("---")

# --------------------------------------------------
# SYSTEM STATUS
# --------------------------------------------------

if critical_count > 0:
    st.markdown(
        f"""
        <div class="alert-box">
        <strong>🚨 CRITICAL THREATS DETECTED</strong><br>
        {critical_count} critical event(s) found in the filtered data.
        Review the threat alerts below.
        </div>
        """,
        unsafe_allow_html=True
    )
elif high_risk_count > 0:
    st.markdown(
        """
        <div class="info-box">
        <strong>⚠️ HIGH-RISK ACTIVITY DETECTED</strong><br>
        Review the security event log for suspicious activity.
        </div>
        """,
        unsafe_allow_html=True
    )
else:
    st.success("No high-risk events detected in the filtered data.")

# --------------------------------------------------
# CHARTS
# --------------------------------------------------

st.subheader("📈 Threat Analytics")

left, right = st.columns(2)

with left:
    st.markdown("#### Threat Severity Distribution")

    severity_counts = (
        filtered_df["severity"]
        .str.lower()
        .value_counts()
    )

    if not severity_counts.empty:
        st.bar_chart(severity_counts)
    else:
        st.info("No severity data available.")

with right:
    st.markdown("#### Events by Source")

    source_counts = filtered_df["source"].value_counts()

    if not source_counts.empty:
        st.bar_chart(source_counts)
    else:
        st.info("No source data available.")

st.markdown("---")

# --------------------------------------------------
# THREAT ALERTS
# --------------------------------------------------

st.subheader("🚨 Threat Alerts")

if high_risk_events.empty:
    st.success("No high-risk events in the current selection.")
else:
    for _, event in high_risk_events.iterrows():
        severity = event["severity"].upper()

        st.markdown(
            f"""
            <div class="alert-box">
            <strong>{severity} | {event["source"]}</strong><br>
            Event: {event["event_type"]}<br>
            Details: {event["description"]}
            </div>
            """,
            unsafe_allow_html=True
        )

st.markdown("---")

# --------------------------------------------------
# SECURITY EVENT LOG
# --------------------------------------------------

st.subheader("📋 Security Event Log")

st.caption(
    f"Displaying {len(filtered_df)} of {len(df)} total events."
)

st.dataframe(
    filtered_df,
    use_container_width=True,
    hide_index=True
)

# --------------------------------------------------
# DOWNLOAD SECURITY DATA
# --------------------------------------------------

st.markdown("---")
st.subheader("📥 Export Security Data")

csv_data = filtered_df.to_csv(index=False).encode("utf-8")

st.download_button(
    label="⬇️ Download Filtered Events (CSV)",
    data=csv_data,
    file_name="TrapTrace_AI_Security_Report.csv",
    mime="text/csv",
    use_container_width=True
)

# --------------------------------------------------
# PROJECT INFORMATION
# --------------------------------------------------

st.markdown("---")

with st.expander("ℹ️ About TrapTrace-AI and Detection Methodology"):
    st.markdown("""
    **TrapTrace-AI** is a prototype cybersecurity event monitoring
    and threat detection platform.

    **Core modules:**
    - Event Collector: Collects and stores security events.
    - Event Analyzer: Analyzes event severity and patterns.
    - Threat Detector: Identifies repeated failed logins and critical events.
    - Correlation Engine: Groups suspicious activity by source.
    - Report Generator: Produces security reports.

    **Current detection approach:**
    Rule-based detection and event correlation using sample security events.

    **Important:** This version uses locally generated sample data.
    It does not yet provide live network monitoring or production-grade
    machine-learning threat detection.
    """)

st.markdown("""
<div class="footer">
TRAPTRACE-AI | CYBERSECURITY MONITORING PROTOTYPE<br>
Built with Python, Pandas and Streamlit
</div>
""", unsafe_allow_html=True)
