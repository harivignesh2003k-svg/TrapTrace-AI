
import os
import html
import pandas as pd
import streamlit as st

# ==================================================
# 1. PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="TrapTrace-AI | Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================================================
# 2. CUSTOM CSS - DARK CYBERSECURITY THEME
# ==================================================

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

p, label {
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

/* RED - CRITICAL THREATS */

.alert-box {
    background-color: #351b25;
    border-left: 5px solid #ef4444;
    padding: 14px 16px;
    border-radius: 8px;
    margin-bottom: 10px;
    color: #ffffff;
}

/* YELLOW - HIGH RISK */

.warning-box {
    background-color: #352b18;
    border-left: 5px solid #f59e0b;
    padding: 14px 16px;
    border-radius: 8px;
    margin-bottom: 10px;
    color: #ffffff;
}

/* GREEN - SYSTEM OPERATIONAL */

.safe-box {
    background-color: #123326;
    border-left: 5px solid #22c55e;
    padding: 14px 16px;
    border-radius: 8px;
    margin-bottom: 10px;
    color: #ffffff;
}

/* BLUE - INFORMATION */

.info-box {
    background-color: #14283a;
    border-left: 5px solid #38bdf8;
    padding: 14px 16px;
    border-radius: 8px;
    margin-bottom: 10px;
    color: #ffffff;
}

div.stDownloadButton > button {
    background-color: #0ea5e9;
    color: white;
    border: none;
    border-radius: 8px;
}

div.stDownloadButton > button:hover {
    background-color: #0284c7;
    color: white;
}

.footer {
    text-align: center;
    color: #64748b;
    font-size: 12px;
    padding-top: 25px;
}

</style>
""", unsafe_allow_html=True)


# ==================================================
# 3. HEADER
# ==================================================

st.markdown("# 🛡️ TrapTrace-AI")

st.markdown(
    "### CYBERSECURITY THREAT MONITORING CENTER"
)

st.caption(
    "Security Event Analysis | Threat Detection | Event Correlation"
)

st.markdown("---")


# ==================================================
# 4. LOAD SECURITY EVENTS
# ==================================================

file_path = "security_events.csv"

if not os.path.exists(file_path):

    st.error("Security events file not found.")

    st.info(
        "Run the main project first using: python run_project.py"
    )

    st.stop()

try:
    df = pd.read_csv(file_path)

except Exception as error:

    st.error(f"Unable to read security events: {error}")
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


# Clean missing values

for column in required_columns:

    df[column] = (
        df[column]
        .fillna("Unknown")
        .astype(str)
    )


# ==================================================
# 5. SIDEBAR CONTROLS
# ==================================================

st.sidebar.title("⚙️ Dashboard Controls")

st.sidebar.markdown("---")

sources = ["All"] + sorted(
    df["source"].unique().tolist()
)

selected_source = st.sidebar.selectbox(
    "Filter by Source",
    sources
)

severities = ["All"] + sorted(
    df["severity"].unique().tolist()
)

selected_severity = st.sidebar.selectbox(
    "Filter by Severity",
    severities
)

search_text = st.sidebar.text_input(
    "🔎 Search Events",
    placeholder="Search event details..."
)

st.sidebar.markdown("---")

st.sidebar.caption(
    "TrapTrace-AI | Prototype v1.0"
)


# ==================================================
# 6. APPLY FILTERS
# ==================================================

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


if search_text.strip():

    search_mask = filtered_df.astype(str).apply(
        lambda column: column.str.contains(
            search_text.strip(),
            case=False,
            na=False,
            regex=False
        )
    ).any(axis=1)

    filtered_df = filtered_df[search_mask]


# ==================================================
# 7. SECURITY OVERVIEW
# ==================================================

total_events = len(filtered_df)

high_risk_df = filtered_df[
    filtered_df["severity"].str.lower().isin(
        ["high", "critical"]
    )
]

high_risk_count = len(high_risk_df)

critical_count = (
    filtered_df["severity"].str.lower()
    == "critical"
).sum()

source_count = filtered_df["source"].nunique()


st.subheader("📊 Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Events",
    total_events
)

col2.metric(
    "High Risk Events",
    high_risk_count
)

col3.metric(
    "Critical Events",
    int(critical_count)
)

col4.metric(
    "Sources Monitored",
    source_count
)

st.markdown("---")


# ==================================================
# 8. SYSTEM STATUS - GREEN INDICATOR
# ==================================================

st.markdown("""
<div class="safe-box">
    <strong>🟢 MONITORING SYSTEM OPERATIONAL</strong><br>
    TrapTrace-AI dashboard is running and security event data
    has been loaded successfully.
</div>
""", unsafe_allow_html=True)


# ==================================================
# 9. THREAT STATUS
# ==================================================

if critical_count > 0:

    st.markdown(
        f"""
        <div class="alert-box">
            <strong>🔴 CRITICAL THREATS DETECTED</strong><br>
            {critical_count} critical security event(s) detected.
            Immediate investigation is recommended.
        </div>
        """,
        unsafe_allow_html=True
    )

elif high_risk_count > 0:

    st.markdown(
        f"""
        <div class="warning-box">
            <strong>🟡 HIGH-RISK ACTIVITY DETECTED</strong><br>
            {high_risk_count} high-risk event(s) require investigation.
        </div>
        """,
        unsafe_allow_html=True
    )

else:

    st.markdown("""
    <div class="safe-box">
        <strong>🟢 NO HIGH-RISK EVENTS DETECTED</strong><br>
        No high or critical events were found in the selected data.
    </div>
    """, unsafe_allow_html=True)


# ==================================================
# 10. THREAT ANALYTICS
# ==================================================

st.markdown("---")

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


# ==================================================
# 11. COLOR-CODED THREAT ALERTS
# ==================================================

st.markdown("---")

st.subheader("🚨 Threat Alerts")

if high_risk_df.empty:

    st.markdown("""
    <div class="safe-box">
        <strong>🟢 SYSTEM STATUS: SAFE</strong><br>
        No high-risk events found in the current selection.
    </div>
    """, unsafe_allow_html=True)

else:

    for _, event in high_risk_df.iterrows():

        severity = event["severity"].upper()

        source = html.escape(event["source"])
        event_type = html.escape(event["event_type"])
        description = html.escape(event["description"])

        if severity == "CRITICAL":

            css_class = "alert-box"
            icon = "🔴"

        elif severity == "HIGH":

            css_class = "warning-box"
            icon = "🟡"

        else:

            css_class = "info-box"
            icon = "🔵"

        st.markdown(
            f"""
            <div class="{css_class}">
                <strong>{icon} {severity} | {source}</strong><br>
                Event: {event_type}<br>
                Details: {description}
            </div>
            """,
            unsafe_allow_html=True
        )


# ==================================================
# 12. SECURITY EVENT LOG
# ==================================================

st.markdown("---")

st.subheader("📋 Security Event Log")

st.caption(
    f"Displaying {len(filtered_df)} of {len(df)} total events."
)

st.dataframe(
    filtered_df,
    width="stretch",
    hide_index=True
)


# ==================================================
# 13. DOWNLOAD SECURITY REPORT
# ==================================================

st.markdown("---")

st.subheader("📥 Export Security Data")

csv_data = filtered_df.to_csv(
    index=False
).encode("utf-8")

st.download_button(
    label="⬇️ Download Filtered Events (CSV)",
    data=csv_data,
    file_name="TrapTrace_AI_Security_Report.csv",
    mime="text/csv",
    width="stretch"
)


# ==================================================
# 14. PROJECT INFORMATION
# ==================================================

st.markdown("---")

with st.expander(
    "ℹ️ About TrapTrace-AI and Detection Methodology"
):

    st.markdown("""
    **TrapTrace-AI** is a prototype cybersecurity event
    monitoring and threat detection platform.

    ### Core Modules

    1. Event Collector – Collects and stores security events.
    2. Event Analyzer – Analyzes event severity and patterns.
    3. Threat Detector – Identifies repeated failed logins
       and critical events.
    4. Correlation Engine – Groups suspicious activity by source.
    5. Report Generator – Produces security reports.

    ### Current Detection Approach

    Rule-based detection and event correlation using
    locally generated sample security events.

    ### Current Limitations

    This version uses sample data. It does not yet provide
    live network monitoring or production-grade
    machine-learning threat detection.
    """)


# ==================================================
# 15. FOOTER
# ==================================================

st.markdown("""
<div class="footer">
TRAPTRACE-AI | CYBERSECURITY MONITORING PROTOTYPE<br>
Built with Python, Pandas and Streamlit
</div>
""", unsafe_allow_html=True)
    
