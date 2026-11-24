
import streamlit as st
import pandas as pd
import os

st.set_page_config(
    page_title="TrapTrace-AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ TrapTrace-AI")
st.subheader("Cybersecurity Threat Monitoring Dashboard")

st.markdown("---")

# Load security events
file_path = "security_events.csv"

if os.path.exists(file_path):
    df = pd.read_csv(file_path)
else:
    st.warning("Security events file not found. Run the main project first.")
    st.stop()

# Sidebar filters
st.sidebar.header("Dashboard Controls")

sources = ["All"] + sorted(df["source"].dropna().unique().tolist())
selected_source = st.sidebar.selectbox("Select Source", sources)

severities = ["All"] + sorted(df["severity"].dropna().unique().tolist())
selected_severity = st.sidebar.selectbox("Select Severity", severities)

filtered_df = df.copy()

if selected_source != "All":
    filtered_df = filtered_df[filtered_df["source"] == selected_source]

if selected_severity != "All":
    filtered_df = filtered_df[
        filtered_df["severity"].str.lower() == selected_severity.lower()
    ]

# Dashboard metrics
total_events = len(filtered_df)
high_risk = filtered_df["severity"].str.lower().isin(
    ["high", "critical"]
).sum()
critical_events = (
    filtered_df["severity"].str.lower() == "critical"
).sum()
sources_count = filtered_df["source"].nunique()

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", total_events)
col2.metric("High Risk Events", int(high_risk))
col3.metric("Critical Events", int(critical_events))
col4.metric("Sources Monitored", sources_count)

st.markdown("---")

# Severity chart
left, right = st.columns(2)

with left:
    st.subheader("Threat Severity Distribution")
    severity_counts = filtered_df["severity"].value_counts()
    st.bar_chart(severity_counts)

with right:
    st.subheader("Events by Source")
    source_counts = filtered_df["source"].value_counts()
    st.bar_chart(source_counts)

st.markdown("---")

# Security event table
st.subheader("Security Event Log")
st.dataframe(filtered_df, use_container_width=True)

# High-risk events
st.subheader("🚨 High-Risk Security Events")

high_risk_df = filtered_df[
    filtered_df["severity"].str.lower().isin(["high", "critical"])
]

if high_risk_df.empty:
    st.success("No high-risk events found.")
else:
    st.dataframe(high_risk_df, use_container_width=True)

# Download report
st.markdown("---")
st.subheader("Download Security Data")

csv_data = filtered_df.to_csv(index=False).encode("utf-8")

st.download_button(
    label="Download Filtered Events CSV",
    data=csv_data,
    file_name="traptrace_security_events.csv",
    mime="text/csv"
)

st.success("TrapTrace-AI Dashboard Loaded Successfully")
