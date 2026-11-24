
import pandas as pd


def correlate_events(filename="security_events.csv"):
    """
    Correlate security events across different sources.
    """

    try:
        df = pd.read_csv(filename)

    except FileNotFoundError:
        print("Security event file not found.")
        return None

    if df.empty:
        print("No events available for correlation.")
        return pd.DataFrame()

    # Identify events from different channels
    channel_summary = (
        df.groupby("source")
        .agg(
            total_events=("event_type", "count"),
            high_risk_events=(
                "severity",
                lambda x: x.astype(str).str.lower().isin(
                    ["high", "critical"]
                ).sum()
            )
        )
        .reset_index()
    )

    print("\n===== TrapTrace-AI Correlation Engine =====")

    print("\nChannel-wise Event Summary:")
    print(channel_summary.to_string(index=False))

    # Identify sources with multiple high-risk events
    suspicious_sources = channel_summary[
        channel_summary["high_risk_events"] >= 2
    ]

    print("\nSuspicious Sources:")

    if suspicious_sources.empty:
        print("No correlated suspicious sources identified.")
    else:
        print(suspicious_sources.to_string(index=False))

    return channel_summary


if __name__ == "__main__":
    correlate_events()
  
