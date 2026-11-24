
import pandas as pd


def analyze_events(filename="security_events.csv"):
    """
    Analyze collected security events and identify
    suspicious activities.
    """

    try:
        df = pd.read_csv(filename)

    except FileNotFoundError:
        print("Security event file not found.")
        return None

    if df.empty:
        print("No events available for analysis.")
        return df

    # Count events by severity
    severity_counts = df["severity"].value_counts()

    # Identify high-severity events
    suspicious_events = df[
        df["severity"].str.lower().isin(["high", "critical"])
    ]

    print("\n===== TrapTrace-AI Event Analysis =====")

    print("\nEvent Severity Summary:")
    print(severity_counts)

    print("\nSuspicious Events:")
    print(suspicious_events)

    return suspicious_events


if __name__ == "__main__":
    analyze_events()
  
