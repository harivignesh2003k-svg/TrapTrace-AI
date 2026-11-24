
import pandas as pd


def detect_threats(filename="security_events.csv"):
    """
    Detect suspicious security patterns.
    """

    try:
        df = pd.read_csv(filename)
    except FileNotFoundError:
        print("Security event file not found.")
        return None

    if df.empty:
        print("No security events to analyze.")
        return pd.DataFrame()

    threats = []

    # Detect repeated failed login attempts
    failed_logins = df[
        df["event_type"].str.lower() == "failed login"
    ]

    if len(failed_logins) >= 3:
        threats.append({
            "threat": "Repeated Failed Login Attempts",
            "count": len(failed_logins),
            "risk": "HIGH",
            "description": "Multiple failed login attempts detected."
        })

    # Detect critical severity events
    critical_events = df[
        df["severity"].str.lower() == "critical"
    ]

    for _, event in critical_events.iterrows():
        threats.append({
            "threat": "Critical Security Event",
            "count": 1,
            "risk": "CRITICAL",
            "description": event["description"]
        })

    results = pd.DataFrame(threats)

    print("\n===== TrapTrace-AI Threat Detection =====")

    if results.empty:
        print("No suspicious patterns detected.")
    else:
        print(results.to_string(index=False))

    return results


if __name__ == "__main__":
    detect_threats()
  
