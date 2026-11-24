
import pandas as pd
from datetime import datetime


def generate_report(
    events_file="security_events.csv",
    output_file="threat_report.txt"
):
    """
    Generate a cybersecurity threat analysis report.
    """

    try:
        df = pd.read_csv(events_file)

    except FileNotFoundError:
        print("Security event file not found.")
        return None

    if df.empty:
        print("No events available for reporting.")
        return None

    total_events = len(df)

    severity_counts = (
        df["severity"].str.lower().value_counts()
    )

    high_risk = df[
        df["severity"].str.lower().isin(
            ["high", "critical"]
        )
    ]

    report = []

    report.append("===================================")
    report.append("       TrapTrace-AI REPORT")
    report.append("===================================")

    report.append(
        f"Generated: {datetime.now().isoformat()}"
    )

    report.append(f"Total Events: {total_events}")

    report.append("\nSeverity Distribution:")

    for severity, count in severity_counts.items():
        report.append(f"{severity}: {count}")

    report.append("\nHigh-Risk Events:")

    if high_risk.empty:
        report.append("No high-risk events detected.")
    else:
        for _, event in high_risk.iterrows():
            report.append(
                f"{event['source']} | "
                f"{event['event_type']} | "
                f"{event['description']}"
            )

    report.append("\n===================================")

    with open(output_file, "w", encoding="utf-8") as file:
        file.write("\n".join(report))

    print("\nThreat report generated successfully!")
    print(f"Saved as: {output_file}")

    return output_file


if __name__ == "__main__":
    generate_report()
  
