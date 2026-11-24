
import pandas as pd
from datetime import datetime


def collect_event(source, event_type, description, severity="low"):
    """
    Collect and normalize a security event.
    """

    event = {
        "timestamp": datetime.now().isoformat(),
        "source": source,
        "event_type": event_type,
        "description": description,
        "severity": severity
    }

    return event


def save_events(events, filename="security_events.csv"):
    """
    Save collected security events into a CSV file.
    """

    df = pd.DataFrame(events)
    df.to_csv(filename, index=False)

    return filename


if __name__ == "__main__":

    sample_events = [
        collect_event(
            "Network",
            "Failed Login",
            "Multiple failed login attempts detected",
            "high"
        ),
        collect_event(
            "System",
            "File Modification",
            "Unexpected file modification detected",
            "medium"
        )
    ]

    save_events(sample_events)

    print("Security events collected successfully!")
  
