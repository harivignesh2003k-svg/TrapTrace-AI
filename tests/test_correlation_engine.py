
import pandas as pd

from src.correlation_engine import correlate_events


def test_identify_suspicious_sources(tmp_path):

    events = pd.DataFrame([
        {
            "source": "Network",
            "event_type": "Failed Login",
            "severity": "high"
        },
        {
            "source": "Network",
            "event_type": "Unauthorized Access",
            "severity": "critical"
        },
        {
            "source": "System",
            "event_type": "File Modification",
            "severity": "low"
        }
    ])

    filename = tmp_path / "events.csv"
    events.to_csv(filename, index=False)

    result = correlate_events(str(filename))

    assert not result.empty

    network = result[result["source"] == "Network"]

    assert network.iloc[0]["high_risk_events"] == 2


def test_no_suspicious_sources(tmp_path):

    events = pd.DataFrame([
        {
            "source": "System",
            "event_type": "File Modification",
            "severity": "low"
        },
        {
            "source": "Application",
            "event_type": "Normal Activity",
            "severity": "medium"
        }
    ])

    filename = tmp_path / "events.csv"
    events.to_csv(filename, index=False)

    result = correlate_events(str(filename))

    suspicious = result[
        result["high_risk_events"] >= 2
    ]

    assert suspicious.empty


def test_empty_event_file(tmp_path):

    events = pd.DataFrame(
        columns=["source", "event_type", "severity"]
    )

    filename = tmp_path / "events.csv"
    events.to_csv(filename, index=False)

    result = correlate_events(str(filename))

    assert result.empty
  
