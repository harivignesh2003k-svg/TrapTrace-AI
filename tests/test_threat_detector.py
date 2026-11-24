
import pandas as pd

from src.threat_detector import detect_threats


def test_detect_repeated_failed_logins(tmp_path):

    events = pd.DataFrame([
        {
            "source": "Network",
            "event_type": "Failed Login",
            "description": "Login failure",
            "severity": "high"
        }
        for _ in range(3)
    ])

    filename = tmp_path / "events.csv"
    events.to_csv(filename, index=False)

    result = detect_threats(str(filename))

    assert not result.empty
    assert (
        result.iloc[0]["threat"]
        == "Repeated Failed Login Attempts"
    )


def test_detect_critical_events(tmp_path):

    events = pd.DataFrame([
        {
            "source": "System",
            "event_type": "File Modification",
            "description": "Critical file modification",
            "severity": "critical"
        }
    ])

    filename = tmp_path / "events.csv"
    events.to_csv(filename, index=False)

    result = detect_threats(str(filename))

    assert "Critical Security Event" in result["threat"].values


def test_no_threats_detected(tmp_path):

    events = pd.DataFrame([
        {
            "source": "System",
            "event_type": "File Modification",
            "description": "Normal activity",
            "severity": "low"
        }
    ])

    filename = tmp_path / "events.csv"
    events.to_csv(filename, index=False)

    result = detect_threats(str(filename))

    assert result.empty
  
