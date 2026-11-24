
import pandas as pd

from src.event_analyzer import analyze_events


def test_identify_high_risk_events(tmp_path):

    events = pd.DataFrame([
        {
            "source": "Network",
            "event_type": "Failed Login",
            "description": "Repeated login failures",
            "severity": "high"
        },
        {
            "source": "System",
            "event_type": "File Modification",
            "description": "Normal file update",
            "severity": "low"
        },
        {
            "source": "Application",
            "event_type": "Unauthorized Access",
            "description": "Unauthorized access detected",
            "severity": "critical"
        }
    ])

    filename = tmp_path / "events.csv"
    events.to_csv(filename, index=False)

    result = analyze_events(str(filename))

    assert len(result) == 2
    assert set(result["severity"]) == {"high", "critical"}


def test_no_high_risk_events(tmp_path):

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

    result = analyze_events(str(filename))

    assert result.empty


def test_missing_event_file(tmp_path):

    filename = tmp_path / "missing.csv"

    result = analyze_events(str(filename))

    assert result is None
  
