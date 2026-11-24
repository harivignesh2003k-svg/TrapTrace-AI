
import pandas as pd

from src.event_collector import collect_event, save_events


def test_collect_event():
    event = collect_event(
        "Network",
        "Failed Login",
        "Multiple failed login attempts",
        "high"
    )

    assert event["source"] == "Network"
    assert event["event_type"] == "Failed Login"
    assert event["severity"] == "high"
    assert "timestamp" in event


def test_default_severity():
    event = collect_event(
        "System",
        "File Modification",
        "Unexpected file modification"
    )

    assert event["severity"] == "low"


def test_save_events(tmp_path):
    events = [
        collect_event(
            "Network",
            "Failed Login",
            "Login failure",
            "high"
        )
    ]

    filename = tmp_path / "test_events.csv"

    save_events(events, str(filename))

    df = pd.read_csv(filename)

    assert len(df) == 1
    assert df.iloc[0]["source"] == "Network"
  
