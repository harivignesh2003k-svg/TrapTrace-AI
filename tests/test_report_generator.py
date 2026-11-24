
import pandas as pd

from src.report_generator import generate_report


def test_generate_threat_report(tmp_path):

    events = pd.DataFrame([
        {
            "timestamp": "2026-11-24T10:00:00",
            "source": "Network",
            "event_type": "Failed Login",
            "description": "Multiple failed login attempts",
            "severity": "high"
        },
        {
            "timestamp": "2026-11-24T10:05:00",
            "source": "System",
            "event_type": "File Modification",
            "description": "Normal file update",
            "severity": "low"
        }
    ])

    events_file = tmp_path / "events.csv"
    report_file = tmp_path / "report.txt"

    events.to_csv(events_file, index=False)

    result = generate_report(
        str(events_file),
        str(report_file)
    )

    assert result is not None
    assert report_file.exists()

    content = report_file.read_text(encoding="utf-8")

    assert "TrapTrace-AI REPORT" in content
    assert "Total Events: 2" in content
    assert "high" in content


def test_missing_event_file(tmp_path):

    events_file = tmp_path / "missing.csv"
    report_file = tmp_path / "report.txt"

    result = generate_report(
        str(events_file),
        str(report_file)
    )

    assert result is None
    assert not report_file.exists()
  
