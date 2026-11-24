
import pandas as pd

from src.event_collector import collect_event, save_events
from src.event_analyzer import analyze_events
from src.threat_detector import detect_threats
from src.correlation_engine import correlate_events
from src.report_generator import generate_report


def test_complete_security_pipeline(tmp_path):

    # Step 1: Collect sample security events
    events = [
        collect_event(
            "Network",
            "Failed Login",
            "Repeated login attempt",
            "high"
        ),
        collect_event(
            "Network",
            "Failed Login",
            "Suspicious login attempt",
            "critical"
        ),
        collect_event(
            "Network",
            "Failed Login",
            "Multiple login failures",
            "high"
        ),
        collect_event(
            "System",
            "File Modification",
            "Normal file update",
            "low"
        )
    ]

    # Step 2: Save events
    events_file = tmp_path / "events.csv"
    save_events(events, str(events_file))

    assert events_file.exists()

    # Step 3: Analyze events
    analyzed = analyze_events(str(events_file))

    assert len(analyzed) == 3

    # Step 4: Detect threats
    threats = detect_threats(str(events_file))

    assert not threats.empty

    # Step 5: Correlate events
    correlation = correlate_events(str(events_file))

    network = correlation[
        correlation["source"] == "Network"
    ]

    assert network.iloc[0]["high_risk_events"] == 3

    # Step 6: Generate report
    report_file = tmp_path / "report.txt"

    result = generate_report(
        str(events_file),
        str(report_file)
    )

    assert result is not None
    assert report_file.exists()

    report = report_file.read_text()

    assert "TrapTrace-AI REPORT" in report
    assert "Total Events: 4" in report
  
