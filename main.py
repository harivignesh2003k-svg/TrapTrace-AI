
from src.event_collector import collect_event, save_events
from src.event_analyzer import analyze_events
from src.threat_detector import detect_threats
from src.correlation_engine import correlate_events
from src.report_generator import generate_report


def main():

    print("\n====================================")
    print("       WELCOME TO TRAPTRACE-AI")
    print(" AI-POWERED CYBERSECURITY SYSTEM")
    print("====================================")

    # Step 1: Collect security events
    print("\n[1] Collecting Security Events...")

    events = [
        collect_event(
            "Network",
            "Failed Login",
            "Multiple failed login attempts",
            "high"
        ),
        collect_event(
            "Network",
            "Failed Login",
            "Repeated login failure",
            "high"
        ),
        collect_event(
            "Network",
            "Failed Login",
            "Suspicious login activity",
            "critical"
        ),
        collect_event(
            "System",
            "File Modification",
            "Unexpected file modification",
            "medium"
        ),
        collect_event(
            "Application",
            "Unauthorized Access",
            "Unauthorized access detected",
            "critical"
        )
    ]

    save_events(events)

    print("Security events collected successfully.")

    # Step 2: Analyze events
    print("\n[2] Analyzing Security Events...")

    analyze_events()

    # Step 3: Detect threats
    print("\n[3] Detecting Cyber Threats...")

    detect_threats()

    # Step 4: Correlate events
    print("\n[4] Correlating Security Events...")

    correlate_events()

    # Step 5: Generate report
    print("\n[5] Generating Threat Report...")

    generate_report()

    print("\n====================================")
    print("       ANALYSIS COMPLETED")
    print("====================================")
    print("Generated Files:")
    print("- security_events.csv")
    print("- threat_report.txt")


if __name__ == "__main__":
    main()
