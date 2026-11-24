
import sys
from pathlib import Path

from main import main


def run():

    print("\n====================================")
    print("          TRAPTRACE-AI")
    print("   Cybersecurity Detection Platform")
    print("====================================")

    print("\nInitializing application...")

    project_directory = Path(__file__).resolve().parent

    print(f"Project Directory: {project_directory}")

    try:
        main()

    except KeyboardInterrupt:
        print("\nApplication stopped by user.")

    except Exception as error:
        print(f"\nApplication Error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    run()
  
