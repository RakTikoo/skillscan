"""Benign sample skill: summarise today's events from a local text file."""

from pathlib import Path


def main() -> None:
    events_file = Path(__file__).parent / "events.txt"
    if not events_file.exists():
        print("No events file found.")
        return
    lines = [line.strip() for line in events_file.read_text().splitlines() if line.strip()]
    print(f"You have {len(lines)} event(s) today:")
    for line in sorted(lines):
        print(f"  - {line}")


if __name__ == "__main__":
    main()
