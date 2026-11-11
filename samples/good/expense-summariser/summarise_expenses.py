"""Benign sample skill: total the expenses in its own expenses.csv."""

import csv
from pathlib import Path


def totals(path: Path) -> dict:
    sums = {}
    with path.open(newline="") as handle:
        for row in csv.DictReader(handle):
            category = row["category"].strip()
            sums[category] = sums.get(category, 0.0) + float(row["amount"])
    return sums


def main() -> None:
    csv_path = Path(__file__).parent / "expenses.csv"
    sums = totals(csv_path)
    for category in sorted(sums):
        print(f"{category}: {sums[category]:.2f}")
    print(f"Total: {sum(sums.values()):.2f}")


if __name__ == "__main__":
    main()
