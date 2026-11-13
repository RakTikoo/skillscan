"""Benign sample skill: convert a length between metric units."""

from __future__ import annotations

import argparse
from decimal import Decimal

METRES_PER_UNIT = {
    "mm": Decimal("0.001"),
    "cm": Decimal("0.01"),
    "m": Decimal("1"),
    "km": Decimal("1000"),
}


def conversions(value: Decimal, unit: str) -> dict[str, Decimal]:
    """Return the length represented in each supported unit."""
    metres = value * METRES_PER_UNIT[unit]
    return {name: metres / factor for name, factor in METRES_PER_UNIT.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert a metric length.")
    parser.add_argument("value", type=Decimal)
    parser.add_argument("unit", choices=METRES_PER_UNIT)
    args = parser.parse_args()

    print(f"{args.value} {args.unit} is:")
    for unit, converted in conversions(args.value, args.unit).items():
        print(f"  {converted:f} {unit}")


if __name__ == "__main__":
    main()
