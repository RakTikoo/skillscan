"""Benign sample skill: scale a simple recipe by a given factor."""

from __future__ import annotations

import argparse
from decimal import Decimal

# A small embedded recipe (amounts in grams or counts)
RECIPE = {
    "flour": Decimal("250"),
    "sugar": Decimal("100"),
    "butter": Decimal("120"),
    "eggs": Decimal("2"),
    "milk": Decimal("150"),
}


def scale(factor: Decimal) -> dict[str, Decimal]:
    """Return the recipe with each quantity multiplied by the factor."""
    return {name: amount * factor for name, amount in RECIPE.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description="Scale a simple recipe.")
    parser.add_argument("factor", type=Decimal, help="Multiplier for all quantities")
    args = parser.parse_args()

    print(f"Recipe scaled by {args.factor}:")
    for name, amount in scale(args.factor).items():
        print(f"  {name}: {amount}")


if __name__ == "__main__":
    main()
