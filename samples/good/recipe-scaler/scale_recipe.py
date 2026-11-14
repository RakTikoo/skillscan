"""Benign sample skill: scale a local recipe to a different serving count."""

import sys
from pathlib import Path


def parse_recipe(text: str) -> tuple[int, list[tuple[float, str, str]]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    base_servings = int(lines[0])
    items: list[tuple[float, str, str]] = []
    for line in lines[1:]:
        quantity, unit, name = line.split(maxsplit=2)
        items.append((float(quantity), unit, name))
    return base_servings, items


def format_quantity(value: float) -> str:
    return f"{value:g}"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: python scale_recipe.py <servings>")
        return 1
    try:
        target = int(argv[1])
    except ValueError:
        print("Servings must be a whole number.")
        return 1
    if target < 1:
        print("Servings must be at least 1.")
        return 1

    recipe_file = Path(__file__).parent / "recipe.txt"
    if not recipe_file.exists():
        print("No recipe file found.")
        return 1

    base_servings, items = parse_recipe(recipe_file.read_text(encoding="utf-8"))
    factor = target / base_servings
    print(f"Recipe scaled to {target} serving(s) (base {base_servings}):")
    for quantity, unit, name in items:
        scaled = format_quantity(round(quantity * factor, 2))
        print(f"  {scaled} {unit} {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
