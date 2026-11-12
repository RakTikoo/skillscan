"""Benign sample skill: organise files in its own folder by extension.

Reads the files next to this script, groups them by file extension, and
prints a short report of how many files of each type were found. It never
writes, deletes, or moves anything outside its own folder, and it makes
no network calls.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path


def organise(folder: Path) -> dict[str, int]:
    """Return a mapping of file extension to file count for ``folder``."""
    counts: Counter[str] = Counter()
    for entry in sorted(folder.iterdir()):
        if entry.is_file():
            ext = entry.suffix.lower() or "(no extension)"
            counts[ext] += 1
    return dict(counts)


def main() -> None:
    here = Path(__file__).resolve().parent
    counts = organise(here)
    if not counts:
        print("No files found.")
        return
    print("Files by extension:")
    for ext in sorted(counts):
        print(f"  {ext}: {counts[ext]}")


if __name__ == "__main__":
    main()
