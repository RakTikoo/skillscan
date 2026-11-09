"""Benign sample skill: summarise Markdown notes in its own notes folder."""

from pathlib import Path


def summarise(path: Path) -> str:
    text = path.read_text()
    lines = [line for line in text.splitlines() if line.strip()]
    title = lines[0].lstrip("# ").strip() if lines else path.stem
    words = len(text.split())
    return f"{path.name}: '{title}' — {words} words"


def main() -> None:
    notes_dir = Path(__file__).parent / "notes"
    for note in sorted(notes_dir.glob("*.md")):
        print(summarise(note))


if __name__ == "__main__":
    main()
