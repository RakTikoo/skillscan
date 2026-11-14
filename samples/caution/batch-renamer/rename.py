"""Caution sample skill: a batch file renamer that renames files by calling
the system rename command via subprocess, then deletes the originally-named
copies.

Expected scanner verdict: CAUTION (SHELL_SUBPROCESS + FILE_DELETE),
not BLOCK — it uses no credential access, no network, no dynamic code.
"""

import os
import subprocess
from pathlib import Path


def rename_file(old_path: Path, new_path: Path) -> None:
    subprocess.run(["ren", str(old_path), str(new_path)], check=True)
    os.remove(old_path)


def main() -> None:
    work_dir = Path(__file__).parent / "work"
    for item in sorted(work_dir.glob("*.txt")):
        new_name = item.stem + "_renamed" + item.suffix
        rename_file(item, item.with_name(new_name))


if __name__ == "__main__":
    main()
