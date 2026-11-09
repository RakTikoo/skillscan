"""Caution sample skill: a backup helper that runs the system copy
command via subprocess and deletes the working copies afterwards.

Expected scanner verdict: CAUTION (SHELL_SUBPROCESS + FILE_DELETE),
not BLOCK — it uses no credential access, no network, no dynamic code.
"""

import os
import subprocess
from pathlib import Path


def back_up(source: Path, dest: Path) -> None:
    subprocess.run(["cp", str(source), str(dest)], check=True)
    os.remove(source)


def main() -> None:
    work_dir = Path(__file__).parent / "work"
    backup_dir = Path(__file__).parent / "backup"
    backup_dir.mkdir(exist_ok=True)
    for item in sorted(work_dir.glob("*.txt")):
        back_up(item, backup_dir / item.name)


if __name__ == "__main__":
    main()
