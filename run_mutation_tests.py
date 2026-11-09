#!/usr/bin/env python3
"""Run SkillScan against the evasion/mutation corpus in samples-mutations/.

Every mutation is a simulated malicious skill (SSH-key stealer / dropper /
unrestricted MCP manifest) rewritten with one evasion technique: string
concatenation, pathlib joins, importlib/getattr indirection, alias imports,
JS fetch, shell variables, UTF-16 encoding, unscanned extensions, and more.
Every one is expected to be BLOCK (exit 2).

These samples are only ever SCANNED (read as text). They are never executed,
imported, or installed. All endpoints are example.invalid; all credential
paths are fake.

Usage: python3 run_mutation_tests.py
Exit code: 0 if every mutation is BLOCK, 1 otherwise.
"""

import base64
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent
CORPUS = ROOT / "samples-mutations"


def materialise(folder: Path, tmp_root: Path) -> Path:
    """Return the folder to scan. Fixtures stored as <name>.b64 (used for
    the UTF-16 sample, whose raw bytes are not UTF-8) are decoded into a
    temporary copy first; the stored corpus itself is never modified."""
    if not any(folder.glob("*.b64")):
        return folder
    dest = tmp_root / folder.name
    dest.mkdir(parents=True)
    for item in folder.iterdir():
        if item.suffix == ".b64":
            (dest / item.stem).write_bytes(base64.b64decode(item.read_text()))
        elif item.is_file():
            shutil.copy2(item, dest / item.name)
    return dest


def main() -> int:
    folders = sorted(p for p in CORPUS.iterdir() if p.is_dir())
    if not folders:
        print(f"No mutation samples found in {CORPUS}")
        return 1
    failures = 0
    tmp = tempfile.TemporaryDirectory()
    for folder in folders:
        scan_target = materialise(folder, Path(tmp.name))
        proc = subprocess.run(
            [sys.executable, "-m", "skillscan", str(scan_target), "--format", "json"],
            cwd=ROOT, capture_output=True, text=True,
        )
        try:
            report = json.loads(proc.stdout)
            verdict = report["verdict"]
        except (json.JSONDecodeError, KeyError) as exc:
            print(f"FAIL {folder.name}: could not parse scanner output ({exc})")
            failures += 1
            continue
        if verdict != "BLOCK" or proc.returncode != 2:
            print(f"FAIL {folder.name}: verdict={verdict} exit={proc.returncode} "
                  f"(expected BLOCK/2) — EVADED")
            failures += 1
        else:
            rules = sorted({f["rule"] for f in report["findings"]})
            print(f"PASS {folder.name}: BLOCK exit=2 rules={','.join(rules)}")
    if failures:
        print(f"\n{failures} mutation(s) EVADED")
        return 1
    print(f"\nAll {len(folders)} mutations caught (BLOCK).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
