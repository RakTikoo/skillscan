#!/usr/bin/env python3
"""Edge-case tests for SkillScan: the scanner must never hang, never
silently PASS on content it did not scan, and never confuse a usage
error with a BLOCK verdict.

Fixtures are built in a temporary directory. Nothing is executed except
the scanner itself.

Usage: python3 run_edge_tests.py
Exit code: 0 if every case matches, 1 otherwise.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent


def scan(target: Path, *extra: str, timeout: int = 15):
    proc = subprocess.run(
        [sys.executable, "-m", "skillscan", str(target), "--format", "json", *extra],
        cwd=ROOT, capture_output=True, text=True, timeout=timeout,
    )
    try:
        return proc, json.loads(proc.stdout)
    except json.JSONDecodeError:
        return proc, None


def main() -> int:
    failures = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f": {detail}" if detail else ""))
        if not ok:
            failures += 1

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)

        # 1. FIFO must not hang and must not PASS.
        fifo_dir = base / "fifo"
        fifo_dir.mkdir()
        os.mkfifo(fifo_dir / "pipe.txt")
        (fifo_dir / "a.txt").write_text("hello\n")
        try:
            proc, report = scan(fifo_dir, timeout=10)
            check("fifo-no-hang", report is not None and report["verdict"] == "CAUTION",
                  f"verdict={report and report['verdict']}")
        except subprocess.TimeoutExpired:
            check("fifo-no-hang", False, "scanner hung >10s on a FIFO")

        # 2. Empty folder: nothing scanned -> CAUTION (SCAN_INCOMPLETE), not PASS.
        empty = base / "empty"
        empty.mkdir()
        proc, report = scan(empty)
        check("empty-not-pass", report is not None and report["verdict"] == "CAUTION"
              and report["scanned_files"] == 0,
              f"verdict={report and report['verdict']}")

        # 3. Oversize file with a payload: skipped + CAUTION, never silent PASS.
        big_dir = base / "big"
        big_dir.mkdir()
        (big_dir / "big.py").write_text("\n".join(
            ["# filler comment line"] * 120000 + ["import os", 'os.system("id")']))
        proc, report = scan(big_dir)
        check("oversize-not-silent", report is not None and report["verdict"] == "CAUTION"
              and len(report["skipped_files"]) == 1,
              f"verdict={report and report['verdict']}")

        # 4. Usage errors exit 3 — distinct from BLOCK (2).
        proc, _ = scan(base / "does-not-exist")
        check("nonexistent-exit-3", proc.returncode == 3, f"exit={proc.returncode}")
        proc, _ = scan(big_dir / "big.py")
        check("single-file-exit-3", proc.returncode == 3, f"exit={proc.returncode}")

        # 5. A .py file with a syntax error still gets line-rule findings.
        syn = base / "syn"
        syn.mkdir()
        (syn / "bad.py").write_text('def broken(:\nimport os\nos.system("id")\n')
        proc, report = scan(syn)
        check("syntax-error-graceful", report is not None and report["verdict"] == "BLOCK",
              f"verdict={report and report['verdict']}")

        # 6. UTF-16 encoded stealer is decoded and BLOCKed (not binary-skipped).
        utf = base / "utf16"
        utf.mkdir()
        (utf / "steal.py").write_bytes(
            'key = open("/home/user/.ssh/id_rsa").read()\n'.encode("utf-16"))
        proc, report = scan(utf)
        check("utf16-scanned", report is not None and report["verdict"] == "BLOCK",
              f"verdict={report and report['verdict']}")

    if failures:
        print(f"\n{failures} edge case(s) FAILED")
        return 1
    print("\nAll edge cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
