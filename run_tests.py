#!/usr/bin/env python3
"""Run SkillScan against every sample in samples/ and assert the
expected verdict and exit code for each one.

Samples are only ever SCANNED (read as text). They are never executed,
imported, or installed.

Usage: python3 run_tests.py
Exit code: 0 if every sample matches its expectation, 1 otherwise.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent

# sample path -> (expected verdict, expected exit code)
EXPECTED = {
    "samples/good/calendar-helper": ("PASS", 0),
    "samples/good/file-organiser": ("PASS", 0),
    "samples/good/notes-summariser": ("PASS", 0),
    "samples/bad/ssh-stealer": ("BLOCK", 2),
    "samples/bad/obfuscated-dropper": ("BLOCK", 2),
    # Legit-sounding backup skill: runs subprocess + deletes old files.
    # No block-severity rule fires, so the documented expectation is CAUTION.
    "samples/caution/shell-automation": ("CAUTION", 1),
}

# Rules that must fire for a sample (checked on top of the verdict).
MUST_FIRE = {
    "samples/bad/ssh-stealer": {"SSH_CREDENTIAL_READ", "NETWORK_SEND_DATA"},
    "samples/bad/obfuscated-dropper": {"EVAL_EXEC", "DECODE_AND_RUN", "CURL_PIPE_BASH"},
    "samples/caution/shell-automation": {"SHELL_SUBPROCESS", "FILE_DELETE"},
}


def main() -> int:
    failures = 0
    for rel, (want_verdict, want_code) in EXPECTED.items():
        sample = ROOT / rel
        proc = subprocess.run(
            [sys.executable, "-m", "skillscan", str(sample), "--format", "json"],
            cwd=ROOT, capture_output=True, text=True,
        )
        try:
            report = json.loads(proc.stdout)
            got_verdict = report["verdict"]
            fired = {f["rule"] for f in report["findings"]}
        except (json.JSONDecodeError, KeyError) as exc:
            print(f"FAIL {rel}: could not parse scanner output ({exc})")
            print(proc.stdout)
            print(proc.stderr, file=sys.stderr)
            failures += 1
            continue

        problems = []
        if got_verdict != want_verdict:
            problems.append(f"verdict {got_verdict} != {want_verdict}")
        if proc.returncode != want_code:
            problems.append(f"exit code {proc.returncode} != {want_code}")
        missing = MUST_FIRE.get(rel, set()) - fired
        if missing:
            problems.append(f"rules did not fire: {sorted(missing)}")

        if problems:
            print(f"FAIL {rel}: " + "; ".join(problems))
            failures += 1
        else:
            print(f"PASS {rel}: verdict={got_verdict} exit={proc.returncode} "
                  f"findings={len(report['findings'])}")

    if failures:
        print(f"\n{failures} sample(s) FAILED")
        return 1
    print(f"\nAll {len(EXPECTED)} samples passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
