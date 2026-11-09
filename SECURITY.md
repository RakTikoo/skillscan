# Security policy

SkillScan's whole job is reading **untrusted** folders, so vulnerabilities
in SkillScan itself matter: a malicious skill folder that can crash,
hang, exhaust, or deceive the scanner defeats the tool's purpose.

## Reporting a vulnerability

Please report security issues **privately**, not as a public issue:

- Use GitHub's private vulnerability reporting for this repository:
  **Security → Report a vulnerability** on
  https://github.com/RakTikoo/skillscan
  (GitHub Security Advisories). This keeps the report visible only to the
  reporter and the maintainer until a fix is available.

Please include, as far as you can:

- the SkillScan version (`skillscan/__init__.py`) and your Python version,
- a minimal folder (or a description of its structure) that triggers the
  issue,
- what you expected to happen and what actually happened (hang, crash,
  resource exhaustion, verdict bypass, forged terminal output, …).

Do **not** include real credentials or anyone else's private data in a
report. Sample folders with fake credentials are enough — that is all the
project's own corpus ever uses.

## Supported versions

SkillScan is pre-1.0. Only the **latest release on the `main` branch** is
supported with security fixes; older checkouts should be updated rather
than patched.

## Scope notes

- Evasion samples (a malicious skill that scans PASS) are security-relevant
  and welcome through the same private channel — or as a public issue if
  you prefer, since the corpus is public anyway. A mutation that evades
  SkillScan is a valuable contribution either way.
- SkillScan is a static linter, not a guarantee of safety: a PASS verdict
  means no known-bad patterns were found in what was scanned. See
  `docs/AUDIT_COVERAGE.md` for the honest coverage map, including the
  technique classes SkillScan does not catch.
