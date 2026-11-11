# Changelog

All notable changes to SkillScan, newest first. Versions follow the
scanner's own `__version__`; every release below passed the full test
suites and an adversarial review before it was pushed.

## v0.5.0 — 2026-11-10

57 rules (was 47). The standalone-coverage wave:

- Prose attack chains: fetch-then-execute, pipe instructions,
  read-then-send, English instruction manipulation, and a
  safety-bypass + lure combination that BLOCKs.
- OUTPUT_MANIPULATION family (CAUTION-only) for suppression and
  steering phrasing, calibrated against benign prose.
- Value tracking (taint-lite): credential data flowing into a network
  send BLOCKs, with scope-aware, flow-sensitive tracking.
- Offline typosquat check against shipped PyPI/npm top lists
  (CAUTION-only), validated at zero flags across 1,300+ legitimate
  package names.
- Fix pass after a three-reviewer adversarial review: lure
  proximity/framing, taint phantom-flow elimination, guard-laundering
  closures, typosquat extraction and speed.
- Measured on MaliciousSkillBench (see docs/BENCHMARKS.md):
  malicious BLOCK 45.7%, BLOCK+CAUTION 82.4%; benign false BLOCKs 0.

## v0.4.0 — 2026-11-10

47 rules (was 41). The precision wave:

- Dependency-source and dependency-execution checks, JS
  download-and-run, install-prose analysis, prose download-run chains,
  folder-level read-and-disclose.
- Fix pass after adversarial review: a regex hang bug, inert-text
  precision (comments/strings no longer BLOCK), lifecycle scoping.
- The v0.3 false-BLOCK regression (15 benign skills) eliminated:
  false BLOCKs back to 0, flagged-at-all down to 22.3%.

## v0.3.0 — 2026-11-10

41 rules (was 34). The concealment wave:

- Hidden text (zero-width, Unicode tags, BiDi), non-English
  instruction phrases (14 language files), Markdown concealment,
  substitution-execution, environment injection (.pth), completed
  session-object sends, bytecode honesty, OWASP tags.

## v0.2.0 — 2026-11-10

34 rules (was 25). Live-secret detection, cloud-metadata endpoints,
browser credential stores, reverse shells, install-script analysis,
repo-URL scanning, SARIF output, the GitHub Action and the
pre-install hook.

## v0.1.0 — 2026-11-09

First public release: 25 deterministic rules over skill folders, MCP
manifests and package files; PASS / CAUTION / BLOCK verdicts with
exit codes 0/1/2/3; published audit coverage map.
