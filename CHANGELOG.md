# Changelog

All notable changes to SkillScan, newest first. Versions follow the
scanner's own `__version__`; every release below passed the full test
suites and an adversarial review before it was pushed.

## v0.6.0 — 2026-11-11

59 rules (was 57). The agent-config poisoning wave, built from two
2026 real-world reports of skills rewriting the user's global
agent configuration and reading agent credential stores:

- AGENT_CONFIG_WRITE: code that writes, appends, copies or
  registers into a GLOBAL agent configuration location
  (~/.claude/CLAUDE.md and settings/hooks, ~/.codex config,
  desktop MCP configs, `claude mcp add`, global editor/agent
  rules) BLOCKs. A home anchor is required — a skill's own
  project-local .claude/.codex/.mcp files never count, reading a
  global config is not flagged, and documentation telling the
  user to make the change themselves is CAUTION, not BLOCK.
- AGENT_CREDENTIAL_READ: reads of AI-agent credential stores
  (~/.claude/.credentials.json, ~/.codex/auth.json, Gemini and
  OpenCode auth files) BLOCK at the SSH-key tier and count as
  credential material for EXFIL_COMBINATION and value tracking,
  including paths assembled through variables, starred
  path-parts lists, and collections of pre-joined paths.
- Regression suite run_v06_tests.py plus a 24-fixture
  both-direction set built before the rules; the benign review
  corpora show zero new-rule fires.
- Fix pass after three adversarial reviews (regression suite
  run_v06fix_tests.py): quadratic matcher blowups removed
  (500 KB anchor-dense file: did-not-finish → ~3 s); credential
  reads require a real read (exists/stat probes and bare path
  references no longer count); config writes are
  direction-aware (backups out of a config are not writes) and
  demote to CAUTION when structurally gated by a user
  confirmation, an opt-in flag, or a delete-only edit; stale
  variable bindings die on reassignment; evasion coverage
  widened (more languages, anchors, path normalisation, quoted
  shell commands, folded path assembly, sibling-module
  constants; red-team target-rule fires 4/50 → 42/50, the rest
  accepted by design and listed in docs/AUDIT_COVERAGE.md).
- Fix wave 2 after a second round of all three reviews
  (regression suite run_v06fix2_tests.py): mediation signals
  count only in real code (comments/strings blanked), helper
  primitives must be called, shell prompts must actually guard
  the write, delete-only is disqualified by any key-addition
  shape (.update({...}), dict merges), and flag gates are
  shape-based with polarity and anti-tautology checks (an
  opt-out --dry-run guard no longer demotes); mediation is
  folder-aware (a prompt in the invoking file counts, an
  unreferenced neighbour's does not); primitives widened (JS
  prompts package, GUI confirm dialogs, Ruby gets); `..`/`.`
  resolved textually (skills-store exclusion bypass closed);
  default-argument paths tracked; write verbs added (dd of=,
  tar -C, unzip -d — a 2>/dev/null redirect no longer hides
  them); credential reads added for batch type/more,
  fs.createReadStream, and one-level helper argument flow;
  tilde-user config writes fire at CAUTION; two new quadratic
  patterns closed (per-function regex fan-out, per-write
  demotion rebuilds) plus a stale-token correctness bug fixed
  in both directions; the timing suite now pins four bomb
  shapes, each < 5 s. Environment-variable and config-file
  opt-ins are documented as NOT mediation signals (no
  guaranteed human in the loop).
- Measured on MaliciousSkillBench (see docs/BENCHMARKS.md):
  malicious BLOCK 45.8% (3,399), BLOCK+CAUTION
  82.4% (no verdict weaker than the fix pass anywhere);
  benign false BLOCKs 0, new-rule fires on 5 of 2,235
  benign folders, all at CAUTION.

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
