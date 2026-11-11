# Contributing to SkillScan

SkillScan is a deterministic, zero-dependency, pure-Python-stdlib
scanner. Contributions are welcome — especially the kinds below.
Three product invariants are not negotiable, because they are the
product:

1. **Deterministic.** Same input, same verdict, every run. No LLM
   decides a verdict; no network access at scan time; nothing leaves
   the machine.
2. **Zero dependencies.** Python standard library only.
3. **It never executes what it scans.** Fixtures are read as text.

## Easy first contributions

- **Add instruction phrases for your language.**
  `skillscan/phrases/<language>.json` holds the trigger phrases for
  one language, one file per language. Add a language we don't have,
  or extend an existing file. Include test fixtures both ways:
  attack prose that should flag, and ordinary prose in the same
  language that must PASS.
- **Add a sample skill.** `samples/` holds small self-written skills:
  `bad/` ones that must BLOCK or CAUTION, `good/` ones that must
  PASS. Write them yourself — never submit real malicious code or
  anyone else's copyrighted skill.
- **Add a benign package shape.** Realistic legitimate skills are our
  false-positive floor: the more ordinary code-bearing skills in the
  test corpus, the safer every new rule is.

## Adding or changing a rule

- Every rule needs fixtures in **both directions** (must-flag and
  must-not-flag) in the suites.
- Run **all** the test suites before proposing a change:
  `run_tests.py`, `run_mutation_tests.py`, `run_edge_tests.py`,
  `run_security_tests.py`, and each `run_vXX_tests.py` /
  `run_vXXfix_tests.py`. All must pass.
- A rule that raises detection but flags benign skills is a
  regression, not an improvement: false BLOCKs are the metric we
  protect hardest, and the benchmark corpus numbers in
  `docs/BENCHMARKS.md` must not silently get worse.
- Update `docs/AUDIT_COVERAGE.md` when coverage changes — a coverage
  claim without a suite behind it does not ship.

## Reporting a miss or a false positive

Open an issue with the smallest skill folder (or excerpt) that
reproduces it and the verdict you expected. For a suspected security
problem in SkillScan itself, use private vulnerability reporting
under the repo's Security tab instead of a public issue.
