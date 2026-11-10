# SkillScan in your toolchain

SkillScan's exit codes (0 PASS, 1 CAUTION, 2 BLOCK, 3 scanner error) are
the integration surface. Three ready-made ways to use them:

## 1. GitHub Action

The composite action at the repo root (`action.yml`) runs SkillScan in
CI — e.g. on a pull request that adds a skill, or a scheduled scan of
vendored agent tooling.

```yaml
jobs:
  skillscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: RakTikoo/skillscan@v0.2.0
        with:
          path: ./skills/my-skill        # folder to scan
          fail-on-block: "true"          # default: BLOCK fails the job
          # format: sarif                # text | json | md | sarif
```

Inputs: `path` (required), `fail-on-block` (default `"true"` — CAUTION
warns but never fails), `format` (default `text`), `python-version`
(default `3.12`). Outputs: `verdict` and `exit-code`, so later steps can
branch on the result. A scanner error (exit 3) always fails the job:
"could not scan" must never look like "passed".

## 2. SARIF output

`--format sarif` emits SARIF 2.1.0 JSON: every rule becomes a SARIF
rule descriptor (id, plain-English description, default level —
`error` for block-severity rules, `warning` for caution) and every
finding becomes a result with the rule id, message, file and line.

```bash
python3 -m skillscan ./some-skill --format sarif > skillscan.sarif
```

That file can be uploaded to GitHub code scanning
(`github/codeql-action/upload-sarif`), opened in VS Code with the SARIF
Viewer extension, or consumed by any SARIF-aware dashboard — findings
then appear next to your other static-analysis results instead of in a
separate report.

## 3. Pre-install hook

`hooks/pre-install-scan.sh` wraps the scanner for install-time use:

```bash
./hooks/pre-install-scan.sh ./downloaded-skill   # prints the report
echo $?                                          # 0/1/2/3 as above
./hooks/pre-install-scan.sh ./downloaded-skill && cp -r ./downloaded-skill ~/.skills/
```

It takes one folder path, runs the scanner from this repo (override the
scanner location with `SKILLSCAN_HOME`), prints the full report plus a
one-line plain-English outcome, and exits with the scanner's exit code
— so `&&` chains, installer scripts and CI steps can gate on it
directly. Treat exit 3 ("the scan could not run") as a refusal, not a
pass.

## Scanning a GitHub repo directly

No clone step needed — pass the URL:

```bash
python3 -m skillscan https://github.com/some-owner/some-skill
```

Only `https://github.com/<owner>/<repo>` URLs are accepted (anything
else is a usage error, exit 3). SkillScan shallow-clones the repo into
a temporary directory with redirect-following disabled, scans it, and
deletes the clone. Requires `git` on `PATH`.
