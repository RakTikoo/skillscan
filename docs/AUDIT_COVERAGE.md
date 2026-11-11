# Audit coverage map

How SkillScan v0.5's 57 deterministic rules line up against the techniques
documented in published audits of real malicious AI-agent skills and MCP
servers.

**Method, stated plainly:**

- The techniques below are summarised **in our own words** from the cited
  audits. No report text and no malicious code from any audit is reproduced
  here.
- "Evidence" means one thing only: an **existing** sample in `samples/` or
  `samples-mutations/`, or a fixture in `run_v02_tests.py` / `run_v03_tests.py`
  / `run_v04_tests.py` (those suites build inert fixtures in a temp dir), that an existing test
  suite already scans, with the verdict that suite asserts. No new sample
  was created for this map beyond what those suites contain.
- Where a rule plausibly addresses a technique but no existing sample
  exercises it that way, the evidence column says so —
  *"rule present, no dedicated sample yet"* — instead of implying a test
  exists.
- **Coverage** means: **Covered** = a rule (or rule combination) addresses
  the technique and an existing sample proves the rule fires in that shape;
  **Partial** = a rule addresses part of the shape, or catches it only in
  some forms (e.g. in code but not in prose, or only at CAUTION severity);
  **Gap** = no rule addresses the technique in the form the audit documents.

## Tally

| Audit | Techniques mapped | Covered | Partial | Gap |
|-------|-------------------|---------|---------|-----|
| Snyk — ToxicSkills (Feb 2026) | 11 | 3 | 5 | 3 |
| Koi Security — ClawHavoc (Feb 2026) | 7 | 1 | 4 | 2 |
| Invariant Labs — MCP Tool Poisoning (Apr 2025) | 4 | 0 | 2 | 2 |
| Koi Security — postmark-mcp (Sep 2025) | 3 | 0 | 2 | 1 |
| **Total** | **25** | **4** | **13** | **8** |

The pattern in that tally is honest and worth understanding: SkillScan is
strong on the *code-shaped* half of these audits (credential reads, network
exfiltration, decode-and-run droppers) and weak on the *language-shaped*
half (instructions in prose or tool descriptions that talk the agent into
doing the work). That weakness is structural — see the Gaps section.

---

## 1. Snyk — "ToxicSkills"

- **Publisher:** Snyk (security research team)
- **Date:** 5 February 2026 (skills snapshot of the same date; 3,984 skills
  from ClawHub and skills.sh; 534 with at least one critical issue, 76
  human-confirmed malicious payloads)
- **URL:** https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/

| # | Technique (our words) | Coverage | Rule(s) | Evidence from existing suites |
|---|------------------------|----------|---------|-------------------------------|
| S1 | Skill code reads credential stores (SSH keys, cloud credential files) and sends the contents to an outside server | **Covered** | SSH_CREDENTIAL_READ, CLOUD_CREDENTIAL_READ, NETWORK_SEND_DATA, EXFIL_COMBINATION | `samples/bad/ssh-stealer` — BLOCK, exit 2; `run_tests.py` asserts SSH_CREDENTIAL_READ and NETWORK_SEND_DATA fire (EXFIL_COMBINATION also fires). The same shape survives string-splitting, `chr()` codes, GET-parameter smuggling and UTF-16 encoding in `samples-mutations/01, 03, 11, 12, 14, 17` — all BLOCK in `run_mutation_tests.py` |
| S2 | Encoded (e.g. base64) payload is decoded and then executed, often ending in a download piped straight into a shell | **Covered** | BASE64_OBFUSCATION, DECODE_AND_RUN, EVAL_EXEC, CURL_PIPE_BASH | `samples/bad/obfuscated-dropper` — BLOCK, exit 2; `run_tests.py` asserts EVAL_EXEC, DECODE_AND_RUN and CURL_PIPE_BASH fire. Chunked-base64 variant: `samples-mutations/10-b64-chunks-importlib` — BLOCK (DECODE_AND_RUN, DYNAMIC_IMPORT) |
| S3 | The skill's *instructions* (SKILL.md prose) tell the agent/user to fetch and install untrusted software from an outside location, including archives a scanner cannot see inside | **Partial** | CURL_PIPE_BASH, INSTALL_FROM_URL, RUNTIME_PACKAGE_INSTALL, NETWORK_ACCESS (all line rules also run over documentation) | v0.4 gave this row its dedicated fixtures (`run_v04_tests.py`): an install instruction whose source is a URL, git source, archive file, or non-official index now fires the dedicated INSTALL_FROM_URL in prose — and, as the refinement's other side, prose that merely names a registry package no longer flags at all. Documentation findings are deliberately capped at CAUTION and negated safety prose is skipped (scanner design), so a prose-only install instruction can never produce a BLOCK from SkillScan. Still Partial for exactly that reason: the cap is a design stance, not a detection |
| S4 | Obfuscated exfiltration commands are embedded in installation instructions rather than in code files | **Partial** | BASE64_OBFUSCATION, DECODE_AND_RUN, SSH_CREDENTIAL_READ, CLOUD_CREDENTIAL_READ (line rules run over `.md` too) | Rule present, no dedicated sample yet — the corpus's obfuscated samples keep the payload in code (`samples/bad/obfuscated-dropper`, mutation 10). In prose, DECODE_AND_RUN's block severity is capped to CAUTION like every documentation finding |
| S5 | Instructions push the agent to weaken the machine: alter service/startup configuration so a backdoor persists, delete system files, loosen security settings | **Partial** | PERSISTENCE, RM_RF, FILE_DELETE, CHMOD_CHOWN | In *code* these fire at full severity — PERSISTENCE/RM_RF are exercised by the corpus's shell-shaped samples (e.g. `samples-mutations/06-shell-home-var`, BLOCK) and FILE_DELETE by `samples/caution/shell-automation` (CAUTION, asserted by `run_tests.py`). In *prose* the same words are capped at CAUTION; a dedicated persistence sample does not exist, so for PERSISTENCE specifically: rule present, no dedicated sample yet |
| S6 | Prompt-injection wording in skill text: hidden or deceptive instructions outside the skill's stated purpose, "ignore previous instructions"-style overrides, fake system-message framing, Unicode/base64-smuggled instructions | **Partial** | BASE64_OBFUSCATION; v0.3: HIDDEN_TEXT, MARKDOWN_CONCEALMENT, NON_ENGLISH_INSTRUCTION | The *mechanics* half is now covered with fixtures: `run_v03_tests.py` proves Unicode Tags-block smuggling in a manifest description BLOCKs (and CAUTIONs without keywords), zero-width / BiDi / HTML-comment concealment CAUTIONs, Markdown hiding places (display:none, white-on-white, `<details>`) CAUTION, and instruction-attack phrases in 10 languages CAUTION — with benign multilingual controls (emoji ZWJ, Persian/Indic joiners, a Spanish cooking README) all PASS. The *meaning* half remains a Gap inside this Partial: no rule judges whether visible, plainly-worded prose is deceptive — that is a semantic judgement a deterministic rule set does not make |
| S7 | Skills instruct the agent to print/echo secrets back, or ask the user to paste secrets into outputs or commands | **Gap** | — | No rule inspects instructions *about* credential handling in prose. ENVIRON_SECRET_ACCESS covers code touching the environment, not text asking a human or agent to reveal a secret |
| S8 | Hardcoded secrets and tokens embedded in the skill itself (leaked keys, or deliberately embedded tokens for attacker infrastructure) | **Covered** | HARDCODED_SECRET_LIVE, HARDCODED_SECRET_GENERIC | v0.2 added secret detection: live-format credentials (AWS key ids, GitHub and GitLab tokens, `sk-` keys, Stripe live keys, npm tokens, Slack tokens, private-key blocks) BLOCK; long high-entropy literals assigned to secret-named variables (including a bare KEY / TOKEN / SECRET / PASSWORD name) CAUTION, as are Stripe *test* keys. `run_v02_tests.py` fixtures assert both tiers fire, and that placeholders (`your-api-key`, `changeme`, `xxxx`), env-var references, low-entropy values, and clearly-marked documentation examples do **not**. Honest limits: the generic tier's effective minimum is ~12 characters (an entropy floor of 3.5 bits/char, despite an 8-character regex floor), so secrets that are short, low-entropy, split across strings, or encoded are not caught; live-format values in test files or marked FAKE_/FIXTURE are downgraded to CAUTION rather than BLOCK; and a random-looking test value can trip the CAUTION tier |
| S9 | Content the skill fetches at run time from third parties carries injected instructions back to the agent (indirect injection through fetched content) | **Gap** | — (NETWORK_ACCESS flags that fetching happens, at CAUTION) | The fetched content does not exist in the folder at scan time, so there is nothing static to inspect. Flagging "this skill fetches remote content" is the only signal, and it is also true of most honest skills |
| S10 | Run-time fetching and execution of remote code/instructions — the reviewed artefact is benign, the behaviour is swapped in later from an external endpoint (`curl \| bash`, dynamic imports, remote instruction loading) | **Partial** | CURL_PIPE_BASH, DYNAMIC_IMPORT, EVAL_EXEC, NETWORK_ACCESS | The `curl \| bash` form is Covered-grade: `samples/bad/obfuscated-dropper` asserts CURL_PIPE_BASH (BLOCK). Dynamic-import indirection is exercised by `samples-mutations/04-importlib-getattr` and `10-b64-chunks-importlib` (BLOCK). But a plain fetch of remote *instructions* (no pipe-to-shell, no eval) fires only NETWORK_ACCESS at CAUTION — that form is a Gap inside a Partial |
| S11 | Skills with direct access to money — trading, payments, crypto operations, bank accounts | **Gap** | — | SkillScan has no capability-classification rule for financial access, and by design a capability is not the same as malice (compare the CAUTION philosophy for subprocess/network). No rule and no sample |

## 2. Koi Security — ClawHavoc

- **Publisher:** Koi Security (researcher Oren Yomtov); campaign disclosed
  1 February 2026 (2,857 ClawHub skills audited, 341 malicious, 335 of them
  one campaign; a 16 February update raised Koi's count to 824 as the
  registry grew past 10,700)
- **URLs:** original report —
  https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting
  (the original page now redirects to the acquirer's site; the findings are
  preserved in the AI Incident Database summary —
  https://incidentdatabase.ai/reports/6951/ — which is the text this map
  was drawn from)

| # | Technique (our words) | Coverage | Rule(s) | Evidence from existing suites |
|---|------------------------|----------|---------|-------------------------------|
| K1 | Professional-looking documentation with a fake "Prerequisites" step: the user is told to download an archive from an outside repository (Windows) or paste a hosted install script into their terminal (macOS) before the skill will work | **Partial** | CURL_PIPE_BASH, RUNTIME_PACKAGE_INSTALL (line rules run over documentation, capped at CAUTION) | Rule present, no dedicated sample yet. The payload (a password-protected archive; an off-site paste-in script) lives *outside* the skill folder, so the only in-folder evidence is the instruction text itself — exactly the prose case SkillScan deliberately never BLOCKs on |
| K2 | The pasted/hosted script is obfuscated shell that fetches the next stage from attacker infrastructure, which in turn pulls down a stealer binary | **Partial** | BASE64_OBFUSCATION, DECODE_AND_RUN, CURL_PIPE_BASH, NETWORK_ACCESS | If the script itself were inside the folder, the corpus proves the shape is caught: `samples/bad/obfuscated-dropper` (BLOCK, asserted) and mutation 10 (BLOCK). In the documented campaign the script is hosted off-folder, so a folder scan sees only K1's instruction. No sample exercises the off-folder variant — by definition none can |
| K3 | Stealer harvests stored secrets at scale: exchange API keys, wallet private keys, SSH credentials, browser passwords | **Partial** | SSH_CREDENTIAL_READ, CLOUD_CREDENTIAL_READ, ENV_FILE_READ, CREDENTIAL_ENUMERATION, BROWSER_CREDENTIAL_STORE, EXFIL_COMBINATION | The SSH/cloud/.env slice is Covered-grade: `samples/bad/ssh-stealer` (BLOCK, asserted rules) and `samples-mutations/15-glob-discovery` (BLOCK; CREDENTIAL_ENUMERATION fires). v0.2 added BROWSER_CREDENTIAL_STORE (browser profile password/cookie stores — Login Data, logins.json, key4.db, Local State — browser profile dirs, wallet extension storage): CAUTION alone, and it counts as credential material for EXFIL_COMBINATION, so store-access + send BLOCKs. Store paths are also recognised after AST constant folding, so concatenated fragments (`'goo' + 'gle-chr' + 'ome'`) are caught. `run_v02_tests.py` asserts all three shapes. Still Partial: wallet *private-key files* in arbitrary locations, exchange-key files with project-specific names, and anything the stealer reaches by enumerating directories generically can still fall between rules |
| K4 | Reverse-shell backdoor hidden inside otherwise functional skill code | **Covered** | SHELL_OS_SYSTEM, SHELL_SUBPROCESS, NETWORK_ACCESS, NETWORK_SEND_DATA, REVERSE_SHELL | The corpus's code-level send/shell shapes are asserted BLOCK: `samples/bad/ssh-stealer` (NETWORK_SEND_DATA), `samples-mutations/05-subprocess-list` (BLOCK; SHELL_SUBPROCESS + NETWORK_SEND_DATA fire over a subprocess argument list). v0.2 added REVERSE_SHELL for the raw-socket form: a socket connection wired to a shell (dup2 of the socket fd, pty.spawn, bash /dev/tcp, or spawning /bin/sh alongside a socket) BLOCKs, with Python/JS/bash fixtures in `run_v02_tests.py`, plus a benign socket-client fixture proving ordinary socket code without a shell does not trip it. Honest limit: a socket shell that avoids all of those wirings (e.g. passing the socket to an already-running interpreter through an unusual route) can still evade |
| K5 | Bot credentials sitting in the agent's own `.env` file are read and sent out to a third-party webhook endpoint | **Partial** | ENV_FILE_READ, NETWORK_SEND_DATA, EXFIL_COMBINATION | ENV_FILE_READ is exercised by the corpus's `.env`-shaped mutations and EXFIL_COMBINATION fires across the stealer corpus (mutations 01, 02, 03, 06, 08, 12, 14, 17 — all BLOCK). Marked Partial, not Covered, because no single existing sample is the `.env`-to-webhook shape end-to-end: rule present in combination, no dedicated sample yet |
| K6 | Typosquatting and impersonation: skill names and listings that imitate the registry, popular tools, or categories users search for (fake updaters, wallet trackers, video downloaders) | **Gap** | — | SkillScan scans folder *contents*, not marketplace metadata, publisher history, or name similarity. A typosquat with clean code scans PASS, correctly by its own lights — the deception is in the listing, not the files |
| K7 | One shared command-and-control address reused across hundreds of skills from a handful of publisher accounts | **Gap** | — | This is cross-skill, registry-level correlation. A single-folder static scanner has no view of other skills, other publishers, or shared infrastructure, and keeps no reputation data |

## 3. Invariant Labs — MCP Tool Poisoning Attacks

- **Publisher:** Invariant Labs
- **Date:** April 2025 (updated 7 and 11 April 2025)
- **URL:** https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks

| # | Technique (our words) | Coverage | Rule(s) | Evidence from existing suites |
|---|------------------------|----------|---------|-------------------------------|
| I1 | A tool's *description* (text the model reads but the user barely sees) secretly instructs the model to read sensitive local files — client config, SSH keys — and smuggle the contents back inside an ordinary-looking tool argument | **Partial** | MCP_UNRESTRICTED_EXEC / MCP_UNRESTRICTED_READ (declared shape); v0.3: HIDDEN_TEXT, NON_ENGLISH_INSTRUCTION (description concealment mechanics) | `samples-mutations/09-mcp-manifest` proves the structural side (BLOCK on an unconstrained tool declaration). v0.3 covers the *concealment* slice of the description attack: a description smuggling its instruction in Unicode Tags characters BLOCKs when the decoded payload carries instruction keywords, and zero-width/BiDi/HTML-comment hiding in descriptions CAUTIONs (`run_v03_tests.py` fixtures, including a manifest-description case). What remains a Gap inside this Partial: a description that asks for the same thing in plain, visible, novel wording — judging that prose is *asking for something hidden* is semantic, and no rule attempts it |
| I2 | Shadowing: a description on one server redefines how the agent must treat a *different, trusted* server's tool (e.g. rerouting its output to the attacker), without the malicious tool ever being called | **Gap** | — | Requires reasoning about cross-server instruction semantics. SkillScan scans one folder at a time and never interprets description meaning. No rule, no sample |
| I3 | Rug pull: a server that was reviewed and approved quietly changes its tool descriptions afterwards, so the installed behaviour is not the reviewed behaviour | **Gap** | — | A scan is a snapshot of one folder at one moment. Nothing in SkillScan pins hashes, versions, or re-checks a server after install. No rule can see a change that happens after the scan |
| I4 | The exfiltration channel itself: stolen data leaves inside normal tool-call arguments to the connected server, and can be encoded first to make it less visible | **Partial** | BASE64_OBFUSCATION (encoding half only) | If a server *implementation in the folder* performs a network send, NETWORK_SEND_DATA / EXFIL_COMBINATION apply and are corpus-proven (see S1). But when the "send" is the model placing text into a tool argument of a remote server, there is no network code in the folder to flag — that half is a Gap inside this Partial. Rule present for the code half, no dedicated sample for the argument-channel half |

## 4. Koi Security — postmark-mcp

- **Publisher:** Koi Security (researcher Idan Dardikman), reported by
  Infosecurity Magazine
- **Date:** 25 September 2025
- **URLs:** reporting —
  https://www.infosecurity-magazine.com/news/malicious-ai-agent-server/
  ; original Koi report —
  https://www.koi.security/blog/postmark-mcp-npm-malicious-backdoor-email-theft
  (now redirects to the acquirer's site)

| # | Technique (our words) | Coverage | Rule(s) | Evidence from existing suites |
|---|------------------------|----------|---------|-------------------------------|
| P1 | A previously clean, legitimately useful MCP server turns malicious in a later version: one added line silently copies everything the tool processes (here, every email it sends) to the developer's own outside server | **Partial** | NETWORK_SEND_DATA, NETWORK_ACCESS | A hard-coded extra send in implementation code is the shape NETWORK_SEND_DATA exists for, and it is corpus-proven (`samples/bad/ssh-stealer`, asserted; mutation 05 via subprocess, BLOCK). Two honest limits keep this Partial: the rule fires the same way for a *legitimate* second send (analytics, a backup CC) — the rule cannot tell a backdoor copy from a feature — and a JavaScript server's per-call copy inside an existing send function may present as ordinary code for that tool. Rule present, no dedicated sample yet for the "one extra line in a real server" shape |
| P2 | The trust history itself is the weapon: fifteen clean versions build the user base that version sixteen then exploits, and deleting the package from the registry afterwards does not remove it from installed clients | **Gap** | — | Version-over-version diffing, publisher reputation, and post-install monitoring are all outside a single-folder, single-moment static scan. No rule, no sample |
| P3 | The malicious code runs server-side with the full permissions users granted the tool — no exploit needed, just the access the tool legitimately has | **Partial** | MCP_SERVER_COMMAND, MCP_UNRESTRICTED_EXEC, MCP_UNRESTRICTED_READ | SkillScan can flag *unbounded capability declarations*: `samples-mutations/09-mcp-manifest` — BLOCK (MCP_UNRESTRICTED_EXEC + MCP_UNRESTRICTED_READ asserted by the suite), and MCP_SERVER_COMMAND flags manifests that launch via shell/interpreter commands. But for a conventional server whose declared tools are narrow (send email), the scan sees a normal tool doing its normal job — capability *within* a legitimate-looking scope is not distinguishable from the feature itself |

---

## v0.2 additions beyond these four audits

Three v0.2 rule families came from incidents reported *after* this map's
four audits (spotted by the project's audit watch), so they have no row
above. Stated with the same honesty standard:

- **Cloud metadata endpoints** (CLOUD_METADATA_ACCESS / CLOUD_METADATA_EXFIL)
  — malicious MCP npm packages reported in November 2026 probed the
  cloud metadata service (169.254.169.254 and friends) for live
  credentials. Endpoint access alone is CAUTION; combined with an
  outbound send or other credential access it BLOCKs. The endpoint is
  recognised in dotted, decimal-integer, hex, and IPv6 forms and via
  the IMDSv2 token path. A send whose destination IS the metadata
  endpoint (the IMDSv2 token PUT) counts as metadata access, not as a
  send. Fixtures in `run_v02_tests.py` assert all of these. Limit: an
  endpoint reached via a resolved hostname or a non-standard path can
  still evade the patterns.
- **Error / environment leakage into tool results** (ERROR_INFO_LEAK,
  CAUTION) — MCP tool code returning raw exception text, stack traces,
  or environment dumps as tool results (the shape behind CVE-2026-119613,
  AshAi, Nov 2026). Python `return` shapes are detected, including a
  one-hop local (`tb = traceback.format_exc()` then returning `tb`);
  logging an error and returning a plain message is the safe shape and
  is asserted not to fire. Limit: the JS form (returning `e.stack` /
  `e.message` from a catch block) is not detected.
- **Package install-time code** (PACKAGE_INSTALL_SCRIPT /
  PACKAGE_INSTALL_SCRIPT_EXEC) — npm lifecycle scripts and behaviour-
  carrying `setup.py` files run code before the tool is ever called.
  Presence is CAUTION; an install script that downloads or executes
  outside code BLOCKs. Indirection is followed ONE level: a lifecycle
  script's `node <local-file>` target is checked for a fetch+execute
  shape, and a local module imported by `setup.py` gets the same
  behaviour check (comments stripped). The exact well-known benign
  commands `node-gyp rebuild` and `husky` do not fire. Limits: deeper
  indirection chains, non-`node` runners, and downloads assembled
  dynamically inside the referenced file can still evade.

Semantic prompt injection (S6/S7/I1/I2 above) remains a **Gap** in
v0.2, unchanged: no v0.2 rule attempts to judge what instruction prose
*means*, for the reasons given in section B below.

---

## v0.3 additions beyond these four audits

The v0.3 families came from the project's competitor/issue-tracker
research loop (what users of other scanners report missing), stated
with the same honesty standard:

- **Concealment mechanics** (HIDDEN_TEXT / MARKDOWN_CONCEALMENT) —
  invisible-character smuggling (zero-width runs, Unicode Tags-block
  payloads, BiDi controls), instruction-carrying HTML comments, and
  Markdown hiding places (display:none, white-on-white, off-screen
  positioning). This is the mechanics slice of S6/I1 and moves I1 to
  Partial. A plain `<details>` element is NOT counted as a hiding
  place (it is a disclosure widget; see the fix-pass notes below).
  False-positive discipline is fixture-proven: emoji ZWJ sequences,
  Persian/Indic joiners, a file-start BOM, benign HTML comments, and
  benign hidden layout elements all PASS. Limits: variation-selector
  payloads and homoglyph look-alikes are not decoded; a single
  zero-width character in non-ASCII text without keywords is
  deliberately not flagged.
- **Non-English instruction phrases** (NON_ENGLISH_INSTRUCTION,
  CAUTION) — the override / send-credentials / conceal-from-user
  shapes in 14 languages (Spanish, French, German, Polish, Turkish,
  Chinese, Japanese, Russian, Hindi, Portuguese, Arabic, Korean,
  Indonesian, Ukrainian). The phrase lists are per-language JSON data
  files (`skillscan/phrases/<code>.json`) — adding a language means
  adding one file. It is a phrase list, not
  language understanding: novel phrasing and other languages evade
  it, and it is recorded here as a heuristic, not as closing the
  semantic gap (section B stands).
- **Substitution execution** (SUBSTITUTION_EXEC) — downloads
  executed through `$(curl …)`, backtick, or `<(curl …)` substitution
  rather than a pipe (BLOCK); a substitution that only CAPTURES the
  download into a variable that is never executed — including a
  Makefile `$(shell …)` assignment — is the same shape at CAUTION.
  A sibling shape of S2/S10's download-and-run.
- **Session/client sends** — sends through `requests.Session()` /
  `httpx.Client()` / `aiohttp.ClientSession()` objects (variable-bound,
  `with`-bound, attribute-bound as in `self.session`, or chained
  onto the constructor) now resolve onto the library, so the S1/K5
  exfiltration combination sees them; a session GET alone remains a
  plain NETWORK_ACCESS caution.
- **Compiled-code coverage honesty** — a `.pyc`/`.pyo` with no
  matching `.py` source, or a native binary in a folder with no
  source at all, is now a *suspicious* skip: the verdict cannot be a
  clean PASS on code nobody inspected. Compiled artefacts shipped
  alongside their source stay non-suspicious (fixture-proven both
  ways). This addresses a failure mode reported against other
  scanners (bytecode-only skills read as safe); it is a coverage
  stance, not a detection rule. **Stated weakness (decoy):** the
  pairing is by file NAME only — a folder can ship a harmless
  `helper.py` beside a malicious `helper.pyc` and the bytecode reads
  as a routine build artefact, because the scanner trusts the
  source's presence as provenance and never compares the bytecode's
  content against the source. Closing that would require decompiling
  or executing the bytecode, both out of scope for this tool; the
  stance is a tripwire against bytecode-ONLY folders, not a proof
  that shipped bytecode matches its neighbouring source.
- **Environment injection** (ENV_INJECTION / ENV_INJECTION_INSTALL)
  — LD_PRELOAD / DYLD_INSERT_LIBRARIES / PYTHONSTARTUP references
  (CAUTION), the same variables set from an install script, a
  `setup.py`, or an MCP manifest env (BLOCK), and the
  predictable-temp-path + make-executable shape (CAUTION). A new
  family; no row in the four audits above maps to it.
- **OWASP mapping metadata** — every rule now carries OWASP LLM Top
  10 / MCP Top 10 category codes, surfaced in JSON findings and
  SARIF rule metadata. Metadata only; it changes no verdict and no
  coverage cell.

## v0.3 fix pass (post-review corrections)

v0.3 went through the standing multi-agent adversarial review
(false-positive hunter, red team, code auditor). The fixes below are
all regression-fixtured in `run_v03_tests.py`; behaviour that changed
is stated, not smoothed over:

- **Substitution severity is execution-aware.** `VAR=$(curl …)` that
  is captured and never executed is CAUTION, not BLOCK; BLOCK is
  reserved for executing contexts (command position, `eval`, `sh -c`,
  pipes to a shell, process substitution, or a variable the same
  file later executes). Quote-split command names (`cu''rl`) are
  normalised before matching.
- **Comment and concealment keyword bars are instruction-grade.**
  HTML comments and Markdown-hidden content now require a strong
  keyword or a send-verb WITH a credential target — a TODO comment
  about sending an invoice template, or a hidden FAQ mentioning
  "download", no longer fires. A plain `<details>` element is no
  longer treated as concealment at all (disclosure widget); it needs
  a real hiding style/attribute as well. Concealment reading now
  covers off-screen positioning and reads to the element's matching
  close tag (4000-char fallback), and HTML comments are checked
  individually, concatenated (payloads split across comments), and
  to end-of-file when unclosed.
- **The test-banner exemption is content-based.** A comment is
  skipped only when it is banner/safety text AND carries no
  instruction-grade keywords; a banner phrase sharing a comment with
  a payload no longer exempts the payload.
- **Tags-block smuggling is checked file-wide.** All Tags runs in a
  file are also decoded as one concatenation (a keyword split across
  runs still BLOCKs), and a line carrying two or more Tags characters
  in any arrangement — e.g. interleaved with zero-width characters —
  is at least a CAUTION presence hit.
- **Temp-path execution is path-tied.** ENV_INJECTION's /tmp shape
  completes only when the execution context references the SAME path
  (literal, or one hop through a variable bound to it); an unrelated
  subprocess elsewhere in the file no longer completes it, and
  negation prose is honoured.
- **Sessions resolve through attributes.** `self.session = …`
  bindings resolve like variables (previously only plain variables
  did, inconsistently flagging one form and missing the other), and
  `aiohttp.ClientSession` (including `async with`) is a known
  constructor. Chosen semantics for ambiguity: when one name is bound
  to objects of two different modules in a file, its sends are NOT
  classified — a flat symbol table cannot tell which binding a call
  site sees, and guessing manufactures both false positives and
  false negatives (fixture-proven both ways).
- **`.pth` files are a first-class startup surface.** Any `import`
  line or environment/path manipulation in a `.pth` file is
  ENV_INJECTION_INSTALL (BLOCK) — a `.pth` executes at every
  interpreter startup. Plain path entries and comments pass.
  PYTHONPATH joins the injection-variable set for install/startup
  contexts (lifecycle commands, manifest command/args, `setup.py`,
  `.pth`); it is deliberately NOT flagged as a bare MCP manifest
  *env dict* entry, where pointing it at the server's own code is a
  common legitimate configuration.
- **JSON manifests are checked after parsing.** The hidden-text,
  non-English and structure matchers also run over the parsed string
  values of `.json` files, so `\uXXXX`-escaped payloads are caught
  after decoding rather than only in raw text.
- **`.pyc` pairing compares full stems** with the interpreter tag
  stripped (`a.b.pyc` pairs with `a.b.py`; `x.cpython-312.pyc` pairs
  with `x.py`). The name-presence decoy weakness above stands.
- **ANY_LANGUAGE_STRUCTURE (new rule, CAUTION)** — on instruction
  surfaces, the co-occurrence of a PRIVATE credential-store anchor
  (`~/.ssh`, `~/.aws`, a `.env` file, an SSH key file, a browser
  credential store) with an outbound anchor (URL, IP, email address,
  curl/wget, webhook) fires in ANY language, no phrase list needed.
  The anchor is deliberately the private store, not the word
  "token": a guide telling users to send their own token to the
  service's own API URL is normal documentation and passes, as does
  negation-guarded safety prose (both fixture-proven; a malicious
  shape written in Italian — a language with no phrase set — fires).

---

## v0.4 additions — the benchmark fix wave

v0.4 came from measuring v0.2 against MaliciousSkillBench (9,740
labelled skills; internal report in the project watch folder). Three
targets, in the order the data ranked them:

- **Dependency sources** (DEPENDENCY_SOURCE / DEPENDENCY_EXECUTION)
  — the supply-chain family was the weakest measured family
  (11.4% BLOCK in v0.2) and the one place a rival's lead was purely
  structural. Dependency manifests (`package.json`, requirements
  files, `pyproject.toml`, `setup.py`, `Pipfile` — plus template
  manifests, `package.template.json` / `package.json.template`,
  which are package.json files in waiting and get the same
  install-script and dependency-source analysis) are now parsed for
  WHERE each dependency comes from: a git URL, a direct http(s)
  archive link, a local file path, or a non-official package index
  is DEPENDENCY_SOURCE (CAUTION); the same package also running
  code at install time — an npm lifecycle script, a behavioural
  `setup.py`, a loader-injection install — or declaring an
  unrestricted-exec MCP tool escalates it to DEPENDENCY_EXECUTION
  (BLOCK). (Combination scoping narrowed to the same package
  directory by the fix pass below: one package's lifecycle script
  no longer escalates another package's source.) Registry-pinned manifests pass, fixture-proven in
  `run_v04_tests.py`. Two honest limits: (1) the benchmark corpus
  itself declares almost no off-registry dependencies (its
  supply-chain labels ride on install *instructions*, covered by
  INSTALL_FROM_URL below), so this family's measured gain on that
  corpus is small — the rule exists because the shape is real in
  the wild, not because the corpus rewards it; (2) typosquat /
  name-similarity detection is deliberately NOT attempted — it
  needs registry metadata (see gap class C, K6/K7) and a fixed
  top-package list would false-positive against the long tail of
  legitimate names.
- **JS network + download-and-run** — the code-bearing miss census
  found Node `http`/`https` module calls (`https.get(...)`,
  `http.request(...)`) matched NO rule in v0.2/v0.3: NETWORK_ACCESS
  now covers them, DYNAMIC_IMPORT covers a JS `require()` of a
  computed (non-literal or string-concatenated) path, and the
  combination — fetch + dynamic load in one file — is
  DOWNLOAD_AND_RUN (BLOCK), the JS analogue of DECODE_AND_RUN.
  Literal `require("name")` and fetch-only files stay at their
  ordinary severities, fixture-proven both ways.
- **Install-prose refinement** (INSTALL_FROM_URL; RUNTIME_PACKAGE_
  INSTALL narrowed in documentation) — v0.2 put 17.7% of *benign*
  skills into the CAUTION pile for one reason: their instructions
  said "install <named package>". Documentation installs are now
  classified by source: named registry packages, bare installs, and
  declared-requirements installs no longer flag; a URL / git /
  archive / local-path / custom-index source fires INSTALL_
  FROM_URL (CAUTION) in prose and code alike. Code behaviour is
  unchanged (a named install in a script still cautions as
  RUNTIME_PACKAGE_INSTALL). Negated safety prose is still skipped
  before classification. This narrows S3's noise without narrowing
  its catch: the off-registry *source* is the lure shape.
- **Adjacent fix the new fixtures exposed:** the `setup.py`
  behaviour check matched module NAMES as bare words, so a
  metadata-only `setup.py` declaring `requests` in
  `install_requires` read as install-time network behaviour. The
  check now requires usage form (import or call). Proven by the
  v0.4 `setup.py` fixtures (plain metadata passes; dependency-link
  sources still caution).
- **SUBSTITUTION_EXEC documentation cap (precision fix, folded in
  from the v0.3 re-run report):** v0.3 BLOCKed executing
  substitutions inside documentation — code-fence examples in
  prose — producing 15 false BLOCKs on the benchmark's benign set
  and breaking the scanner's zero-false-BLOCK property. The
  executing form in a documentation file is now capped at CAUTION,
  like every other rule's documentation findings; the same shape
  in a code file still BLOCKs. Measured on the full benign set:
  false BLOCKs 15 → 0.
- **Directive-comment recalibration (HIDDEN_TEXT):** the v0.3 fix
  pass raised the HTML-comment bar to credential-grade keywords
  only; the re-run showed the payload comments it lost are
  DIRECTIVE-shaped — "[SYSTEM … DIRECTIVE] …", "OPERATIONAL
  DIRECTIVE: you are configured as …" — agent-addressed orders in
  framing vocabulary. A directive-shape tier now sits beside the
  grade bar (bracketed meta-directive header; "directive" plus an
  imperative; "execute the following"). Measured: 6 of the 20
  HIDDEN_TEXT regression folders recovered (the other 14 carry
  only a benchmark-harness "do not execute" label, present on the
  benign side too and now explicitly banner-exempt), and the
  shape matches 0 of 2,235 benign folders' comments.
- **Prose chains and the agent-as-channel (PROSE_DOWNLOAD_RUN /
  READ_AND_DISCLOSE):** two document/folder-level joins aimed at
  the re-run's two big miss pools. PROSE_DOWNLOAD_RUN joins an
  external archive/binary target + a download step + a run step
  across one document — measured on the v0.3 prose-only miss pool
  (984 folders): the rule fired in 146, and the pool's total
  conversion was 193 (19.6%). READ_AND_DISCLOSE joins code that
  reads local files with prose directing disclosure to an
  external destination — measured conversion on the code-bearing
  miss pool is small (3 folders): that pool's prose overwhelmingly
  says "report to the user", which is the normal agent loop and
  deliberately NOT flagged. The strict bar is the honest one; the
  residual agent-as-channel class (reads parameterised files,
  discloses in conversation) remains a documented gap (class F).

### v0.4 fix pass — adversarial-review fixes (regression suite:
`run_v04fix_tests.py`, 65 cases)

Three independent reviews of the v0.4 build (red team 36 fixtures,
false-positive hunter 51 fixtures, code auditor ~30 probes) found
one critical defect class, a set of false BLOCKs, and a set of
evasions. All are fixed in this pass; the version stays 0.4.0.

- **Scanner DoS (auditor F1, critical).** Two v0.4 regexes were
  quadratic — the PEP 508 direct-reference pattern and the prose
  archive-target pattern; a 300 KB `setup.py` or a 1.9 MB
  single-line `requirements.txt` hung the scanner for over a
  minute. Both are rewritten as linear scans (bounded look-back
  for direct references; extension-anchored search for archive
  targets), and every other v0.4-new pattern was audited for the
  same disease (the JS load-shape lookahead was also bounded).
  Worst adversarial shape now scans in ~2 s; perf regression cases
  are in the suite.
- **Inert text is not behaviour (FP-1, FP-3, auditor F5/F6).**
  Line rules and the dedicated matchers now distinguish comments
  and string literals from live code in Python, shell, and JS/TS
  files: a substitution quoted in a comment is dropped (not merely
  capped), one inside a Python/JS string caps at CAUTION, and one
  in live code still BLOCKs — per site, so a file that both quotes
  the pattern and executes it still BLOCKs. `setup.py` behaviour
  analysis runs on string-stripped code, `urllib.parse` is no
  longer classified as network access anywhere (it manipulates URL
  strings; `urllib.request` still counts), and a fetch *word* in a
  JS comment is no longer fetch evidence for DOWNLOAD_AND_RUN.
- **Routine install hooks (FP-2, auditor F2).** DEPENDENCY_
  EXECUTION no longer escalates on routine lifecycle commands
  (`tsc` builds, `patch-package`, `husky`, `node-gyp rebuild`,
  git-describe version reads) and only combines within the same
  package directory. The CAUTION findings themselves are
  unchanged; download/execute-shaped hooks still escalate.
- **Evasions closed.** Remote dynamic `import("https://…")` and
  the fetch→write→literal-`require` two-stage dropper now BLOCK;
  the banner exemption no longer swallows directive payloads, and
  persona-override shapes joined the directive family (with
  framework/legal directive documentation — Angular/Vue/CSS/EU —
  recognised as documentation, not payloads); npm `overrides` /
  yarn `resolutions`, requirements `-r` includes, folded strings
  in `setup.py`, and single-quoted Pipfile sources are read;
  malformed `package.json` still gets raw-text dependency and
  script analysis; install classification covers `npm i`,
  `pnpm add`, `bun add`, every command on a line, attached
  `-i<url>` flags, userinfo in index URLs, and trailing comments;
  READ_AND_DISCLOSE joins across a paragraph block, stems its
  verbs (uploading, delivering), accepts named-platform
  destinations and `cat`/`read_csv` readers — while honouring
  explicit negations, consent gates, self-recipients, and local
  destinations; PROSE_DOWNLOAD_RUN joins across a folder's
  documents and accepts `.sh` targets and get/fetch/grab verbs,
  with bare-URL targets requiring a staging step so "download the
  app and run it" still passes; executing contexts for
  substitutions include interpreter `-c`/`-e` and dot-source, and
  the shell squeeze collapses backslash escapes (`c\url`).
- **Acceptance results.** Red team: 36/36 fixtures at target
  tiers (was 13 gaps). False-positive set: zero false BLOCKs
  everywhere; the remaining CAUTIONs on that set are the by-design
  ones (off-registry sources and direct-URL installs are CAUTION
  findings on purpose, and two official-installer prose chains
  stay CAUTION as accepted). Benign review folders and the benign
  package corpus: 0 BLOCK, verdicts unchanged. All suites green,
  including the 65 new fix-pass cases.
- **Full-corpus re-scan (MaliciousSkillBench, same counting as
  the v0.3 report).** Benign (n=2,235): false BLOCKs **15 → 0**
  (the v0.3 regression is fully reversed), CAUTION 578 → 498
  folders, median 32 ms. Malicious (n=7,421, 0 scanner errors):
  BLOCK 45.9% → 45.7% and BLOCK+CAUTION 81.8% → 81.8% — detection
  held flat by design (25 BLOCK→CAUTION demotions from the
  inert-text caps, offset by new BLOCKs from the dropper and
  combination fixes); misses 1,353 → 1,351. Per family:
  execution/code-delivery BLOCK+CAUTION 95.6% → 97.8% (its misses
  halved, 140 → 70); dependency/supply-chain BLOCK 12.0% → 13.2%
  with BLOCK+CAUTION 88.6% → 87.4% (n=167, noise band);
  instruction manipulation BLOCK+CAUTION 87.8% → 85.8% and the
  pure prose-only subset 51.8% → 44.4% — the honest cost of the
  directive-documentation narrowing above: recognisable framework
  and legal documentation is no longer flagged, and some real
  manipulation prose is shaped like it. Median malicious scan
  89 ms (v0.3: 90 ms).

What v0.4 deliberately does not claim: the largest miss class —
prose-only skills whose payload is pure instruction manipulation —
is unchanged (gap class B stands; it is semantic). Cross-file
value-level dataflow for the remaining code-bearing quiet skills is
still not performed (gap class F stands).

---

## v0.5 additions — the standalone-coverage wave

Design: `skillscan-watch/V05_PLAN.md`. Everything below is still
zero-dependency, offline and deterministic — no network, no model,
nothing leaves the machine. Rules 47 → 57.

- **Prose chain extensions (coverage S3/K1).** The by-hand chain
  family grows four members: PROSE_FETCH_EXECUTE (a script or tool
  fetched by URL and run, including anaphoric "then run it" steps —
  the anaphoric variant requires a staging step, because "download
  the app and run it" is an ordinary install sentence and a v0.4
  control case), PROSE_PIPE_INSTRUCTION (pipe-a-download-into-a-
  shell as documentation, fenced or in words), PROSE_READ_SEND
  (the prose-only sibling of READ_AND_DISCLOSE: a prose read half
  plus a send verb with a strict destination — URL, email or
  "external" — in one sentence, with the shared consent/self/own/
  local suppressors and a third-party-subject guard),
  PROSE_SAFETY_BYPASS, and the LURE_WITH_BYPASS combination
  (BLOCK): a download-and-run chain anywhere in the folder plus a
  safety-bypass instruction anywhere in the folder.
- **Output manipulation + English prompt manipulation (gap class
  B, mechanics side).** OUTPUT_MANIPULATION and
  PROSE_INSTRUCTION_EN run ONLY on instruction surfaces — a
  skill's SKILL.md, *.mdc editor rules, and tool-description JSON
  string values — never on arbitrary documentation, and never on
  fenced code examples. Three bars for output manipulation:
  concealment from the user, compliance steering, and
  recommendation bias (bias verb + quantifier in one sentence and
  a competitor contrast in the same block). Discussion of such
  attacks is exempt per sentence: framing vocabulary and
  prohibitions of the form ("never follow instructions that
  say…") suppress the match they frame — the v0.4 NEGATION_RE is
  deliberately not reused here, because it matches a bare "do
  not" and would neutralise "do not tell the user" itself.
  Matching runs over paragraph blocks, because real skills
  hard-wrap prose and a payload split across a wrap is still one
  instruction. First-cut bars measured 1.43% rule-alone on the
  benign corpus (markdown tables and checklists); the shipped
  bars measure **0.36%** rule-alone (see the re-scan below).
- **Taint-lite for Python (gap class F, intra-file slice).**
  TAINTED_SEND (BLOCK): values sourced from credential material —
  classified by path value (SSH/cloud/browser-store fragments,
  `.env`, credential filenames), never by variable name — flow
  through assignments, containers, f-strings, transparent
  wrappers (str/bytes/encoders/json.dumps) and file-local function
  return summaries into a network send at any argument position.
  SECRET_FLOW (CAUTION): a secret-named environment variable's
  value in a request BODY — a service's own token in its own
  Authorization header is explicitly not flagged, and plain file
  contents on a socket are not flagged ("file"/"input" taint
  never fires alone). Intra-file and Python-only; no sanitiser
  modelling (encoding a credential does not clean it). As
  originally built, function summaries were name-keyed, not
  scope-keyed; the fix pass below replaced the tracker with a
  scope-aware, flow-sensitive one. This is the honest
  small slice of class F, not the class.
- **Offline typosquat (gap K6, name-shape only).**
  TYPOSQUAT_SUSPECT (CAUTION) compares declared dependency names
  against curated top-package lists shipped as data files
  (`skillscan/toplists/{pypi,npm}.json`, loaded like `phrases/`),
  using Damerau-Levenshtein distance 1, distance 2 under
  first-letter + prefix guards, separator mutations and
  homoglyph-lite folds. A known-legitimate-neighbours list is
  part of the data (fastai, authlib, clsx, safer-buffer and
  friends are real packages one edit from a top name).
  Validation gate, asserted in run_v05_tests.py: 545 harvested
  legitimate PyPI names and 775 npm names (from local manifests,
  lock files, installed trees and installed-package metadata;
  the fix pass added famous near-miss packages the first cut
  flagged — nox, fpdf, pypdf2, markdown2, aredis, polar, preact,
  momentjs — to the known-legitimate-neighbours data)
  produce **zero** flags, and a synthetic mutation battery over
  the top names is caught at 100% (the battery generates the
  same mutation classes the matcher implements — a consistency
  check, not an independent red team). Expected benchmark gain
  is ~zero by construction: the benchmark corpus declares
  almost no squatted dependencies. The value is forward-looking,
  against real-world manifests.

- **Full-corpus re-scan (MaliciousSkillBench, same counting as
  the v0.4 report).** Benign (n=2,235): false BLOCKs **0**
  (unchanged), CAUTION 498 → 543 folders, median 33 ms. Every new
  prose rule's rule-alone benign rate is under the plan's 1%
  bar: OUTPUT_MANIPULATION 0.36%, PROSE_INSTRUCTION_EN 0.63%,
  PROSE_READ_SEND 0.85%, PROSE_PIPE_INSTRUCTION 0% alone (0.67%
  counting co-fires), PROSE_SAFETY_BYPASS 0.09%; LURE_WITH_BYPASS,
  TAINTED_SEND, SECRET_FLOW and TYPOSQUAT_SUSPECT fire zero times
  on the benign set. Malicious (n=7,421, 0 scanner errors):
  BLOCK 45.7% → 45.7% (3,394 → 3,395) and BLOCK+CAUTION 81.8% →
  **82.2%** — 32 folders newly flagged, none lost, no BLOCK
  demoted; median 70 ms. Per family: data exfiltration B+C
  82.3% → 83.5% (pure subset 81.9% → 83.1%), instruction
  manipulation B+C 85.8% → 86.0% (pure prose subset 44.4% →
  44.7%), execution unchanged at 97.8%, supply-chain unchanged.
  New-rule fires on the malicious set: PROSE_PIPE_INSTRUCTION
  309 folders (nearly all co-firing with existing rules),
  PROSE_READ_SEND 126, OUTPUT_MANIPULATION 107,
  PROSE_INSTRUCTION_EN 106 (20 alone), PROSE_FETCH_EXECUTE 52,
  SECRET_FLOW 18, PROSE_SAFETY_BYPASS 10, TAINTED_SEND 2,
  LURE_WITH_BYPASS 1, TYPOSQUAT_SUSPECT 0 (as predicted — the
  corpus declares no squatted dependencies).

### v0.5 fix pass — three adversarial reviews, one combined pass

The v0.5 build was reviewed by three independent adversarial
passes before shipping: a red team (24 fixtures, 20 true
evasions), a false-positive hunt (45 fixtures, 5 new benign
BLOCKs) and a code audit (13 findings, one HIGH). One combined
fix pass addressed all three; `run_v05fix_tests.py` encodes one
regression case per reviewer finding, and all ten suites are
green. Per finding:

- **Taint tracker rewritten (audit F1 HIGH, F2, F3; red team
  rt14–rt17).** The build's tracker keyed credential bindings by
  bare variable name across the whole file and never killed
  taint on reassignment — it BLOCKed on flows that do not exist
  (a name collision between two functions) and missed flows
  that do (container writes). The replacement is scope-aware
  and flow-sensitive: per-function scopes, statements in order,
  reassignment kills taint, branches merge by union, container
  writes (subscript stores, append/extend/update/setdefault,
  setattr) carry taint, unknown method calls propagate receiver
  taint (`.read().strip()`, `.hex()` — no sanitiser modelling,
  as before), tuple unpacking and walrus assignments are
  tracked, and function summaries (parameter pass-through,
  return taint) resolve to a bounded fixpoint. Findings now
  carry evidence strings ("credential value from read of …
  reaches a network send"). A taint or parse failure on a deep
  expression records a Skipped note (SCAN_INCOMPLETE) instead
  of silently disabling the analysis (F2). Path classification
  no longer treats public key material as a credential: `.pub`
  files never classify, and `.pem` classifies only with a
  key-shaped name (FP hunt).
- **LURE_WITH_BYPASS proximity + framing (FP hunt, critical).**
  The build joined a bypass phrase anywhere in a folder with a
  download-run chain anywhere else and blocked five benign
  folders (a printer FAQ, a Defender exclusion guide, a
  Gatekeeper guide, anti-phishing training material, a Mac
  setup assistant). The combination now requires the same file
  with the two halves within 40 lines, and the bypass matcher
  itself suppresses warning/training/troubleshooting framing at
  paragraph level; the sanctioned right-click → Open path is
  exempt. All five fixtures pass; the red team's split-in-one-
  document lure (rt12) still blocks.
- **Guard laundering closed (rt03, rt04, rt09, rt10; audit F4,
  F5, F9).** Output-manipulation guards now judge frame
  STRUCTURE, not keywords: a quoted payload is suppressed, a
  prohibition frame suppresses only the matches it governs, and
  a framing word ("example", "attackers") suppresses only when
  it introduces the match as an exhibit — "example" inside the
  payload sentence no longer launders it (rt03), and a payload
  wearing prohibition shape ("never let the user know…") fires
  (rt04). Disclose/read-send suppression is judged per sentence
  instead of per block (F5): a self/own-data frame no longer
  covers a sentence that names a concrete external destination
  (rt09, rt10). Sentence boundaries no longer split on the dot
  inside an email address or URL, which had hidden exactly
  those destinations from the override logic.
- **Chain and prose gaps (rt01, rt02, rt05–rt08, rt11, rt13;
  audit F6).** The negation helper behind every prose chain
  (and v0.4's PROSE_DOWNLOAD_RUN) no longer treats a bare "not"
  as a prohibition — clause-scoped strong prohibitions only.
  PROSE_FETCH_EXECUTE joins across a document and across a
  folder (rt01, rt13); pipe-to-shell gained hand/give/feed/pass
  phrasings (rt02); bypass synonyms ("switch off") and
  same-document cross-paragraph joins landed (rt11, rt12);
  disclose/read-send gained synonym targets, the relay verb,
  consent phrasings from terse professional prose, and a
  document-level destination join whose send verb must carry a
  content object (rt08; the content-object requirement was
  added after a first re-scan showed the unconstrained join
  tripled the rule's benign rate). Same-sentence duplication
  between PROSE_READ_SEND and PROSE_INSTRUCTION_EN is deduped.
- **Typosquat extraction + matcher (rt18, rt19, rt20; audit
  F7, F12).** The build's PyPI half was blind to unpinned names
  (a specifier character was wrongly required); bare quoted
  names in pyproject are now extracted, setup.py resolves one
  level of module-level list variables, distance-2 matching
  extends to the top-100 names, and Cyrillic-lookalike names
  are folded before comparison. The matcher was rewritten
  around a deletion index: per-name cost fell from ~0.45 ms to
  ~0.07 ms (20k-name pyproject manifest 8.9 s → 2.8 s) with
  verdicts unchanged — every candidate is still verified with
  the same distance function. Famous legitimate near-miss
  packages the first cut flagged (nox, fpdf, pypdf2, markdown2,
  aredis, polar, yaml, preact, momentjs) joined the
  known-legitimate-neighbours data and the validation sets.
- **Surfaces (audit F8, F10, F11).** A deep-JSON failure in the
  tool-description value pass now records a Skipped note
  instead of dying silently; an unclosed code fence is treated
  as ordinary text rather than swallowing the rest of the
  document from the prose matchers; the instruction-surface
  gate accepts a lowercase `skill.md`.
- **Accepted, with reasons.** Four red-team fixtures remain
  evasions by design (rt21–rt24: compound package names,
  novel paraphrase steering, novel override wording, and
  cross-file value flow — the deterministic ceiling and the
  never-claimed class-F remainder). A handful of benign
  fixtures still earn a CAUTION from a single new rule where
  the shape genuinely is the shape (a prompt-injection course
  discussing overrides; a journal tool that forwards
  manuscripts to a named external editor — a real read-and-send
  flow a human approves knowingly). Three FP-hunt fixtures
  still BLOCK via TAINTED_SEND because the flow is real
  (credential stores read and uploaded); they blocked in v0.4
  on other rules too. One corpus folder's only build signal
  was an output-manipulation shape the reviewers proved fires
  on ordinary English; it now passes — the measured cost of
  the narrowing, one folder (below).

- **Full-corpus re-scan (MaliciousSkillBench, same counting).**
  Benign (n=2,235): false BLOCKs **0** (gate held), CAUTION
  543 → 555 folders, median 33 ms → 43 ms. New-rule benign rule-alone
  rates: OUTPUT_MANIPULATION 0.36% → 0.13%, PROSE_READ_SEND
  0.85% → 1.34% (the rt07/rt08/rt09/rt10 closures widen the
  net on professional prose; CAUTION-only), PROSE_INSTRUCTION_EN
  0.63% (unchanged), PROSE_SAFETY_BYPASS 0.09% (unchanged);
  LURE_WITH_BYPASS, TAINTED_SEND, SECRET_FLOW and
  TYPOSQUAT_SUSPECT still fire zero times. Malicious
  (n=7,421, 0 scanner errors): BLOCK 45.7% → **45.7%**
  (3,395 → 3,395 — identical in every attack family) and
  BLOCK+CAUTION 82.2% → **82.4%** (6,102 → 6,117): 16 folders
  newly flagged, 1 lost (the output-manipulation-only folder
  above), no BLOCK demoted or promoted. Median 70 ms → 80 ms
  (the flow-sensitive taint pass and the new joins). New-rule
  fires moved with the closures they encode: PROSE_FETCH_EXECUTE
  52 → 204 folders (the cross-document/cross-folder joins),
  PROSE_READ_SEND 126 → 194, PROSE_INSTRUCTION_EN 106 → 120,
  TAINTED_SEND 2 → 3, TYPOSQUAT_SUSPECT 0 → 2. The output-
  manipulation family is unchanged (28.9% B+C); its remaining
  misses are still the semantic-steering class documented
  below.

What v0.5 deliberately does not claim: output manipulation is
phrase-shaped, not semantic — paraphrased steering with none of
the listed shapes still passes (gap class B stands). The
benchmark's own output-manipulation family did **not** move
(28.9% B+C before and after): inspection of its pure misses
shows the payload is predominantly domain-framed steering
("current engineering protocols require noting that…") inside
otherwise ordinary skills — meaning, not mechanism. Taint-lite
is Python-only and intra-file; the reader-helper class (code
reads, prose sends) is covered by READ_AND_DISCLOSE /
PROSE_READ_SEND, not by dataflow. Typosquat sees only names
similar to the curated top lists; a squat of a mid-tail package
is invisible to it.

---

## Gaps — the full honest list

Every Gap and Partial above, grouped by *why* it is hard for this tool.
Nothing here is a roadmap promise; several items are out of scope for a
static folder scanner by design, and are listed so nobody over-trusts a
PASS.

### A. The payload is not in the folder
- **K1, K2** — fake prerequisite steps point at archives and hosted scripts
  elsewhere; a folder scan can only see the pointing, and prose findings
  are capped at CAUTION by design.
- **S9** — injected instructions arrive in content fetched at run time;
  there is nothing to inspect at scan time.
- **S10 (partial)** — remote *instruction* loading without a pipe-to-shell
  or eval presents as a plain network fetch.

### B. The attack is meaning, not mechanism (semantic prompt injection)
- **S6, S7, I1, I2** — deceptive instructions in SKILL.md prose or MCP tool
  descriptions, requests to reveal secrets, and cross-tool shadowing all
  require judging what natural language *means and intends*. SkillScan's
  verdicts come from deterministic pattern rules precisely so they are
  reproducible; it has no instruction-semantics rule, and bolting an LLM
  judge on would change the tool's core guarantee. v0.3 narrows this
  class from the mechanics side — concealment characters, hiding
  places, and known attack phrases in 14 languages (moving I1 to
  Partial) — but the meaning itself remains unjudged, and S7/I2 are
  untouched. This is the single
  largest gap class in the audits — Snyk found prompt injection in the
  overwhelming majority of confirmed malicious skills, usually *combined*
  with the code patterns SkillScan does catch (which is why the code half
  still matters).

### C. The attack happens across time or across the registry
- **I3, P2** — rug pulls and clean-then-malicious version histories need
  pinning, diffing, or monitoring after install.
- **K6, K7** — typosquatting and shared infrastructure across hundreds of
  skills need registry-level metadata and correlation.
- A pre-install, single-folder scanner structurally cannot see any of
  these. They belong to registries and install-time tooling, not to this
  CLI.

### D. Capability is not malice
- **S11, P1, P3** — direct money access, a second network send, or broad
  granted permissions are each the *feature* in honest tools and the
  *weapon* in malicious ones. SkillScan flags capability at CAUTION where
  a rule exists at all (network, subprocess, manifest shape) and does not
  pretend to infer intent.

### E. Missing rule families (code-shaped, so fixable in principle)
- **S8** — *addressed in v0.2:* hardcoded-secret detection now exists
  (HARDCODED_SECRET_LIVE / HARDCODED_SECRET_GENERIC; see the S8 row).
  Short, low-entropy, split or encoded secrets still evade it.
- **K3 (partial)** — *partly addressed in v0.2:* browser credential
  stores and wallet extension storage now have a dedicated rule
  (BROWSER_CREDENTIAL_STORE). Wallet private-key files under
  project-specific names and generic directory enumeration of credential
  material remain gaps.
- **K4 (limit)** — *partly addressed in v0.2:* REVERSE_SHELL catches the
  common raw-socket wirings (dup2, pty.spawn, /dev/tcp, shell spawn
  alongside a socket — including a quoted `['sh', '-c', …]` list — and
  the Ruby TCPSocket + IO.popen form). Exotic wirings can still fall
  between rules: a pipe-relay shell with no dup2, and a JS shell whose
  name is assembled from string fragments, are known evasions. Raw
  socket sends on their own are only a CAUTION capability flag
  (NETWORK_ACCESS) — chat clients and echo servers are benign socket
  code — and count toward combinations only when the receiver resolves
  to the socket module.
- **S4, S5, K5 (evidence gaps)** — rules exist and fire in code, but
  the corpus has no dedicated sample for the prose form (S4, S5) or
  the exact end-to-end shape (K5), so those mappings are asserted by rule
  inspection, not by a test. They are labelled that way in the tables
  rather than upgraded to "Covered". (S3's prose form gained
  dedicated fixtures in v0.4 — see the v0.4 section above; it stays
  Partial only because prose findings cap at CAUTION by design.)

### F. Runtime behaviour (already stated in the README, repeated for completeness)
- Behaviour decided by a server response, the date, or an encrypted config
  is invisible to any static scan; strong packing beyond base64/hex is
  flagged at most as obfuscation; value-level taint tracking across files
  is not performed (EXFIL_COMBINATION works at skill level, not value
  level).

---

*Map compiled from the four audits above and the scanner source
(`skillscan/rules.py`, `skillscan/scanner.py`) and test suites as of
v0.5.0. If a rule or a sample changes, this map must change with it — a
coverage claim without a suite behind it is exactly the kind of thing
this document exists to prevent.*
