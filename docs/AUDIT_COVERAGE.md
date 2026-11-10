# Audit coverage map

How SkillScan v0.2's 34 deterministic rules line up against the techniques
documented in published audits of real malicious AI-agent skills and MCP
servers.

**Method, stated plainly:**

- The techniques below are summarised **in our own words** from the cited
  audits. No report text and no malicious code from any audit is reproduced
  here.
- "Evidence" means one thing only: an **existing** sample in `samples/` or
  `samples-mutations/`, or a fixture in `run_v02_tests.py` (the v0.2 suite
  builds inert fixtures in a temp dir), that an existing test suite already
  scans, with the verdict that suite asserts. No new sample was created
  for this map beyond what those suites contain.
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
| Invariant Labs — MCP Tool Poisoning (Apr 2025) | 4 | 0 | 1 | 3 |
| Koi Security — postmark-mcp (Sep 2025) | 3 | 0 | 2 | 1 |
| **Total** | **25** | **4** | **12** | **9** |

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
| S3 | The skill's *instructions* (SKILL.md prose) tell the agent/user to fetch and install untrusted software from an outside location, including archives a scanner cannot see inside | **Partial** | CURL_PIPE_BASH, RUNTIME_PACKAGE_INSTALL, NETWORK_ACCESS (all line rules also run over documentation) | Rule present, no dedicated sample yet. Documentation findings are deliberately capped at CAUTION and negated safety prose is skipped (scanner design), so a prose-only install instruction can never produce a BLOCK from SkillScan. No existing sample puts the download instruction in prose only |
| S4 | Obfuscated exfiltration commands are embedded in installation instructions rather than in code files | **Partial** | BASE64_OBFUSCATION, DECODE_AND_RUN, SSH_CREDENTIAL_READ, CLOUD_CREDENTIAL_READ (line rules run over `.md` too) | Rule present, no dedicated sample yet — the corpus's obfuscated samples keep the payload in code (`samples/bad/obfuscated-dropper`, mutation 10). In prose, DECODE_AND_RUN's block severity is capped to CAUTION like every documentation finding |
| S5 | Instructions push the agent to weaken the machine: alter service/startup configuration so a backdoor persists, delete system files, loosen security settings | **Partial** | PERSISTENCE, RM_RF, FILE_DELETE, CHMOD_CHOWN | In *code* these fire at full severity — PERSISTENCE/RM_RF are exercised by the corpus's shell-shaped samples (e.g. `samples-mutations/06-shell-home-var`, BLOCK) and FILE_DELETE by `samples/caution/shell-automation` (CAUTION, asserted by `run_tests.py`). In *prose* the same words are capped at CAUTION; a dedicated persistence sample does not exist, so for PERSISTENCE specifically: rule present, no dedicated sample yet |
| S6 | Prompt-injection wording in skill text: hidden or deceptive instructions outside the skill's stated purpose, "ignore previous instructions"-style overrides, fake system-message framing, Unicode/base64-smuggled instructions | **Partial** | — (no prompt-injection rule exists) | Only the encoding half is visible: if the smuggled text uses base64 in a scannable file, BASE64_OBFUSCATION fires at most (CAUTION in documentation). No existing sample exercises instruction-override wording, and no rule judges whether prose is *deceptive* — that is a semantic judgement a regex rule set does not make |
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
| I1 | A tool's *description* (text the model reads but the user barely sees) secretly instructs the model to read sensitive local files — client config, SSH keys — and smuggle the contents back inside an ordinary-looking tool argument | **Gap** | — (MCP_UNRESTRICTED_EXEC / MCP_UNRESTRICTED_READ examine a manifest's declared tool *shape*, not the meaning of its description text) | No existing sample exercises description-text instructions; `samples-mutations/09-mcp-manifest` proves only the structural side (BLOCK; MCP_UNRESTRICTED_EXEC + MCP_UNRESTRICTED_READ fire on an unconstrained tool declaration). Judging that description prose is *asking for something hidden* is semantic prompt-injection judgement — no rule attempts it |
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
  judge on would change the tool's core guarantee. This is the single
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
- **S3, S4, S5, K5 (evidence gaps)** — rules exist and fire in code, but
  the corpus has no dedicated sample for the prose form (S3, S4, S5) or
  the exact end-to-end shape (K5), so those mappings are asserted by rule
  inspection, not by a test. They are labelled that way in the tables
  rather than upgraded to "Covered".

### F. Runtime behaviour (already stated in the README, repeated for completeness)
- Behaviour decided by a server response, the date, or an encrypted config
  is invisible to any static scan; strong packing beyond base64/hex is
  flagged at most as obfuscation; value-level taint tracking across files
  is not performed (EXFIL_COMBINATION works at skill level, not value
  level).

---

*Map compiled from the four audits above and the scanner source
(`skillscan/rules.py`, `skillscan/scanner.py`) and test suites as of
v0.2.0. If a rule or a sample changes, this map must change with it — a
coverage claim without a suite behind it is exactly the kind of thing
this document exists to prevent.*
