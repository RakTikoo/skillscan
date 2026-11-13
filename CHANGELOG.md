# Changelog

All notable changes to SkillScan, newest first. Versions follow the
scanner's own `__version__`; every release below passed the full test
suites and an adversarial review before it was pushed.

## v0.7.0 — 2026-11-13

Stage 1 of the LLM mode, built at the owner's direction. The
deterministic rule count is unchanged (59) and offline mode — the
default — is byte-for-byte v0.6.0 behaviour. What is new is an
optional, clearly demarcated second mode:

- `--llm` flag, with `--llm-model` and `--llm-base-url`. After the
  offline scan, the skill's prose (SKILL.md and markdown/docs —
  never code) is sent to an OpenAI-compatible chat provider
  (default: Groq free tier, `qwen/qwen3.8-27b`) for a second
  opinion on semantic prose steering — the output-manipulation
  family the deterministic rules measurably cannot finish — plus
  a second opinion on files whose prose already drew a
  deterministic CAUTION.
- Additive only: the model can add an `LLM_STEERING` finding
  (CAUTION or BLOCK per a fixed rubric). It can never clear,
  downgrade, or alter an offline finding or verdict. Combined
  verdict = max(offline, llm), labelled with its source in every
  format; JSON keeps the offline fields unchanged and adds one
  `llm` object; the exit code follows the combined verdict.
- Hardening for a hostile judge target: scanned prose is sent as
  delimited untrusted data; the judge must answer in a fixed JSON
  schema (off-schema responses are discarded); a steering claim
  applies only when its evidence quote is verifiably present in
  the text sent (quote grounding, drops reported); temperature 0;
  one file per call under byte caps.
- Failure discipline: missing key (environment only —
  `SKILLSCAN_LLM_API_KEY`, fallback `GROQ_API_KEY`), network
  error, timeout, HTTP error, or garbage response → the LLM
  section reports UNAVAILABLE and the offline verdict and exit
  code stand. Hard timeouts, a failure circuit breaker, and a
  review wall-clock budget; the key is never printed, logged, or
  written to disk. Standard library only.
- Regression suite run_v07_tests.py uses an in-process stub
  provider (no live API): schema discipline, quote grounding,
  injection-shaped prose, timeout / HTTP-error / key-leak paths,
  partial-coverage reporting, and all four report formats.
  Live-model accuracy was unmeasured at stage 1; the measured
  results and the one open item are recorded at the end of this
  entry.
- Stage-2 adversarial review fix wave (three independent reviews —
  judge red team, false-positive/weak-model review, code audit —
  all findings addressed before any live measurement):
  cross-host redirects are now refused, so the API key can never
  be forwarded to a different host on a 30x; coverage reporting is
  honest at chunk granularity (a file counts as reviewed only when
  every chunk of it was judged — chunk-cap, file-cap and mid-file
  budget truncations name the file with chunk counts and make the
  review "partial"); each chunk call carries a context header
  (file, chunk k of n, the skill's own description); quote
  grounding is markdown/punctuation-insensitive and requires a
  substantive quote (block tier ≥4 words and ≥25 chars, caution
  ≥3 words); the verdict parser accepts only a bare JSON object
  (optionally fenced); `llm.verdict` is null when the review was
  unavailable or fully reviewed nothing, in JSON and SARIF alike;
  the size budget counts attempted sends, and failure reporting
  distinguishes provider-unreachable from unusable-responses. The
  judge rubric was rewritten for a weak model: disguised-promotion
  and materiality tests, a bulleted NOT-steering list (quoted /
  taught / detected attacks, sample prompts for other tools,
  confidentiality, persona/formatting rules, own-business
  marketing, scope-routing, creative work), hard benign few-shot
  examples, a block-tier tie-break (unsure whether the user is
  deceived → not steering), a judge-by-meaning line, and an
  any-language instruction. Regression suite is now 85 checks;
  the judge red-team battery holds 19 of 22 attacks (the three
  that remain are judge-behaviour questions — a fully parroting
  judge, negation blindness, chunk-boundary layout — that the
  live-model measurement exists to price).
- Provider requests now carry an explicit product User-Agent
  (`SkillScan/<version> (+https://github.com/RakTikoo/skillscan)`,
  version read from the package). Found live, 2026-11-12:
  Cloudflare-fronted providers (Groq included) reject the stock
  Python-urllib signature with error 1010 — an HTTP 403
  indistinguishable from a rejected key (an unauthenticated
  control request returns the identical 403). The regression
  suite asserts the header is sent and is never the urllib
  default.
- The LLM client is provider-neutral: one OpenAI-compatible
  chat-completions call driven only by base URL + model + key,
  with no provider-specific code path. The defaults are the
  reference preset (Groq free tier, `llama-3.1-8b-instant`); the
  README documents the preset matrix (Groq, OpenRouter `:free`,
  Cerebras, Gemini's OpenAI-compatible endpoint, OpenAI, and
  local Ollama / LM Studio / vLLM servers). `GROQ_API_KEY` is
  honoured only when the configured endpoint is Groq's — a Groq
  key is never sent to another host (regression-tested).
  Regression suite is now 93 checks.
- Fix wave 2 (from the first live smoke, 2026-11-12): the
  completion budget is now 1024 tokens by default and configurable
  (`SKILLSCAN_LLM_MAX_TOKENS`, clamped 16–16384). The stage-1
  client's fixed 200-token cap starved reasoning judges — a
  reasoning model's thinking counts against the same budget, and
  the observed failure was 198 of 200 tokens spent reasoning and
  empty content returned. Only the reply's `content` is parsed
  (reasoning carried in a separate field is ignored), and empty
  content is now explicitly an unusable response with the usual
  partial/UNAVAILABLE semantics, never a verdict. Regression
  suite is now 103 checks, including reasoning-envelope and
  empty-content stub judges. The stale Groq default model id
  (`llama-3.1-8b-instant` returns model_not_found on Groq today)
  is deliberately NOT changed in this wave: its replacement is
  chosen by a controlled bake-off between the account's current
  small models, and that bake-off stopped on a provider 429
  before it could decide (see the measurement record).
- Default model decided (bake-off completed 2026-11-12): the
  reference-preset default is now `qwen/qwen3.8-27b`, replacing
  the retired `llama-3.1-8b-instant`. In the controlled bake-off
  (20 dev-exposed output-manipulation misses + the 21
  false-positive trace folders, judged under the frozen rubric),
  qwen/qwen3.8-27b returned schema-valid verdicts on all 20
  misses (5 caught: 4 CAUTION + 1 BLOCK) and read the one trace
  it completed clean, with zero false BLOCKs. The measured
  alternates: `openai/gpt-oss-20b` on the same Groq preset
  (6 of 20 caught, one CAUTION of benign-discipline noise on the
  trace set, zero false BLOCKs) and `gemini-3.5-flash-lite` on
  Gemini's endpoint (20/20 schema-valid, 4 of 20 caught, trace
  set not reached before its free-tier lane stopped). Full-set
  rates (Set A / Set B, held-out first) remain to be measured;
  see the measurement record for exact coverage and limits.
- Live measurement (2026-11-12/13, MaliciousSkillBench
  output-manipulation family plus a 280-skill benign sample;
  held-out figures first). Design-ceiling run with a current
  frontier model as judge (full sets, 697 calls, 100%
  schema-valid): family BLOCK+CAUTION 28.9% → 54.6%, BLOCK
  1.0% → 19.6%; benign false BLOCKs 0 of 280. Weak free-tier
  judges on held-out Set A (77 skills): gemini-3.5-flash-lite
  judged 73 — BLOCK+CAUTION 37.0% → 53.4% on the skills it
  judged, BLOCK 1 → 6; the default qwen/qwen3.8-27b judged 44
  before its free-tier budget stopped it — 34.1% → 43.2%,
  BLOCK 1 → 4, its catches overlapping Gemini's. No ungrounded
  claim survived the grounding gate in any weak-judge run.
- What remains open at release: the benign set (Set B, 280
  skills) has not yet been judged by a weak free-tier model.
  Its corpus-scale run is scheduled for 2026-11-14, and until
  it reports, the zero-false-BLOCK figure above is a
  current-model result and the simpler-model benign check is
  still ongoing. The deterministic benchmark figures in the
  README are offline-mode numbers and are unchanged by this
  release.

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
