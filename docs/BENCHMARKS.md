# Benchmarks — methodology and full results

SkillScan's measured detection and false-positive rates on a public
labelled corpus. These are SkillScan's own numbers, published as
measured — including the families where the rates are poor and a
false-positive regression in the current version. Last run:
**2026-11-10**, scanner **SkillScan v0.3.0** (41 deterministic rules).

## Corpus

**MaliciousSkillBench** — an academic benchmark consolidating 13
public sources into 9,740 labelled skills: **7,505 malicious /
2,235 benign**, with harmonised attack-category labels assigned to a
subset of the malicious side.

- GitHub: https://github.com/protectskills/MaliciousSkillBench
  pinned at commit `893afd609be22a2dfac5a2b94bbebb4eeb99515e`
  (2026-08-22).
- Hugging Face: https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench
  pinned at revision `d4b42ce5766a6e0359c987cf59c1007cb3795a90`
  (`primary.parquet`, used for benign texts and label metadata).
- Licence/terms as stated in the corpus repository: code Apache-2.0;
  benchmark-authored metadata/annotations CC BY 4.0; third-party skill
  artifacts retain their upstream terms, and a responsible-use
  document governs the malicious artifacts. The corpus is used for
  measurement only.

## How the run was done

- *Malicious side:* the corpus's per-source package archives were
  extracted (path-safe extraction, no execution) into real folder
  trees, and each skill folder was scanned individually. 7,421 of
  7,505 malicious skills have an extracted package tree and were run;
  the remaining 84 are text-only/sanitised records with no package
  tree and were not run.
- *Benign side:* the benchmark does not ship benign package trees; it
  ships frozen skill text. Each benign identity's frozen text was
  materialised as a single `SKILL.md` in its own folder, and all
  2,235 were scanned that way.
- SkillScan interacted with every sample by reading it as text only.
  Nothing was executed, installed, imported, or uploaded. The scanner
  produced zero errors across all 9,656 scans.
- Median scan time was ~90 ms per malicious skill (v0.3's file-wide
  passes roughly doubled the per-skill cost versus the previous
  version).

## Counting rules

- Corpus label *malicious*: a **BLOCK** verdict counts as strict
  detection; **BLOCK or CAUTION** counts as loose detection.
- Corpus label *benign*: a **BLOCK** verdict counts as a false
  positive; a **CAUTION** verdict counts as a soft flag and is
  reported separately, not as a false positive.
- Attack-family breakdowns use the corpus's harmonised category
  field. Families are multi-label: a skill counts in every family it
  carries ("membership basis"). Where a family's membership number
  flatters the result, the pure single-category figure is stated
  alongside.

## Results

### Headline

| Set | n | BLOCK | CAUTION | PASS | Detection (BLOCK) | Detection (BLOCK+CAUTION) |
|---|---|---|---|---|---|---|
| Malicious | 7,421 | 3,409 | 2,659 | 1,353 | **45.9%** | **81.8%** |
| Benign | 2,235 | 15 | 578 | 1,642 | false BLOCK **0.67%** | flagged 26.5% |

### Detection by attack family (membership basis)

| Family | n | BLOCK | BLOCK+CAUTION |
|---|---|---|---|
| privilege_tool_authority_abuse | 1,004 | 74.6% | 99.1% |
| execution_code_delivery | 3,205 | 74.2% | 95.6% |
| credential_access | 197 | 55.8% | 94.9% |
| persistence_control | 249 | 55.4% | 90.0% |
| instruction_goal_memory_manipulation | 1,560 | 63.7% | 87.8% |
| data_exfiltration_disclosure | 266 | 35.3% | 82.3% |
| resource_availability_abuse | 330 | 22.7% | 91.2% |
| dependency_supply_chain | 167 | 12.0% | 88.6% |
| defense_evasion_obfuscation | 20 | 10.0% | 100% |
| integrity_output_manipulation | 97 | 1.0% | 32.0% |
| discovery_reconnaissance | 5 | 0.0% | 60.0% |
| (no category assigned) | 2,591 | 24.7% | 67.6% |

Two membership figures need their honest footnotes:

- *Instruction/goal manipulation* looks respectable on a membership
  basis because most of those skills also carry code-shaped labels.
  Among **pure** instruction-manipulation skills (single category,
  prose payloads, n=365), BLOCK is **9.0%** and BLOCK+CAUTION ~51.8%.
- *Output manipulation* is near-blind in both views: pure
  single-category BLOCK 1.2%, BLOCK+CAUTION ~31%.

### Benign side in detail

- False BLOCKs: **15 of 2,235 (0.67%)** — a regression in v0.3. Every
  one is a single rule, `SUBSTITUTION_EXEC`, firing at block severity
  on command-substitution examples inside benign prose documentation
  (install docs with shell code fences are the typical shape). A fix
  is in progress; the rate is published as measured.
- CAUTIONs: 578 (25.9%). The top driver is `RUNTIME_PACKAGE_INSTALL`
  (395 skills, 17.7% of all benign): documentation prose that tells
  the user to install a named package. That is a deliberate caution —
  install instructions are also the classic lure shape — but it is
  the largest single source of review burden and a known refinement
  candidate.

## Limitations

- **Most misses are prose-only skills.** Of the 1,353 malicious
  skills that PASSed, 984 are a single `SKILL.md` with no code:
  install lures pointing at external archives, pure instruction/goal
  manipulation, and output manipulation. A deterministic folder
  scanner sees behaviour shapes in code and text mechanics; it does
  not understand what prose *means*, and these numbers show exactly
  where that boundary sits.
- **Code-bearing misses exist too.** 193 missed folders contain code.
  The dominant shape is a small reader-helper script that reads local
  files and returns their contents, with the onward send performed by
  the agent following the prose — the exfiltration channel is outside
  the folder's code. A third of the class is pure transformation code
  structurally indistinguishable from benign utilities.
- **Asymmetry caveat.** Malicious skills were scanned as full
  packages (code included); benign skills as prose-only folders. That
  mirrors how SkillScan is used (scan the folder you were given), but
  it means the benign false-positive figure measures prose-triggered
  false BLOCKs, not code-triggered ones.
- **Manifest shapes are rare in this corpus.** Only ~5.7% of the
  malicious folders carry any manifest-style file at all, and no
  URL/VCS dependency specs appear in it — so the
  dependency/supply-chain family's low BLOCK rate is mostly a
  severity-policy question about install instructions, and these
  results say little about manifest-heavy real-world folders either
  way.
- **Corpus dependence.** These rates are properties of this corpus at
  this pinned revision and this scanner version. A different corpus
  will give different numbers; the pinned commits above are what make
  this run reproducible and falsifiable.
