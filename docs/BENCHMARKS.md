# Benchmarks — methodology and full results

SkillScan's measured detection and false-positive rates on a public
labelled corpus. These are SkillScan's own numbers, published as
measured — including the families where the rates are poor. Last run:
**2026-11-10**, scanner **SkillScan v0.5.0** (57 deterministic rules).

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
- Median scan time was ~80 ms per malicious skill and ~43 ms per
  benign skill.

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
| Malicious | 7,421 | 3,395 | 2,722 | 1,304 | **45.7%** | **82.4%** |
| Benign | 2,235 | 0 | 555 | 1,680 | false BLOCK **0%** | flagged 24.8% |

What changed from v0.4, stated exactly: BLOCK detection is identical
in every labelled attack family below; across the whole malicious
set, one previously-CAUTION uncategorised skill moved to BLOCK and
47 previously-PASS skills moved to CAUTION, and no skill's verdict
got weaker. The v0.5 gain is breadth at CAUTION (new prose-chain,
output-manipulation and value-flow rules), not strict detection.

### Detection by attack family (membership basis)

| Family | n | BLOCK | BLOCK+CAUTION |
|---|---|---|---|
| privilege_tool_authority_abuse | 1,004 | 74.4% | 99.4% |
| execution_code_delivery | 3,205 | 74.1% | 97.9% |
| credential_access | 197 | 55.3% | 95.9% |
| persistence_control | 249 | 55.0% | 90.0% |
| instruction_goal_memory_manipulation | 1,560 | 63.9% | 86.2% |
| data_exfiltration_disclosure | 266 | 35.0% | 83.8% |
| resource_availability_abuse | 330 | 22.7% | 90.3% |
| dependency_supply_chain | 167 | 13.2% | 87.4% |
| defense_evasion_obfuscation | 20 | 10.0% | 100% |
| integrity_output_manipulation | 97 | 1.0% | 28.9% |
| discovery_reconnaissance | 5 | 0.0% | 20.0% |
| (no category assigned) | 2,591 | 24.5% | 67.6% |

Two membership figures need their honest footnotes:

- *Instruction/goal manipulation* looks respectable on a membership
  basis because most of those skills also carry code-shaped labels.
  Among **pure** instruction-manipulation skills (single category,
  prose payloads, n=365), BLOCK is **8.8%** and BLOCK+CAUTION 45.2%.
- *Output manipulation* is near-blind in both views: pure
  single-category BLOCK 1.2%, BLOCK+CAUTION 28.6%.

### Benign side in detail

- False BLOCKs: **0 of 2,235 (0%)**, as in v0.4. v0.3 measured 15
  false BLOCKs (0.67%) — a regression caused by `SUBSTITUTION_EXEC`
  firing at block severity on command-substitution examples inside
  benign prose documentation. v0.4 capped inert text (comments,
  string literals, documentation examples) below block severity,
  the regression was fully reversed on the same benign set, and
  v0.5 holds at zero.
- CAUTIONs: 555 (24.8%), up from 498 (22.3%) in v0.4. The increase
  is the new v0.5 coverage firing at caution severity on benign
  prose: `PROSE_READ_SEND` (60 skills), `PROSE_INSTRUCTION_EN` (27),
  `PROSE_FETCH_EXECUTE` (16), `PROSE_PIPE_INSTRUCTION` (15) and
  `OUTPUT_MANIPULATION` (4). The top driver overall remains
  `PROSE_DOWNLOAD_RUN` (290 skills, 13.0% of all benign): prose
  that joins an external download with a run step.

## Limitations

- **Most misses are prose-only skills.** Of the 1,304 malicious
  skills that PASSed, 886 are a single `SKILL.md` with no code:
  install lures pointing at external archives, pure instruction/goal
  manipulation, and output manipulation. A deterministic folder
  scanner sees behaviour shapes in code and text mechanics; it does
  not understand what prose *means*, and these numbers show exactly
  where that boundary sits.
- **Code-bearing misses exist too.** 239 missed folders contain
  code. The dominant shape is a small reader-helper script that
  reads local files and returns their contents, with the onward
  send performed by the agent following the prose — the exfiltration
  channel is outside the folder's code. Part of the class is pure
  transformation code structurally indistinguishable from benign
  utilities.
- **Asymmetry caveat.** Malicious skills were scanned as full
  packages (code included); benign skills as prose-only folders.
  That mirrors how SkillScan is used (scan the folder you were
  given), but it means the benign false-positive figure measures
  prose-triggered false BLOCKs, not code-triggered ones.
- **Manifest shapes are rare in this corpus.** Only ~5.7% of the
  malicious folders carry any manifest-style file at all, and no
  URL/VCS dependency specs appear in it — so the
  dependency/supply-chain family's low BLOCK rate is mostly a
  severity-policy question about install instructions, and these
  results say little about manifest-heavy real-world folders either
  way.
- **Corpus dependence.** These rates are properties of this corpus
  at this pinned revision and this scanner version. A different
  corpus will give different numbers; the pinned commits above are
  what make this run reproducible and falsifiable.
