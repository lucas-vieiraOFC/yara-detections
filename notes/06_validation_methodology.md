# 06 — Validation Methodology (fixing the paper's evaluation gaps)

The paper reports 93.8 % TPR / 0.006 % FPR over 25 malware samples and "50,000
NSRL clean files". Research (see `03` §3) surfaced four methodological problems
and the material to fix them. This document is the validation protocol for the
expanded rule set (`rules/sride_stealer.yar` + `tools/sride_triage.py`).

## 1. Corpus construction — what "clean" actually means

**Problem found:** NSRL RDS distributes **hashes, not files** (NIST Special
Database 28; `rds_modernm.zip`). "50 k NSRL clean files" as printed is
methodologically impossible; what the authors likely did is collect files and
*verify* them against RDS. The protocol must say so.

Clean corpus (target n ≥ 10 000, strata recorded):
- OS system files (fresh Windows 10/11 installs, `C:\Windows\System32`, SysWOW64),
  verified against RDS hashes where possible.
- **Adversarial-clean strata** (the FP surface that actually matters):
  - NSIS/Inno/MSI installers (high-entropy compressed payloads),
  - games/media apps (PNG/JPEG in `.rsrc`, Authenticode overlays),
  - commercial protectors (Themida/VMProtect/Enigma legitimate users, Steam),
  - UPX-packed legitimate tools,
  - **statically linked Rust and Go utilities** (ripgrep, fd, cargo tools,
    rclone, restic) — the exact background for the toolchain and entropy rules;
    the paper's corpus apparently contained few of these, and `05` §5 shows why
    they matter (byte-level ROP idioms fire on megabyte Rust `.text`).
- Developer workstations' `System32\drivers`, .NET assemblies (BSJB), Python
  bundles (PyInstaller).

Malware corpus:
- The 4 in-repo families (positives for family rules) + the 5 paper families
  (AsyncRAT, NjRAT, custom C2, UPX banking trojan, shellcode dropper) — pull
  additional samples per family from MalwareBazaar/MalShare/VX-Underground;
  target n ≥ 30 per family so per-family TPR has meaning (see §3).
- **ROP-positive controls** (the paper lacked these entirely!): the synthetic
  chain PEs from `tools/make_chain_test_pe.py` (extend: vary arch, section
  placement, immediate density, chain length 3–20, junk insertion) — a
  generator script producing hundreds of parameterized positives costs an hour
  and removes the "did anyone ever test a real chain?" question.
- **Transformed-ROP controls**: run ROPInjector on a stock shellcode + carrier
  PE, and ROPfuscator's demo — validating against *transformed output*, the
  paper's stated hard case, which its evaluation never includes.
- SOREL-20M / EMBER-2018 for scale; EMBER2024 for label-noise-aware reference
  (CrowdStrike 2025 documents EMBER label noise explicitly).

## 2. Ground truth and leakage control

- **Temporal split** (TESSERACT, Pendlebury et al., USENIX Sec 2019): rules must
  be written from samples *older* than the evaluation samples where both exist.
  State each rule's authoring sample set in metadata (`sample =` fields already
  started in `rules/sride_stealer.yar`).
- **Family disjointness**: no two corpus samples from the same campaign build
  counted as independent detections (hash-dedupe, then TLSH/ssdeep cluster
  near-dupes at threshold; report both raw and deduped TPR).
- **Rule-vs-sample independence**: the sample a rule was authored from is a
  *training* point, not a detection — report TPR with authored samples excluded.
- **Inter-rule dedup**: aggregate TPR counts a sample once even when generic +
  family rules both fire (the paper's aggregate 93.8 % appears to double-count
  its generic/family overlap).
- Chain-scan ground truth: a run is a true positive only if manual disassembly
  (Ghidra) confirms pivot/spine/terminator *semantics*, per D'Elia et al.
  (EuroSec 2019) reconstruction methodology.

## 3. Statistics — stop reporting 0.1 %-precision numbers on n=5

- Report **Wilson score confidence intervals** (95 %) with every TPR/FPR.
  At n=5/family, one miss moves TPR by 20 pp; the paper's "96.0 %" on 25
  samples has a Wilson interval roughly ±8–15 pp per family. With n=30,
  ±7–12 pp. Precision follows from n — choose n first.
- FPR on 50 k clean files: an observed 0.006 % = 3 files. Report the count,
  not just the percentage, and **name the FP files** (which stratum?) — the
  installer/protector strata will dominate.
- Scan-cost reporting: samples/s and peak RSS per rule tier (family vs hunting),
  measured with panopticon-style per-rule timing; the paper's 1 157 samples/s
  is fine to keep but should be split by rule, since short-atom rules dominate
  cost (the `{ 94 }` class problem, `03` §3).
- Rule quality gate: run **yaraQA** + YARA-Forge scoring
  (quality ≥ 70 target) over the rule file; record atom-length warnings (the
  current file carries 7 documented short-atom warnings on hunting-tier rules —
  acceptable if labeled, fatal if shipped silently).

## 4. Scoring model for the fused detector

Flat hand-tuned weights (detect.c) → evidence-tiered score:

| Tier | Evidence | Score policy |
|---|---|---|
| identity | exact SHA-256 / TLSH ≤ 10 | verdict alone |
| family-durable | campaign key/seed, build path, protocol state labels, crate-stack combination | 2+ anchors → verdict; 1 → suspicious |
| structural | verified chain (class 0), per-section entropy + packer marker, reflective-load profile | verdict only with a corroborating tier; alone → suspicious |
| provenance | rustc/crate fingerprints, obfuscator presence | never verdict alone; multiplier on others |
| expiring IOC | C2 domains/IPs, webhook strings | corroboration; half-life noted in metadata |

Negative weights for known-goodware collisions (e.g., `0x9E3779B9` alone,
`leave;ret` alone) — the formal vocabulary is Canfora et al.'s *robustness*
(variant coverage) vs *looseness* (FP propensity), ICTSS 2020.

## 5. Variant-tracking layer (beyond exact hashes)

For the "one rebuild kills the hash" problem (`02` W2):
- **TLSH** (Oliver et al., CTC 2013) and **ssdeep** (Kornblum, DFRWS 2006)
  file-level digests per family seed; **per-section ssdeep** (Shiel & Pan,
  DFRWS EU 2019) for packed samples.
- **imphash is nearly useless on Rust/Go** (static linking → no meaningful
  import table; confirmed by Cyber Triage 2024 and the malwaredb/imphash
  notes) — for these families use the **dependency imphash** (sorted crate
  list hash, rustbininfo-style) instead. impfuzzy (JPCERT/CC 2016) for
  C/C++ families.
- **Rich-header hash** for the MSVC stage-1 loaders (Kaspersky GReAT 2018;
  Poslušný & Kalnai, VB2019).
- **binlex** trait hashes as the modern structural option; a binlex-style trait
  over *gadget byte sequences* is a defensible novel extension.
- YARIX (USENIX Sec 2021) as the indexing layer once rule matches exist at
  scale.

## 6. Regression harness (concrete)

```
research/validation/
  corpus/{clean,malware,controls}/...        (hashes pinned in manifest.json)
  run_scan.py      — yara (classic AND YARA-X) + triage tool over corpus,
                     emits per-file JSON (rules hit, tier scores, timings)
  score.py         — Wilson CIs, per-stratum FP analysis, dedup-aware TPR,
                     YARA-Forge/yaraQA quality gate, markdown report
  gen_controls.py  — parameterized synthetic chains (extends make_chain_test_pe)
```

CI gate: any rule change must keep (a) family-rule FPR = 0 on the clean corpus,
(b) control-suite TPR = 100 %, (c) hunting-tier warnings explicitly labeled.
Differential run on both engines (classic 4.5.7 + YARA-X 1.x) with match-set
diff reported — the two engines *will* diverge on edge cases (YARA-X's stricter
regex and `of` semantics), and silent divergence is a reproducibility hazard.

## 7. What honest numbers will probably look like

Based on the local experiments (`05`): family rules should hold ~100 % TPR at
~0 FPR on in-family samples (they key on multiple durable anchors); the
chain-pointer verifier should hold 100 % on synthetic positives with FPR driven
to ~0 by the spine-shape + `.pdata` filters on x64, with x86 Windows remaining
the hard case (no `.pdata`); the byte-level generic ROP rules will show
measurable FP on the Rust/Go strata — publish that number, don't tune it away;
it's the empirical motivation for the pipeline approach.
