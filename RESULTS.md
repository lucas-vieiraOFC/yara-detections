# Revision run record — every number in the revised paper, and where it came from

All scans: YARA 4.5.7 (CLI) and YARA-X 1.19.0 (`yr`, official release binary), on
Arch Linux x86_64, Python 3.14.6, capstone 5.0.7, pefile 2024.8.26.
Frozen digests (see ENVIRONMENT.txt):
- rules tree (rules_v4.yar):    c3e6110ac88fcfbcfaf442aaeca47bb0c08d513ddb31cd96d843c1f455ffc8cf
- verifier tree (sride_triage.py + make_chain_test_pe.py): 4ebac58f7f5180f55634649908939a228e4861fe44549b70fbfdb951bf315730

## 1. Reproduction of the v3 external scan
`scan_revision.py`, orig arm vs ../corpus_results.csv: 59/59 files identical, 0 mismatches.
v3 generic rule: 32/56 malware (57.1% [44.1, 69.2]).

## 2. Corrected rule set (rules_v4.yar)
Changes: Rule 1 proximity over all four pivot classes + any spine element;
$pivot_pop {5C C3}; $term_syscall {0F 05 C3}; guard 5MB; Rule 4 port removed;
Rule 5a UPX0/UPX1 section-name fix (v3 anchors ".UPX0" could never fire on real
UPX output — verified against putty-upx.exe: sections are UPX0/UPX1/.rsrc);
Rule 2 packed track demoted to hunting tier in metadata; Rule 3 relabelled.
Results (external_rules_v4.csv):
- generic v4: 34/56 malware = 60.7% [47.6, 72.4]; gained Carberp (packed) and
  one Fareit sample, both non-XCHG pivots — direct evidence the v3 defect bound.
- sets with >=1 generic hit: 19 of 22 archive family sets (was 18 of 22).
- family rules: 3 external malware hits (IllusionBot builder, Hupigon via
  AsyncRAT unpacked track; njRAT v0.6.4 builder via NjRAT rule) + putty-upx
  (clean) via Rule 2 packed track and, post-fix, Rule 5a.
- clean PE controls: all 3 match the generic rule (FP surface as reported in v3 Q3).

## 3. Entropy two-track ablation (replaces v3 Table VI)
external_ablation.csv: pattern-only arm vs two-track arm — file-level outcomes
identical on all 59 files. Packed external malware files: 16. Recovered by the
entropy track: 0/16 (95% upper 19.4%). Packed track's only external firing:
clean UPX-packed PuTTY. Run `python3 -m ropkit.audit_arms external_ablation.csv`.

## 4. Base-rate null models (review defect S7)
`python3 -m ropkit.nullmodel --source ../../corpus/clean --out null` (3 sources,
9 null files). Generic rule fires on 3/3 shuffled, 3/3 random, 3/3 entropy
nulls (100% [43.8, 100] per class). AsyncRAT packed track + Rule 5a fire on the
putty-upx-derived nulls (PE head with UPX section names is preserved by
construction). Verifier: 0 verified chains on all 9 nulls. Small-n: reported as
a pilot base rate with rule-of-three bounds.

## 5. Parameter sensitivity (review defect S6), 59 files
- Proximity window (bytes): 64->36, 128->37, 256->37, 512->37, 1024->37 hits.
  Chosen 256 is on the plateau; 64 loses one file.
- Spine threshold k-of-6: 2->43, 3->37, 4->34, 5->32. Chosen 3-of-6.
- Entropy threshold (Rules 2 packed track + 5a): 6.5->2/1 fires, 6.8..7.5->3/1.
  Chosen 7.0 is on the plateau; 6.5 loses one unpacked-track detection.

## 6. Verifier (sride_triage.py --chain-scan)
- 59/59 real PE binaries: 0 verified chains (95% upper bound 6.1%). Up to 311
  candidate runs on a single Rust binary, all rejected (jump-table/vtable/.pdata).
- Synthetic positives (controls/): chains of 3, 4, 5 and 8 gadgets all verified;
  3 gadgets is the floor of spine shape B. chain5 == chain_orig byte-identical
  (sha256 ccdc814f…): the original five-gadget control reproduces.
- Negative controls: vtable run rejected; all 9 null-model files rejected.
- Placement: .data verified; .rdata with interleaved immediates verified.
  Blind spots measured: unaligned (+2 bytes) chain missed (aligned pointer grid);
  chain split across two sections demoted to candidate (neither half verifies
  alone). Both consistent with the threat-model non-goals; now measured.

## 7. Dual-engine compatibility
v3 and v4 rule sets compile under YARA 4.5.7 and YARA-X 1.19.0 (warnings only:
single-byte atoms, loop ranges, deprecated pe.number_of_sections). Match sets
identical on all 73 files (59 corpus + 5 controls + 9 nulls), both engines.

## 8. Community indicator baseline + longitudinal decay (review Exp. C)
YARA-Forge core package, release 20260816 (5034 rules; repo now
YARAHQ/yara-forge). Same-family scoring: a file counts as indicator-detected
iff at least one fired rule's name matches its family (Bladabindi scored under
njrat). Any-rule hits: 7/56 files, all same-family. external_decay.csv ->
`python3 -m ropkit.decay external_decay.csv --bin-width 5`:
  era        n   structural [CI]          indicator [CI]
  2007-2011  5   100.0 [56.6,100.0]       20.0 [3.6,62.4]
  2012-2016  45   53.3  [39.1,67.1]       13.3 [6.3,26.2]
  2017-2021  2*  100.0 [34.2,100.0]       0.0  [0.0,65.8]   * thin
  2022-2026  4*  75.0  [30.1,95.4]        0.0  [0.0,49.0]   * thin
Overall: structural 34/56 = 60.7% [47.6,72.4]; indicator 7/56 = 12.5% [6.2,23.6].
Years = archive-documented first-seen per family/batch; thin bins reported but
not interpreted; no trend line fitted.

## 9. Throughput (relative loop cost of the corrected Rule 1)
Per-file yara CLI spawn, 59 files: v3 set 98 files/s, v4 set 92 files/s
(~7% cost of the four-class proximity loops; absolute numbers are
spawn-dominated and not comparable to the batch-scan figure).

## 10. Development (fitting) table — retained, relabelled
Per-family Wilson CIs recomputed by `python3 -m ropkit.stats` (self-test PASSED,
reproduces all eight intervals printed in v3): Generic 88.0 [76.2,94.4]
(44/50), AsyncRAT 96.0 [86.5,98.9] (48/50), njRAT 100.0 [88.6,100.0] (30/30),
Custom C2 90.0 [59.6,98.2] (9/10), BankUPX 100.0 [83.9,100.0] (20/20),
BankPay 90.0 [69.9,97.2] (18/20); family mean 93.8; pooled 169/180 = 93.9
[89.4,96.6] (footnote only). v3 Table VI did not reconcile with its own packed
counts (2/3/1 packed vs claimed gains of 8.0/5.7/2.0 samples; 71.4% of 20 is
not an integer) and is replaced by the count framing + item 3 above.

## 7. v5 rule set (ROP-only) — 2026-08-17

Rules: `../../rules/sride_rules_v5.yar` (canonical), frozen copies at
`rules_v5.yar` and `frozen/rules/sride_rules_v5.yar`. Scan driver:
`scan_v5.py`. Changes from v4: every indicator/string anchor removed
(hollowing API triad, UPX magic + section names, BSJB CLR marker, persistence
string, rolling-XOR constant, bank targets, TLS hook); Rule 5a withdrawn (no
ROP content; entropy-gated tracks showed no held-out benefit, §3 above);
Rule 2 packed track removed, unpacked-track guard flagged experimental;
Rules 2/3/4/5b gained the ±256-byte pivot–spine proximity anchor. Rule 1
byte-identical to v4.

Frozen digests (same construction as ENVIRONMENT.txt):
- rules tree v5 (sride_rules_v5.yar): 14191ff276bb330a57c6fadf0fe6634d65f8075e37b9ac5089cf2c21648c5b72
- verifier tree (unchanged):         4ebac58f7f5180f55634649908939a228e4861fe44549b70fbfdb951bf315730
- v4 rules tree (unchanged):         c3e6110ac88fcfbcfaf442aaeca47bb0c08d513ddb31cd96d843c1f455ffc8cf

External corpus (external_rules_v5.csv, YARA 4.5.7):
- generic rule: 34/56 malware (unchanged, as required by the byte-identical
  rule); 3/3 clean PE controls; 9/9 null files; 5/5 synthetic controls.
- staging (non-generic) rules: 36/56 malware across 19/22 sets (not
  family-locked — the measured cost of indicator removal; v4 was 3/56).
  Per rule on the 59-file set: NjRAT-tuned triad 39 files (36 malware + 3
  clean), entropy-guarded staging 3 (IllusionBot Build, Hupigon, Taleret
  9b3c6f), banking-payload shape 1 (clean putty-upx), x64 syscall 0.
- clean controls: putty.exe, putty-upx.exe, 7z-install.exe each match the
  generic rule; staging hits as above.
- null model (9 files): generic 3/3 per class (unchanged); NjRAT triad 9/9;
  banking shape 3/9 (the putty.exe-derived null in each class); entropy-guarded
  staging and x64 syscall 0/9.
- synthetic controls: generic 5/5; x64 syscall rule 5/5 (controls carry
  SYSCALL;RET chains by construction).

Arms and engines:
- v4 arm re-verified against external_rules_v4.csv: 59/59 files, 0 mismatches.
- Dual-engine (YARA 4.5.7 vs YARA-X 1.19.0 `yr`) on all 73 files (59 corpus,
  5 controls, 9 nulls) for the v5 set: match sets identical, 0 mismatches.

Detection scripts (../../Detection_scripts/*.c): string-IOC signature arrays
removed; detection is now known-sample SHA-256 plus the same ROP structural
conjunction as Rule 1 (two-byte pivots only, 0x94 guarded out), reported at
hunting tier ("suspicious"), never as a verdict. Live Windows artifact checks
(behavioural, not strings) unchanged. All four build clean with
`gcc -O2 -Wall -Wextra`; SHA-256 implementation verified against the "abc"
test vector.

## 8. v5.1 corpus expansion + null-model expansion — 2026-08-17/18

Rule set unchanged from v5 (digests unchanged). All scans YARA 4.5.7 + YARA-X
1.19.0, drivers `scan_v5.py` + ad-hoc scripts as noted.

### 8.1 Era-bin expansion (review correction C3)
14 new malware binaries (11 families, 2019–2023) from the researcher-published
GitHub collection `jstrosch/malware-samples` (password-locked zips; static
handling only; per-file SHA-256 in `corpus_ext_new14.csv`). Staged into
`../../corpus/samples/`. MalwareBazaar was unreachable (401, API auth
required); the GitHub collection is the same provenance class as the existing
researcher-repo sets.

External corpus: 56 → 70 malware, 22 → 35 archive family sets.
- generic rule: 44/70 (62.9% [51.1, 73.2]); ≥1 hit in 29/35 sets. New-file
  misses: Raccoon (16.5 MB) and DCRat (22.6 MB) exceed the 5 MB size guard;
  TrickBot and CryptBot are genuine capability misses.
- staging rules: 46/70 (65.7% [54.0, 75.8]) across 29/35 sets.
- indicator arm (YARA-Forge core 20260816, strict same-family): 8/70 (11.4%
  [5.9, 21.0]); the only post-2016 hit is Vidar-2020. Three cross-family fires
  (Confuserex packer rule, Dlinjector03, Oski) not counted.
- decay table: 2007-2011 n=5 (5/5, 1/5); 2012-2016 n=45 (24/45, 6/45);
  2017-2021 n=11 (9/11 [52.3, 94.9], 1/11 [1.6, 37.7]); 2022-2026 n=9
  (6/9 [35.4, 87.9], 0/9 [0.0, 29.9]). No thin bins remain.
- verifier: 0 verified chains on all 14 new files (TrickBot had no candidate
  runs) → 0/73 real PE binaries (Wilson 95% upper 5.0%).
`external_rules_v5.csv` regenerated (73 corpus files); `external_decay.csv`
extended (14 rows).

### 8.2 Null-model expansion (review correction C2)
30 new clean PE sources from vendor sites (PuTTY suite ×5, Microsoft
Sysinternals ×20, 7-Zip standalone, UPX, Ninja, Python embeddable, SQLite)
plus the 3 existing controls → 33 sources × 3 transforms (shuffle / random /
entropy; 1024-byte PE head preserved, same file size) = 99 null files
(`null_manifest.csv` records every digest). Construction verified identical to
the v4 nulls (common 1024-byte head; histogram preserved under shuffle).

Generic rule: 32/33 shuffled (97.0% [84.7, 99.5]), 33/33 random, 33/33
entropy (98/99 pooled, 99.0% [94.5, 99.8]). Single escape: the smallest
source (python.exe, 103 KB) in the shuffled class — the size dependence the
paper predicts. Staging rules: NjRAT triad 95/99, banking shape 29/99,
entropy-guarded staging 12/99 (all shuffled-class: random/entropy bodies trip
the unpacked-track gate — the guard working as designed), x64 syscall 0/99.
Verifier: 0 verified chains on all 99.

### 8.3 Dual-engine
v5: 177 files (73 corpus + 5 controls + 99 nulls), 0 mismatches.
v3 and v4 rule files additionally verified on the 104 new files (14 corpus +
90 null): 0 mismatches each. Combined with §1/§6 above, both engines agree on
all 177 files for all three rule sets.

### 8.4 Editorial (review corrections C1, C5)
- Development fitting table moved to Appendix C (supplementary), labelled
  non-reproducible fitting diagnostic; §7.3 is now a pointer.
- Related-work search run 2026-08-17 across DBLP, Crossref, arXiv (three query
  families from the review): no uncited close prior art; nearest hits (STROP,
  Usui et al.) already cited. One tangential YARA-methodology citation added
  (Lockett 2021, arXiv:2111.13910). Reported in a footnote to Section 3;
  §7.11/§9.5 updated. Second screener remains future work.

## 9. Writing-consistency round (review of v5 printing): stale counts + ablation re-run
Review flagged five stale numbers, all residue of the 56-file corpus.

1. §7.6 ablation re-run on the expanded corpus (not just declared): the 14 new
   samples were scanned with `rules_v4.yar` vs `rules_v4_pattern_only.yar`
   (yara CLI, per-file). Arms identical on 13 of 14; on Vidar-2023 the
   pattern-only arm additionally fires `AsyncRAT_ROP_ProcessHollow` — the file
   is packed (H=7.66) but not UPX, so the v4 packed track's `UPX!` anchor
   cannot fire and the `_no_section_packed` guard suppresses the unpacked
   track: the gating is strictly counterproductive there. Combined with the
   59 v4-era rows: 20 packed malware binaries in 70, entropy track recovered
   0/20 (Wilson 95% upper 16.1%). Generic rule fires on 18/20 packed (misses:
   DCRat — 22.6 MB, beyond the 5 MB size guard; Bladabindi hostr — genuine
   pattern miss). `external_ablation.csv` extended to 73 rows (70 malware +
   3 clean).
2. Table external Packed total: rows sum to 20 (14 v4-era + 6 new: DCRat,
   Formbook ×2, GandCrab, NullMixer, Vidar-2023, per `corpus_ext_new14.csv`
   entropy measurement); printed total said 21 → fixed to 20.
3. "59-file" (§5.3 loop-cost timing) and "59/59" reproduction claims (§7.4,
   §7.11) now explicitly labelled v4-era corpus.
4. Abstract said 39 family sets → 35 (matches §7.4 and §8).
5. Batch wording aligned: §7.4 and Appendix B now both state 13 batches /
   14 binaries / 11 families for the jstrosch 2019–2023 samples.

Additional stale value caught while fixing (not flagged by the review):
Table external caption gave v3 total Gen 32 (the 56-file v4-era number).
v3 generic re-scanned on the 14 new samples: fires on the same 10 files as
the v4/v5 generic → v3 total on the expanded corpus is 42. Caption now reads
"(total Gen 32 on the 56-file v4-era corpus; 42 on the expanded corpus)".
Verified against `corpus_results.csv`: v3 = 32/56 archive, 3/4 clean (same
clean rows as v5, so no clean-row annotation needed).

### 9.1 Final wording round (acceptance edits)
Abstract: byte-layer sentence replaced with the capability-only/hunting-tier
form; principal-finding sentence added after the 0/73 report. Q3 (§7.4):
blocking-decision sentence added after the clean-controls report. Funding
block added to the declaration sections (was the only one of the five
required blocks missing). PDF now 41 pages.
