# 01 — Analysis of the SRIDE Paper

**Source:** `SRIDE/rop_yara_paper_edited.pdf` — *"Static Detection of ROP Gadget Chains in
Malware via Entropy-Aware YARA Rules"*, Lucas Freitas Vieira, August 2026.
Raw text extraction: `_paper_raw.txt` (kept for reference; PDF text-flow artifacts
repaired in the quotes below).

This document is a critical reading of the paper: what it claims, what actually holds
up, where the gaps are, and what can be expanded. It is the basis for everything else
in `SRIDE/research/`.

---

## 1. What the paper claims

1. **A five-stage Ghidra-to-YARA pipeline** (Fig. 1):
   `Triage (entropy + PE validity) → Packer ID (DIE + section heuristics) →
   Unpack/OEP hunt → Ghidra analysis (imports → XREFs → gadgets) → YARA generation
   + validation`.
2. **A taxonomy of four ROP structural invariants** amenable to YARA encoding
   (Table 1):
   | Class | Bytes | Why it's invariant |
   |---|---|---|
   | Stack pivot | `94` / `89 C4` / `5C` / `50 C3` / `8D 64 xx` | structurally required to redirect the stack |
   | Register load (POP;RET) | `58–5F C3` | argument setup, order-stable across variants |
   | Chain terminator | `FF D0` / `FF E0` / `FF D6` / `0F 05 (C3)` | final dispatch, cannot be removed |
   | Gadget fence | `?? C3` at 16-byte alignment | all gadgets end in RET, compiler-stable |
3. **Entropy-aware two-track rule conditions**: packed path
   (`math.entropy(0, filesize) > 7.0` + packer indicator) OR unpacked path
   (`entropy < 7.0` + structural invariant).
4. **Five rules** (generic dropper, AsyncRAT hollowing, NjRAT staging, custom C2
   64-bit ROP+XOR, UPX-packed Brazilian banking trojan in a packed/payload pair).
5. **Results**: mean TPR 93.8 % at FPR 0.006 % over 25 samples / 5 families,
   validated against 50 k NSRL clean files and EMBER-2018; +22.6 pp TPR over the
   YARA-Forge baseline; entropy pre-filter adds +11.4 pp TPR on packed samples at
   zero FPR cost; ~1 157 samples/s throughput.

The central thesis — *the same structural invariants that make Blind ROP (BROP)
possible offensively (POP;RET sequences always present at stable relative offsets)
are usable defensively as stable detection anchors* — is sound and is the paper's
best idea. It inverts Bittau et al.'s observation into a detection primitive.

---

## 2. What holds up

### 2.1 The core insight is correct

Gadgets are **functionally necessary**: a chain that pivots the stack and loads four
syscall arguments cannot drop below one pivot + four POP;RET gadgets without being
rewritten from scratch. Necessity → stability across repacking/recompilation →
suitability for long-lived signatures. This is exactly the property IOC signatures
(C2 domains, hashes) lack, and the paper articulates it well (§VII.B).

### 2.2 Proximity anchoring is the strongest construction in the rules

Rule 1's condition

```
for any i in (1..#pivot_xchg) : (
    @pop_edi[1] in (@pivot_xchg[i]-256..@pivot_xchg[i]+256)
)
```

is the only thing standing between the rule and a flood of false positives, because
`5F C3` (POP RDI;RET) appears in effectively every compiled binary. Requiring a
*pivot within ±256 bytes of a POP;RET* encodes co-location — a weak but real proxy
for "assembled chain" rather than "compiler background noise". This generalises:
**offset-arithmetic conditions are YARA's under-used structural feature**, and the
paper deserves credit for using them at all (most public rule sets never do).

### 2.3 The two-track entropy condition is pragmatic

Accepting a hit through *either* a packed-track (entropy + packer marker) or an
unpacked-track (structural match) reflects how these samples actually arrive. The
measured +11.4 pp TPR gain on packed variants at zero FPR cost is plausible and is
the paper's most useful empirical observation: **pattern-only rules silently lose
packed variants**, and making the packed branch explicit (even if it only flags
"suspicious packer + high entropy") recovers them.

### 2.4 The layered positioning is honest

The paper correctly places itself as the leftmost (pre-execution) layer in a
defence-in-depth table (ASLR → CFI/CCFI → LBR monitors at later phases) and does
not claim to replace runtime defences. See `03_literature_review.md` for how this
positioning shifts in 2026 with CET/shadow-stack deployment.

---

## 3. What does not hold up (gaps and internal inconsistencies)

These are ordered by severity. Each gap becomes an expansion task in
`04_expanded_invariant_taxonomy.md` / `05_sride_applied_to_stealers.md`.

### G1 — The rules match gadget *bytes*, but the paper's own thesis is about chain *pointers*

The introduction (§II.D) draws the correct distinction: every PE contains potential
gadgets; what matters is whether they are **"wired together in a dispatch structure
embedded in the binary's data sections"** — i.e. `.data`/`.rdata` contains a
sequence of *code-section pointers* (gadget addresses) separated by immediates
(arguments). Stage 4b even describes dispatchers as "a sequence of valid
code-section pointers separated by immediate values".

But **none of the five rules implements that**. All of them match raw gadget
opcodes (`94`, `5F C3`, `FF D0`…) anywhere in the file. A sequence of opcodes
`5F C3 5E C3 5B C3` in `.text` is ordinary compiler output; a 64-bit pointer array
`[ptr→POP RDI;RET][imm][ptr→POP RSI;RET][imm]…` in `.data` is the actual assembled
chain. The paper measures FPR for the former while claiming to detect the latter.

Why it matters: pointer-array detection is *more* distinctive (clean binaries almost
never store long runs of pointers into the middle of code sections in their data
sections — jump tables point at function-aligned code and live in well-known
formats) and survives instruction-level gadget mutation entirely (the chain must
reference *some* pivot gadget, wherever the compiler put it). YARA alone can
approximate this only crudely (e.g., `pe.section_index` tricks are not expressive
enough for "N consecutive dwords in [.text VA range]"); it needs a pipeline stage —
see the **chain-pointer verifier** in `05_sride_applied_to_stealers.md` and
`tools/sride_triage.py`.

### G2 — Single-byte and two-byte patterns are both FP-prone and slow

- `$pivot = { 94 }` (Rule 3), `$pivot_xchg = { 94 }` (Rule 1): a one-byte pattern
  forces YARA's atom engine to scan every offset; it also matches data, alignment
  padding, and random ciphertext. The proximity condition rescues precision, but at
  scan-time cost. A better encoding uses *longer pivot idioms* (`54 5C` PUSH
  ESP;POP ESP, `50 5C`, `94 C3`, `87 E6`, `BC imm32` MOV ESP,imm32…) — expanded in
  `04_expanded_invariant_taxonomy.md` §2.
- `math.entropy(0, filesize)` computes entropy over the *whole file* — the triage
  script in Listing 3 computes **per-section** entropy, which is the more
  discriminative statistic (a 47 MB installer with a 45 MB encrypted `.rdata` has
  modest whole-file entropy but a maximally-packed section). The paper's rules and
  its own Stage 1 are inconsistent here; per-section entropy is available in YARA
  via `math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size)`
  and should be used.

### G3 — The "gadget fence" invariant is declared but never used

Table 1 lists `?? C3` in 16-byte alignment as an invariant class; no rule uses it,
and the paper never shows it discriminates anything. Either validate it or drop it.
`04_expanded_invariant_taxonomy.md` keeps it only in a hardened, alignment-anchored
form.

### G4 — x86-32 bias; the 64-bit story is thin

The taxonomy is 32-bit x86-centric (`XCHG EAX,ESP` etc.). The one 64-bit rule
(Rule 4) uses `5F/5E/5A C3` + `0F 05 C3`, which is fine for Linux-style syscall
chains, but Windows x64 chains look different (no SYSCALL in user malware chains;
`jmp/call [rip+disp]`, `pop rsp`-based pivots because `xchg eax,esp` zero-extends
and is useless under 64-bit ASLR, `ret2reg`). ARM64/ARM-Thumb are out of scope and
unmentioned beyond one limitation line. Expansion: `04_expanded_invariant_taxonomy.md`
§§3–5.

### G5 — No treatment of chain obfuscation beyond one sentence

§VII.C admits junk-byte insertion (`(90)* 5F C3`) "at the cost of higher FPR" and
stops there. Real obfuscation is broader: unaligned gadgets (jumping into the
middle of instructions — the bytes `5F C3` never appear consecutively in `.text`
at all), runtime chain builders (the chain is *computed* at runtime, so no chain
bytes exist statically — this is what ROPInjector/ROPfuscator-style transforms and
most modern loaders do), offset-encoded chains (store `target − base` deltas), and
XOR-wrapped chains. Each breaks a different assumption of the paper; catalogued with
countermeasures in `04_expanded_invariant_taxonomy.md` §6.

### G6 — Validation scale and leakage risks

- 25 samples / 5 families (5 samples/family) is acknowledged as small, but the
  TPRs (88–100 %) are reported to 0.1 % precision that the sample size cannot
  support (1 sample = 20 pp at n=5).
- The clean corpus is "50,000 NSRL + system binaries"; NSRL RDS contains many
  *installer* and *SDK* binaries with high-entropy resources and UPX shells —
  the exact FP surface for the packed track. The 0.006 % FPR claim needs a
  per-family breakdown of *which* clean files scored.
- EMBER-2018 is used as a *labelled* reference but the paper does not say whether
  its own five families are inside EMBER (train/eval leakage) or how EMBER's known
  label noise was handled.
- No inter-rule deduplication is described (the same sample can be counted by the
  generic rule *and* its family rule, inflating aggregate TPR).

A concrete, reproducible validation protocol addressing G6 is written up in
`06_validation_methodology.md`.

### G7 — Rule hygiene details

- Dates in rule metadata (`2026-09-01`) postdate the paper (August 2026) — cosmetic.
- Rule 3 anchors NjRAT with the CLR metadata magic `BSJB` (`42 53 4A 42`) — correct,
  but NjRAT is a .NET family whose native ROP staging occurs in *packed/native
  wrapper* builds; the rule will miss MSIL-only builds (fine, but should be stated).
- No rule carries a `hash` or sample reference in metadata, which makes corpus
  re-validation harder than necessary.

---

## 4. Relationship to the detectors in this repository

The four `detect.c` scripts in the sibling directories (analysed in
`02_detect_scripts_analysis.md`) are the **IOC layer** the paper positions itself
above: cleartext strings + exact SHA-256. They are what the paper would call
"indicators that expire on the next compilation". Merging the two — family IOCs as
the *family-attribution* layer, SRIDE invariants as the *durable detection* layer —
is the natural next step and is implemented in `rules/sride_stealer.yar` and
`05_sride_applied_to_stealers.md`.

---

## 5. Expansion roadmap (what the rest of `research/` does)

| Gap | Where addressed |
|---|---|
| G1 chain-pointer detection | `05` §3, `tools/sride_triage.py` |
| G2 pattern quality / per-section entropy | `04` §2, `rules/`, `06` |
| G3 unused fence class | `04` §2.4 |
| G4 64-bit + ARM coverage | `04` §§3–5 |
| G5 obfuscation countermeasures | `04` §6 |
| G6 validation rigour | `06_validation_methodology.md` |
| Runtime-defence positioning 2026 (CET/PAC) | `03_literature_review.md` |
| Applying SRIDE to the 4 local stealer families | `05_sride_applied_to_stealers.md`, `rules/sride_stealer.yar` |
| Toolchain fingerprinting as a 5th invariant class | `04` §7 (motivated by the Rust stealers in this repo) |
