# 05 — Applying SRIDE to the Four In-Repo Stealer Families (Empirical)

This is where the SRIDE methodology (paper + extensions) meets the four analyzed
families. Everything claimed here was executed locally on the samples; commands
are reproducible with `tools/sride_triage.py` and `rules/sride_stealer.yar`.

Artifacts:
- `tools/sride_triage.py` — triage + packer ID + chain-pointer verifier + Rust
  fingerprints + crypto constants + Myth static decryptor
- `tools/make_chain_test_pe.py` — synthetic positive/negative control generator
- `rules/sride_stealer.yar` — 15 rules, compiles clean on YARA 4.5.7 (only
  documented short-atom performance warnings on hunting-tier rules)

---

## 1. Match matrix (validated 2026-08-10, YARA 4.5.7)

| Sample | File | Family rule | Structural / toolchain rules |
|---|---|---|---|
| Myth stage-1 loader | `mythstealer/55a418f8….exe` | **SRIDE_Myth_Loader_Stage1** | Toolchain_Rust, Rust_StringObfuscation, Packed_HighEntropy_Section, ROP_Pivots_x64†, JOP_Dispatcher†, SROP_Frame† |
| Myth stage-2 DLL | `mythstealer/decrypted_payload.dll` | **SRIDE_Myth_Stealer_Stage2_DLL** | Toolchain_Rust, ROP_Pivots_x64†, JOP_Dispatcher†, SROP_Frame† |
| Prysmax | `prysmaxstealer/rustystealer.exe` | **SRIDE_Prysmax_Rust** | Toolchain_Rust, ROP_Chain_Generic_x86†, ROP_Pivots_x64†, JOP_Dispatcher†, SROP_Frame† |
| Snowflake stage-1 | `snowflakestealer/1ae99a45….exe` | **SRIDE_Snowflake_Loader_Stage1** | Packed_HighEntropy_Section, JOP_Dispatcher† |
| Snowflake payload (raw TEA out) | `payload_decrypted.bin` | — (correctly clean: failed/intermediate decryption, no structure) | — |
| Snowflake stage-2 shellcode | `payload_v2.bin` | **SRIDE_Shellcode_SelfMap_Stub_x86** | — |
| Snowflake stage-3 (decompressed) | `stage3_decompressed.bin` | **SRIDE_Snowflake_Payload_Stage2** + SelfMap_Stub | — |
| Synthetic ROP chain PE | `make_chain_test_pe.py` output | — | **SRIDE_ROP_Chain_Generic_x86** ✓ |
| `/bin/ls` (ELF control) | — | — | — |

† hunting-tier generic rules firing on ordinary compiler background — see §5.

All four family rules fire exactly once, on the right file, with no cross-family
leakage. The chain-pointer verifier results:

| Sample | Pointer runs | Verified chains | Verdict |
|---|---|---|---|
| Synthetic chain PE | 2 | **1** (5 ptrs, 1 imm, ratio 1.0) | true positive ✓ |
| Prysmax (Rust x64, no ROP) | 311 | 0 | clean ✓ |
| Snowflake loader (MSVC x86, no ROP) | 5 | 0 | clean ✓ |
| Myth loader (Rust x64, reflective load, no ROP) | 22 | 0 | clean ✓ |

---

## 2. Finding: the string-IOC detectors under-fire on the packed stage-1

Measured against the Myth stage-1 loader with the IOC weights in
`mythstealer/detect.c`:

- Loader cleartext sigs that actually exist in the loader: `include-crypt-crypto`
  (+2), `native-windows-gui` (+1) → **score 3 = SUSPICIOUS, not DETECTED**
  (threshold 4).
- All weight-3 sigs (C2 domain, C2 IP, webhook message) and `winlnk.exe`,
  `ATOMIC_INTRINSICS=1` live in the **encrypted stage-2** — verified by direct
  byte search: `185.224.3.219/screen` loader@-1 / DLL@15289759;
  `myth.cocukporno.lol` loader@-1 / DLL@15227063.

So without the exact SHA-256, the stock detector *misses the packed dropper* —
the file victims actually download. `SRIDE_Myth_Loader_Stage1` closes the gap
with durable anchors: the obfstr key-schedule seed `A6 5C 38 18` (xorshift32 seed
`0x18385CA6`, a code-level constant that survives string rotation), the crate
pair, and the structural branch (crate + >1 MB section with H > 7.4).

**Correction to `detect.c` recorded:** `dQw4w9WgXcQ:` (encrypted Discord token
prefix) is not statically present in either Myth file (loader@-1, DLL@-1) — it is
a runtime-constructed string, only matchable in memory dumps. The YARA rules
deliberately omit it from static conditions.

## 3. Finding: static decryption beats signature scanning (Myth extractor)

`tools/sride_triage.py --extract-myth` reimplements the loader's key schedule
(xorshift32 from the hardcoded seed → 64-byte keystream → ASCII-hex key →
repeating-XOR over 28 MB). Executed against the real sample:

```
[*] derived payload key: 7cb00c3cb8bab1ca2e910ffe2c918a9ba577d019bcc9ba8c1664bd7592d8c34b
[*] decrypted 28372782 bytes, sha256=be2476c80ecd7819fc9c08d63e287ba933e3ab98459f02d177e662c3d7038219
[+] sha256 matches the analyzed Myth stealer DLL — extractor verified
```

The derived key equals the one recovered manually in the reconstruction, and the
output hashes exactly to the known stage-2 DLL. This demonstrates the **extraction
track**: when a family uses deterministic in-binary key schedules, a detector can
statically produce the inner payload and scan it with the full rule set — turning
one encrypted blob into two scored artefacts. The paper's entropy two-track only
flags such files; the extraction track *resolves* them. Snowflake is the same
opportunity (TEA with embedded key at `0x4144c0`); a `snowflake_decrypt()`
function is the obvious next step (the repo already ships the decrypted blobs to
validate against: `payload_v2.bin`, `stage3_decompressed.bin`).

## 4. Finding: the chain-pointer thesis works — but only with semantic verification

The paper's stated invariant ("assembled chains are pointer runs into code
sections in `.data`/`.rdata`") cannot be encoded in YARA and its rules never
encode it. `sride_triage.py --chain-scan` implements it as a pipeline stage.
What it took to get from naive to useful, each step driven by a measured FP class:

1. **Naive pointer runs** → FPs: MSVC jump tables, C++ vtables, Rust vtables
   (Snowflake: 5 runs; Prysmax: 311 runs — all benign).
2. **+ capstone gadget check** (target must disassemble to ≤8 instructions ending
   in RET/syscall/indirect branch) → still FPs: Rust emits tiny leaf functions
   (`xor eax,eax; ret`, `movabs rax,imm64; movabs rdx,imm64; ret` — a u128-return
   function!) that are byte-for-byte gadget-shaped.
3. **+ `.pdata` function-start filter** → insufficient: LLVM omits unwind entries
   for leaf functions, so real functions look "mid-function".
4. **+ one-function-cluster filter** (jump tables live inside a single
   RUNTIME_FUNCTION range) → kills MSVC switch tables.
5. **+ spine-shape typing** (targets must type as PIVOT/POP/TERM per the paper's
   taxonomy; require SHAPE A `≥2 POP ∧ (≥1 PIVOT ∨ ≥1 TERM)` or SHAPE B
   `PIVOT ∧ TERM ∧ ≥3 ptrs`) → kills the Rust fn-pointer tables (type OTHER).

Final discrimination on the local corpus: **synthetic chain detected; all three
real binaries clean.** The publishable lesson: *byte patterns say "gadget-shaped",
semantics say "chain-shaped"* — the gap between the two is exactly where the FP
rate of the paper's Rule 1 lives. (It also explains the observed
`SRIDE_ROP_Chain_Generic_x86` fire on Prysmax: 5.5 MB of Rust code will, by
chance, contain a `94 C3` within 256 bytes of `5F C3`. Byte-level structural rules
need the size cap and are hunting-tier, not verdict-tier.)

## 5. Honest notes on the generic structural rules

- `SRIDE_ROP_Pivots_x64` (`2 of them`) fires on both x64 binaries: `C9 C3`
  (leave;ret) is ordinary compiler output. Kept as a low-confidence hunting rule;
  it demonstrates why the paper needed the proximity anchor — vocabulary without
  co-location is noise.
- `SRIDE_SROP_Frame_x86_x64` fires on all large Rust binaries: `B8 0F 00 00 00`
  (mov eax,15) + `0F 05` within ±512 B is not rare in megabyte-scale `.text`.
  Tightening lever: require the forged-frame constant size check or restrict to
  non-PE/shellcode files (SROP frames are a Linux-ELF technique in practice).
- `SRIDE_JOP_Dispatcher_x86` fires broadly even at `#upd_pop_jmp >= 4`: `5? FF 2?`
  matches compiler switch idioms. Kept for hunting; the dispatcher-pair form
  (`83 C? 04 FF 2?`, requiring 2 distinct registers) is the precise one and did
  not false-fire on the local corpus.
- Family rules had **zero** cross-hits, including on `/bin/ls`, the synthetic PE,
  and the raw failed-decryption blob.

## 6. Erratum found by local validation (affects the paper's Rule 1)

The proximity condition as printed in the paper —

```
@pop_edi[1] in (@pivot_xchg[i]-256..@pivot_xchg[i]+256)
```

— does **not compile** on stock YARA 4.5.7: `unexpected <in>`. The `in` region
operator requires a `$` string identifier on the left (`$pop_edi in (lo..hi)`);
the `@offset[idx] in (...)` form is rejected by the grammar (all variants tested:
`@a in (0..100)`, `@a[1] in (0..100)`, `@a[1] in (10..filesize)`). The corrected,
portable form (used throughout `rules/sride_stealer.yar`):

```
for any i in (1..#piv_xchg_c3) : (
    ($pop_edi in (@piv_xchg_c3[i]-256..@piv_xchg_c3[i]+256)) or
    ($pop_esi in (@piv_xchg_c3[i]-256..@piv_xchg_c3[i]+256))
)
```

Semantics are also slightly *better*: `$x in (lo..hi)` checks every match of `$x`,
not just the first. Every rule in the paper should be compile-tested before the
camera-ready; this is the sort of bug reviewers catch.

## 7. Family-by-family upgrade summary (detect.c → SRIDE rules)

| Family | detect.c blind spot | SRIDE upgrade (rule / tool) |
|---|---|---|
| Myth | packed stage-1 scores only 3 (SUSP) | seed constant + crate pair + per-section entropy → DETECT; `--extract-myth` resolves stage-2 |
| Prysmax | all-cleartext strings; dies the day the builder flips on obfstr | crate-stack combination (`tokio-tungstenite-0.20` + `rayon-1.10` + `sysinfo-0.29`) + state labels + leaked dev secrets |
| grabber_rs | header already admits release builds hide everything | obfuscator-crate fingerprint (`goldberg-0.1` + `grabber_rs` path) + kill-list group + rare-browser group |
| Snowflake | good anchors but no structural layer | TEA neg-delta + junk-loop constants + per-section entropy; payload rule matches shellcode-wrapped stages (no MZ gate); stub rule catches the self-map idiom |

The combined architecture that falls out of this — IOC layer (detect.c) for
attribution, toolchain + structural layer (YARA) for durable detection,
extraction layer (triage tool decryptors) for packed stages, chain-pointer
verifier for code-reuse payloads — is the expanded SRIDE pipeline, and it is
what `06_validation_methodology.md` proposes to measure properly.
