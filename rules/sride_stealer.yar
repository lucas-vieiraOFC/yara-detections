/*
 * sride_stealer.yar — SRIDE structural research rules (expanded invariant
 * taxonomy, research/04).
 *
 * v5 (2026-08-17): all string-based detections removed. The SRIDE work is
 * about ROP structural invariants, so this set now contains only gadget- and
 * chain-idiom byte patterns. Retired as indicator-layer content (they remain
 * in git history and are documented in research/05):
 *   - section B toolchain fingerprints (/rustc/ paths, panic strings,
 *     obfstr/litcrypt/goldberg crate versions)
 *   - section C stealer family rules (Myth, Prysmax, grabber_rs, Snowflake):
 *     C2 domains, exfil endpoints, crate stacks, build paths, leaked
 *     credentials, mutexes, wallet/messenger target strings
 *   - the x86 shellcode self-map stub rule (call/pop + prologue idiom,
 *     not a ROP structure)
 *   - family-rule hex anchors (obfstr seed, TEA key/delta, timing-loop
 *     constants): constants, not ROP gadgets
 *
 * Retained: the structural SRIDE classes — pivots, POP;RET spines,
 * terminators (x86/x64/ARM64), JOP dispatchers, SROP frames, the
 * ROPfuscator chain-builder idiom — plus the per-section entropy context
 * rule, flagged experimental (no held-out evidence of benefit; paper
 * Section 7.6).
 *
 * Validated locally against the four samples; see research/05 for the
 * (pre-v5) match matrix and the FP caveats. Defensive research use only.
 */

import "pe"
import "math"

/* ------------------------------------------------------------------ */
/* A. Generic structural rules (expanded SRIDE taxonomy, research/04) */
/* ------------------------------------------------------------------ */

rule SRIDE_ROP_Chain_Generic_x86
{
    meta:
        description = "Assembled-ROP idiom: x86 pivot idioms + POP;RET spine + terminator, proximity-anchored"
        author = "Lucas Freitas Vieira"
        date = "2026-08-10"
        mitre_attack = "T1055 / T1620"
        confidence = "medium"
        note = "improved version of paper Rule 1: >=2-byte pivot idioms instead of bare {94}"
    strings:
        // pivot idioms (>=2-byte atoms; see research/04 section 2)
        $piv_xchg_c3   = { 94 C3 }             // xchg eax,esp ; ret
        $piv_movesp    = { 89 C4 C3 }          // mov esp,eax ; ret
        $piv_pushesppop= { 54 5C }             // push esp ; pop esp
        $piv_moveaximm = { BC ?? ?? ?? ?? C3 } // mov esp,imm32 ; ret
        $piv_leaveret  = { C9 C3 }             // leave ; ret
        // spine
        $pop_edi = { 5F C3 }
        $pop_esi = { 5E C3 }
        $pop_ebx = { 5B C3 }
        $pop_ecx = { 59 C3 }
        $pop_edx = { 5A C3 }
        $pop_eax = { 58 C3 }
        // terminators
        $call_eax = { FF D0 }
        $jmp_eax  = { FF E0 }
        $call_esi = { FF D6 }
        $sysenter = { 0F 34 }
        $syscall  = { 0F 05 }
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and
        (1 of ($piv_*)) and (3 of ($pop_*)) and (1 of ($call_*, $jmp_eax, $sysenter, $syscall)) and
        // proximity anchor: a spine element within +-256 bytes of a pivot.
        // NB: the paper's printed form "@x[1] in (lo..hi)" does not compile on
        // stock YARA 4.5.x; the $-identifier region form is the portable one.
        for any i in (1..#piv_xchg_c3) : (
            ($pop_edi in (@piv_xchg_c3[i]-256..@piv_xchg_c3[i]+256)) or
            ($pop_esi in (@piv_xchg_c3[i]-256..@piv_xchg_c3[i]+256))
        )
}

rule SRIDE_ROP_Pivots_x64
{
    meta:
        description = "x64-correct stack pivots (the paper's 0x94 pivot truncates RSP on x64 - research/04 section 4)"
        author = "Lucas Freitas Vieira"
        date = "2026-08-10"
        mitre_attack = "T1055"
        confidence = "medium"
    strings:
        $piv_pushrsp_pop = { 54 5? C3 }        // push rsp ; pop r64 ; ret
        $piv_xchg64      = { 48 94 C3 }        // xchg rax,rsp ; ret
        $piv_xchg64_b    = { 48 87 E? C3 }     // xchg rsp,r64 ; ret (modrm E0-E7 family)
        $piv_pop_rsp     = { 5C C3 }           // pop rsp ; ret
        $piv_leaveret    = { C9 C3 }           // leave ; ret
        $piv_movrsp      = { 48 89 ?? C3 }     // mov rsp,r64 ; ret (modrm C4-FC)
    condition:
        uint16(0) == 0x5A4D and pe.is_64bit() and 2 of them
}

rule SRIDE_JOP_Dispatcher_x86
{
    meta:
        description = "JOP dispatcher gadgets (add r,4; jmp [r] family) - research/04 section 3"
        author = "Lucas Freitas Vieira"
        date = "2026-08-10"
        mitre_attack = "T1055"
        confidence = "low"
        note = "single-dispatcher hits are weak; use for hunting, not verdicts"
    strings:
        $disp_add_edx  = { 83 C2 04 FF 22 }    // add edx,4 ; jmp [edx]
        $disp_add_eax  = { 83 C0 04 FF 20 }    // add eax,4 ; jmp [eax]
        $disp_add_ecx  = { 83 C1 04 FF 21 }    // add ecx,4 ; jmp [ecx]
        $disp_add_ebx  = { 83 C3 04 FF 23 }    // add ebx,4 ; jmp [ebx]
        $upd_pop_jmp   = { 5? FF 2? }          // pop r32 ; jmp [r32]  (ret-less ROP, Checkoway 2010)
    condition:
        uint16(0) == 0x5A4D and (2 of ($disp_*) or (#upd_pop_jmp >= 4))
}

rule SRIDE_SROP_Frame_x86_x64
{
    meta:
        description = "SROP building blocks: sigreturn syscall numbers + syscall/int80 + pop rax;ret"
        author = "Lucas Freitas Vieira"
        date = "2026-08-10"
        mitre_attack = "T1055"
        confidence = "medium"
    strings:
        $sys_nr_64   = { B8 0F 00 00 00 }      // mov eax, 15  (__NR_rt_sigreturn x64)
        $sys_nr_32   = { B8 77 00 00 00 }      // mov eax, 119 (sigreturn i386)
        $sys_nr_32rt = { B8 AD 00 00 00 }      // mov eax, 173 (rt_sigreturn i386)
        $syscall     = { 0F 05 }
        $int80       = { CD 80 }
        $pop_rax     = { 58 C3 }
    condition:
        uint16(0) == 0x5A4D and $pop_rax and
        (1 of ($sys_nr_*)) and (1 of ($syscall, $int80)) and
        // pop rax;ret within 512 bytes of the syscall-number load
        (
        for any i in (1..#sys_nr_64) : (
            $pop_rax in (@sys_nr_64[i]-512..@sys_nr_64[i]+512)
        ) or
        for any i in (1..#sys_nr_32) : (
            $pop_rax in (@sys_nr_32[i]-512..@sys_nr_32[i]+512)
        ) or
        for any i in (1..#sys_nr_32rt) : (
            $pop_rax in (@sys_nr_32rt[i]-512..@sys_nr_32rt[i]+512)
        )
        )
}

rule SRIDE_ROPFuscator_Generator_Idiom
{
    meta:
        description = "ROPfuscator-style chain generator: dense push imm32 runs feeding a ret"
        author = "Lucas Freitas Vieira"
        date = "2026-08-10"
        mitre_attack = "T1027"
        confidence = "medium"
        note = "transformed-ROP output contains the BUILDER, not a chain array (research/04 section 6)"
    strings:
        $push_run = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ??
                      68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ??
                      68 ?? ?? ?? ?? 68 ?? ?? ?? ?? }            // 8x push imm32
        $pushf_popf = { 9C 9D }                                  // flag save/restore pair
        $ret = { C3 }
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $push_run and $pushf_popf and
        $ret in (@push_run[1]..@push_run[1]+4096)
}

rule SRIDE_ROP_ARM64_Gadgets
{
    meta:
        description = "ARM64 ROP/JOP vocabulary: RET / RETAA / RETAB, BR/BLR, mov sp,xn pivots"
        author = "Lucas Freitas Vieira"
        date = "2026-08-10"
        mitre_attack = "T1055"
        confidence = "low"
        note = "file-format agnostic (ELF/Mach-O/raw); A64 is fixed-width so no unaligned gadgets"
    strings:
        $ret        = { C0 03 5F D6 }          // ret
        $retaa      = { FF 0B 5F D6 }          // retaa (PAC)
        $retab      = { FF 0F 5F D6 }          // retab (PAC)
        $pivot_sp0  = { 1F 00 00 91 }          // mov sp, x0
        $pivot_sp1  = { 3F 00 00 91 }          // mov sp, x1
        $ldp_frame  = { ?? ?? ?? A8 C0 03 5F D6 } // ldp .., [sp], #imm ; ret (frame pop)
    condition:
        // several independent terminators + at least one pivot = assembled-chain vocabulary
        (#ret + #retaa + #retab) >= 3 and (1 of ($pivot_*)) and $ldp_frame
}

rule SRIDE_Packed_HighEntropy_Section
{
    meta:
        description = "Per-section entropy context (no ROP content on its own)"
        author = "Lucas Freitas Vieira"
        date = "2026-08-10"
        mitre_attack = "T1027.002"
        confidence = "low"
        note = "experimental: no held-out evidence of benefit (paper Section 7.6); combine with structural rules"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 4096 and
            math.entropy(pe.sections[i].raw_data_offset,
                         pe.sections[i].raw_data_size) > 7.2
        )
}
