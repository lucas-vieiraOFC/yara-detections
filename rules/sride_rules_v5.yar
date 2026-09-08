/*
 * sride_rules_v5.yar — released rule set (v5) for
 * "Structural ROP Invariants for Static Malware Triage: YARA Encoding,
 *  Chain-Pointer Verification, and the Prevalence of Assembled Chains"
 *
 * Changes from the v4 set (rules_v4.yar):
 *   - All indicator/idiom string anchors removed. The released rules now
 *     encode ROP structural invariants only (pivot / POP;RET spine /
 *     terminator), consistent with the paper's scope. Removed: the AsyncRAT
 *     hollowing API triad and UPX magic, the NjRAT BSJB CLR marker and
 *     persistence string, the Custom-C2 rolling-cipher constant, the
 *     Rule 5a UPX section-name anchors, and the Rule 5b bank-target and
 *     TLS-hook strings.
 *   - Rule 5a (UPX packed shell) is withdrawn: it carried no ROP content,
 *     and the held-out ablation (Section 7.6) measured no benefit for the
 *     entropy-gated tracks.
 *   - The entropy two-track condition is reduced to the unpacked-track
 *     guard on Rule 2, flagged experimental in metadata (Section 7.6).
 *   - Rules 2, 3, 4 and 5b gain the +/-256-byte pivot-spine proximity
 *     anchor of Rule 1; without it a gadget-only rule is a base-rate
 *     matcher (Section 7.5).
 *
 * The v3 (sride_paper_rules.yar) and v4 (rules_v4.yar) sets remain
 * released unchanged so that both earlier scan arms stay reproducible.
 */

import "pe"
import "math"

// A section is considered packed/encrypted if its entropy exceeds 7.0 bits/byte.
private rule _any_section_packed {
    condition:
        for any i in (0..pe.number_of_sections - 1) : (
            math.entropy(pe.sections[i].raw_data_offset,
                         pe.sections[i].raw_data_size) > 7.0
        )
}

private rule _no_section_packed {
    condition:
        not _any_section_packed
}

// ---------------------------------------------------------------- Rule 1 ----
// Unchanged from v4.
rule ROP_Structural_Dispatch_Generic {
    meta:
        description  = "ROP structural capability: pivot co-located with spine and terminator"
        author       = "Lucas Freitas Vieira"
        date         = "2026-08-14"
        version      = "4"
        reference    = "Bittau et al., Hacking Blind, IEEE S&P 2014"
        mitre_attack = "T1055, T1620"
        tier         = "hunting"
        confidence   = "medium"
        scope_note   = "Detects ROP capability, NOT a confirmed assembled chain."
        scope_note2  = "Chain confirmation requires the stage-2 chain-pointer verifier."
    strings:
        // Stack pivots. Two-byte forms preferred: single-byte atoms
        // degenerate the Aho-Corasick engine and are guarded below.
        $pivot_xchg  = { 94 }        // XCHG EAX, ESP
        $pivot_mov   = { 89 C4 }     // MOV  ESP, EAX
        $pivot_pop   = { 5C C3 }     // POP  ESP ; RET
        $pivot_push  = { 50 C3 }     // PUSH EAX ; RET

        // Register-load dispatch spine
        $pop_eax = { 58 C3 }
        $pop_ecx = { 59 C3 }
        $pop_edx = { 5A C3 }
        $pop_ebx = { 5B C3 }
        $pop_esi = { 5E C3 }
        $pop_edi = { 5F C3 }

        // Chain terminators
        $term_call_eax = { FF D0 }
        $term_jmp_eax  = { FF E0 }
        $term_call_esi = { FF D6 }
        $term_syscall  = { 0F 05 C3 }   // SYSCALL ; RET, chainable form
    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and 3 of ($pop_*)
        and 1 of ($term_*)
        and (
            ( for any i in (1..#pivot_xchg) :
                ( for any of ($pop_*) :
                    ( $ in (@pivot_xchg[i] - 256 .. @pivot_xchg[i] + 256) ) ) )
            or
            ( for any i in (1..#pivot_mov) :
                ( for any of ($pop_*) :
                    ( $ in (@pivot_mov[i] - 256 .. @pivot_mov[i] + 256) ) ) )
            or
            ( for any i in (1..#pivot_pop) :
                ( for any of ($pop_*) :
                    ( $ in (@pivot_pop[i] - 256 .. @pivot_pop[i] + 256) ) ) )
            or
            ( for any i in (1..#pivot_push) :
                ( for any of ($pop_*) :
                    ( $ in (@pivot_push[i] - 256 .. @pivot_push[i] + 256) ) ) )
        )
}

// ---------------------------------------------------------------- Rule 2 ----
rule AsyncRAT_ROP_ProcessHollow {
    meta:
        description = "AsyncRAT: ROP staging shape (PUSH;RET pivot with co-located spine)"
        author      = "Lucas Freitas Vieira"
        date        = "2026-08-17"
        version     = "5"
        mitre_attack = "T1055.012"
        tier        = "hunting"
        confidence  = "medium"
        reference   = "Mashtizadeh et al., CCFI, CCS '15"
        note        = "v5: hollowing API triad and UPX magic removed (indicators); proximity anchor added; entropy-gated packed track removed (no held-out benefit, Section 7.6)."
        scope_note  = "Detects a ROP staging idiom; not family-keyed and not a confirmed chain."
        entropy_guard = "experimental"   // unpacked-track gate: no held-out evidence of benefit
    strings:
        $push_ret = { 50 C3 }   // PUSH EAX ; RET  (staging pivot)
        $pop_edi  = { 5F C3 }
        $pop_esi  = { 5E C3 }
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        _no_section_packed and
        // spine POP co-located with a PUSH;RET pivot
        for any i in (1..#push_ret) : (
            ($pop_edi in (@push_ret[i]-256..@push_ret[i]+256)) or
            ($pop_esi in (@push_ret[i]-256..@push_ret[i]+256))
        )
}

// ---------------------------------------------------------------- Rule 3 ----
rule NjRAT_ROP_ShellcodeStage {
    meta:
        description = "ROP staging triad (pivot + CALL EAX + spine), tuned on NjRAT native wrapper builds"
        author      = "Lucas Freitas Vieira"
        date        = "2026-08-17"
        version     = "5"
        mitre_attack = "T1055"
        tier        = "hunting"
        confidence  = "medium"
        note        = "v5: BSJB CLR marker and persistence string removed (indicators, Section 9.3); proximity anchor added. No longer family-keyed."
        scope_note  = "Detects a ROP staging idiom; not a confirmed chain."
    strings:
        $pivot   = { 94 }       // XCHG EAX, ESP
        $term    = { FF D0 }    // CALL EAX
        $pop_rdi = { 5F C3 }
        $pop_rsi = { 5E C3 }
    condition:
        uint16(0) == 0x5A4D and filesize < 3MB and
        $term and
        for any i in (1..#pivot) : (
            ($pop_rdi in (@pivot[i]-256..@pivot[i]+256)) or
            ($pop_rsi in (@pivot[i]-256..@pivot[i]+256))
        )
}

// ---------------------------------------------------------------- Rule 4 ----
rule Custom_C2_ROP_Syscall_64 {
    meta:
        description = "Custom C2: 64-bit ROP + syscall vocabulary with co-located spine"
        author      = "Lucas Freitas Vieira"
        date        = "2026-08-17"
        version     = "5"
        mitre_attack = "T1055 / T1071"
        tier        = "hunting"
        confidence  = "medium"
        note        = "v5: rolling-cipher constant removed (algorithmic indicator, not a ROP invariant); proximity anchor added."
        scope_note  = "Detects ROP capability; not a confirmed chain."
    strings:
        $pop_rdi     = { 5F C3 }
        $pop_rsi     = { 5E C3 }
        $pop_rdx     = { 5A C3 }
        $syscall_ret = { 0F 05 C3 }   // SYSCALL ; RET, chainable form
    condition:
        uint16(0) == 0x5A4D and filesize < 1MB and
        (2 of ($pop_rdi, $pop_rsi, $pop_rdx)) and
        for any i in (1..#syscall_ret) : (
            for any of ($pop_rdi, $pop_rsi, $pop_rdx) : (
                $ in (@syscall_ret[i]-256..@syscall_ret[i]+256)
            )
        )
}

// --------------------------------------------------------------- Rule 5b ----
rule BankTrojan_BR_Payload_ROPHook {
    meta:
        description = "BR banking trojan payload: MOV-pivot + JMP-EAX staging shape"
        author      = "Lucas Freitas Vieira"
        date        = "2026-08-17"
        version     = "5"
        mitre_attack = "T1056.003"
        tier        = "hunting"
        confidence  = "medium"
        note        = "v5: bank-target and TLS-hook strings removed (indicators, Section 9.3); proximity anchor added. No longer family-keyed."
        scope_note  = "Detects a ROP staging idiom; not a confirmed chain."
    strings:
        $pivot       = { 89 C4 }    // MOV ESP, EAX
        $term        = { FF E0 }    // JMP EAX
        $pop_eax_ret = { 58 C3 }
        $pop_ebx_ret = { 5B C3 }
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        $term and
        for any i in (1..#pivot) : (
            ($pop_eax_ret in (@pivot[i]-256..@pivot[i]+256)) or
            ($pop_ebx_ret in (@pivot[i]-256..@pivot[i]+256))
        )
}
