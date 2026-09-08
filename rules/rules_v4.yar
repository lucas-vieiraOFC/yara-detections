/*
 * rules_v4.yar — corrected rule set for the revised paper
 * "Structural ROP Invariants for Static Malware Triage: YARA Encoding,
 *  Chain-Pointer Verification, and the Prevalence of Assembled Chains"
 *
 * Changes from the paper-v3 set (sride_paper_rules.yar):
 *   - Rule 1 replaced: proximity clause now covers all four pivot classes
 *     (previously anchored on $pivot_xchg alone); $pivot_pop is { 5C C3 }
 *     (POP ESP;RET) instead of the single byte { 5C }; syscall terminator is
 *     { 0F 05 C3 } (chainable form); size guard 5MB matching the methodology;
 *     scope notes state capability-not-chain semantics.
 *   - Rule 2: packed track demoted to hunting tier in metadata.
 *   - Rule 4: hardcoded campaign port { 11 5C } removed (indicator, not an
 *     invariant); rolling-XOR algorithmic constant retained.
 *   - Rule 3 relabelled as a family rule with a ROP-adjacent component.
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
        description = "AsyncRAT: ROP process hollowing"
        author      = "Lucas Freitas Vieira"
        date        = "2026-08-14"
        version     = "4"
        mitre_attack = "T1055.012"
        confidence  = "high"
        reference   = "Mashtizadeh et al., CCFI, CCS '15"
        packed_track_tier = "hunting"   // packed track is family-blind: any UPX-packed
                                        // file with a hot section; hunting tier only
    strings:
        $push_ret    = { 50 C3 }
        $api_ntunmap = "NtUnmapViewOfSection" ascii wide
        $api_valloc  = "VirtualAllocEx" ascii wide
        $api_write   = "WriteProcessMemory" ascii wide
        $pop_edi     = { 5F C3 }
        $pop_esi     = { 5E C3 }
        $upx_sig     = { 55 50 58 21 }
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and (
            // Packed track — per-section entropy, not whole-file. Hunting tier.
            (_any_section_packed and $upx_sig)
            or
            (_no_section_packed and
             $push_ret and (2 of ($api_*)) and
             (1 of ($pop_edi, $pop_esi)))
        )
}

// ---------------------------------------------------------------- Rule 3 ----
rule NjRAT_ROP_ShellcodeStage {
    meta:
        description = "NjRAT family rule with ROP-adjacent staging component"
        author      = "Lucas Freitas Vieira"
        date        = "2026-08-14"
        version     = "4"
        mitre_attack = "T1055"
        confidence  = "high"
        note        = "Covers native/packed wrapper builds only; MSIL-only builds are out of scope."
        scope_note  = "Precision derives from the BSJB + persistence anchors (indicators); the gadget bytes are ROP-adjacent."
    strings:
        $pivot      = { 94 }
        $term       = { FF D0 }
        $pop_rdi    = { 5F C3 }
        $pop_rsi    = { 5E C3 }
        $dotnet_clr = { 42 53 4A 42 }
        $reg_run    = "CurrentVersion\\Run" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3MB and
        $dotnet_clr and $pivot and $term and
        (1 of ($pop_rdi, $pop_rsi)) and $reg_run
}

// ---------------------------------------------------------------- Rule 4 ----
rule Custom_C2_ROP_Syscall_64 {
    meta:
        description = "Custom C2: 64-bit ROP + syscall"
        author      = "Lucas Freitas Vieira"
        date        = "2026-08-14"
        version     = "4"
        mitre_attack = "T1055 / T1071"
        confidence  = "medium"
        note        = "Campaign port string removed in v4: an indicator, not an invariant."
    strings:
        $pop_rdi     = { 5F C3 }
        $pop_rsi     = { 5E C3 }
        $pop_rdx     = { 5A C3 }
        $syscall_ret = { 0F 05 C3 }
        // Algorithmic constant (extended class 5): a family that decrypts its
        // traffic with this rolling cipher cannot stop carrying it.
        $rolling_xor = { 30 06 30 66 01 30 66 02 83 C6 03 }
    condition:
        uint16(0) == 0x5A4D and filesize < 1MB and
        $syscall_ret and
        (2 of ($pop_rdi, $pop_rsi, $pop_rdx)) and
        $rolling_xor
}

// --------------------------------------------------------------- Rule 5a ----
rule BankTrojan_BR_UPX_Packed {
    meta:
        description = "BR banking trojan: UPX shell"
        author      = "Lucas Freitas Vieira"
        date        = "2026-08-14"
        version     = "4"
        mitre_attack = "T1027.002"
        tier        = "hunting"
        confidence  = "medium"
    strings:
        // UPX section names carry no leading dot; the paper-v3 anchors
        // (".UPX0"/".UPX1") could never fire on real UPX output. Fixed in v4.
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upxb = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and all of ($upx*) and
        _any_section_packed   // per-section entropy, not whole-file.
}

// --------------------------------------------------------------- Rule 5b ----
rule BankTrojan_BR_Payload_ROPHook {
    meta:
        description = "BR banking trojan: ROP + form-grab"
        author      = "Lucas Freitas Vieira"
        date        = "2026-08-14"
        version     = "4"
        mitre_attack = "T1056.003"
        confidence  = "high"
        scope_note  = "Target and TLS-hook strings are behavioural invariants for a BR form-grabber, not mere indicators."
    strings:
        $pivot       = { 89 C4 }
        $term        = { FF E0 }
        $pop_eax_ret = { 58 C3 }
        $pop_ebx_ret = { 5B C3 }
        $tgt_itau    = "itau.com.br" ascii wide nocase
        $tgt_brad    = "bradesco" ascii wide nocase
        $tgt_bb      = "Banco do Brasil" ascii wide nocase
        $hook_ssl    = "SSL_write" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        $pivot and $term and
        (1 of ($pop_eax_ret, $pop_ebx_ret)) and
        (2 of ($tgt_*)) and $hook_ssl
}
