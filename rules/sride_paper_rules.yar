/*
 * sride_paper_rules.yar  —  FROZEN v3 ARM, kept for scan reproduction only.
 *
 * The six rules printed in Section V of
 * "Static Detection of ROP Gadget Chains in Malware via Entropy-Aware YARA Rules"
 * (L. F. Vieira, August 2026; SRIDE/paper.pdf), plus the two private
 * per-section entropy helpers the rules reference (Appendix A of the paper).
 *
 * This file is the paper-v3 rule set, preserved unchanged so the v3 scan arm
 * stays reproducible (the released v3 rules reproduce the recorded v3 scan
 * exactly, 59/59 files). It contains string-based detections (API names,
 * registry keys, packer magics, bank targets) that later versions removed:
 * the current released set is sride_rules_v5.yar, which is ROP-only.
 * Do not deploy these rules; use the v5 set.
 *
 * Notes:
 *   - The Rule 1 proximity clause uses the `$x in (lo..hi)` region form; the
 *     `in` operator requires a `$` string identifier on the left.
 *   - Entropy is evaluated per PE section, matching the Stage-1 triage in the
 *     paper (Listing 3). Packed track = any section > 7.0 bits/byte;
 *     unpacked track = no section above 7.0.
 *   - Verified to compile on YARA 4.5.7 and YARA-X 1.x.
 *
 * For the hardened, extended rule set developed in the accompanying
 * research, see sride_stealer.yar (v5: ROP structural rules only).
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
rule ROP_Shellcode_Dropper_Generic {
    meta:
        description = "ROP: pivot + spine + terminator"
        author      = "Lucas Freitas Vieira"
        date        = "2026-08-01"
        reference   = "Bittau et al., Hacking Blind, S&P '14"
        mitre_attack = "T1055 / T1620"
        confidence  = "medium"
    strings:
        $pivot_xchg = { 94 }
        $pivot_mov  = { 89 C4 }
        $pivot_pop  = { 5C }
        $pop_edi    = { 5F C3 }
        $pop_esi    = { 5E C3 }
        $pop_ebx    = { 5B C3 }
        $pop_ecx    = { 59 C3 }
        $pop_edx    = { 5A C3 }
        $pop_eax    = { 58 C3 }
        $call_eax   = { FF D0 }
        $jmp_eax    = { FF E0 }
        $call_esi   = { FF D6 }
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        (1 of ($pivot_*)) and
        (3 of ($pop_*)) and
        (1 of ($call_*, $jmp_eax)) and
        // Proximity anchor — a dispatch-spine gadget must occur
        // within +/-256 bytes of an observed XCHG EAX,ESP pivot.
        for any i in (1..#pivot_xchg) : (
            ($pop_edi in (@pivot_xchg[i]-256..@pivot_xchg[i]+256)) or
            ($pop_esi in (@pivot_xchg[i]-256..@pivot_xchg[i]+256))
        )
}

// ---------------------------------------------------------------- Rule 2 ----
rule AsyncRAT_ROP_ProcessHollow {
    meta:
        description = "AsyncRAT: ROP process hollowing"
        author      = "Lucas Freitas Vieira"
        date        = "2026-08-01"
        mitre_attack = "T1055.012"
        confidence  = "high"
        reference   = "Mashtizadeh et al., CCFI, CCS '15"
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
            // Packed track — per-section entropy, not whole-file.
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
        description = "NjRAT: pivot + CALL EAX staging"
        author      = "Lucas Freitas Vieira"
        date        = "2026-08-01"
        mitre_attack = "T1055"
        confidence  = "high"
        note        = "Covers native/packed wrapper builds only; MSIL-only builds are out of scope."
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
        date        = "2026-08-01"
        mitre_attack = "T1055 / T1071"
        confidence  = "medium"
    strings:
        $pop_rdi     = { 5F C3 }
        $pop_rsi     = { 5E C3 }
        $pop_rdx     = { 5A C3 }
        $syscall_ret = { 0F 05 C3 }
        $rolling_xor = { 30 06 30 66 01 30 66 02 83 C6 03 }
        $port_4444   = { 11 5C }
    condition:
        uint16(0) == 0x5A4D and filesize < 1MB and
        $syscall_ret and
        (2 of ($pop_rdi, $pop_rsi, $pop_rdx)) and
        $rolling_xor and $port_4444
}

// --------------------------------------------------------------- Rule 5a ----
rule BankTrojan_BR_UPX_Packed {
    meta:
        description = "BR banking trojan: UPX shell"
        author      = "Lucas Freitas Vieira"
        date        = "2026-08-01"
        mitre_attack = "T1027.002"
        confidence  = "medium"
    strings:
        $upx0 = ".UPX0" ascii
        $upx1 = ".UPX1" ascii
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
        date        = "2026-08-01"
        mitre_attack = "T1056.003"
        confidence  = "high"
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
