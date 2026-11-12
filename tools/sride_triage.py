#!/usr/bin/env python3
"""
sride_triage.py — extended SRIDE pipeline Stages 1–2 (+ chain-pointer verifier)

Implements and extends the triage stages of:
  "Static Detection of ROP Gadget Chains in Malware via Entropy-Aware YARA Rules"
  (L. F. Vieira, 2026) — see SRIDE/rop_yara_paper_edited.pdf

Extensions over the paper (see research/01_paper_analysis.md, gaps G1/G2):
  * per-section Shannon entropy (the paper's YARA rules use whole-file entropy,
    its own Stage 1 is per-section — this tool does per-section, which is the
    discriminative one)
  * chain-pointer verification: the paper's stated thesis is that assembled ROP
    chains live in data sections as pointer runs into code sections, but its
    rules only match gadget *bytes*. --chain-scan hunts the pointer runs.
  * embedded-PE hunt (reflectively-loaded payloads, e.g. Myth stealer stage 2)
  * Rust toolchain fingerprint extraction (crate paths, /rustc/ commit)
  * crypto-constant scan (TEA/XTEA delta, AES S-box, ChaCha sigma, SHA-256 K)
  * --extract-myth: proof-of-concept static payload decryption for the Myth
    loader (xorshift32 obfstr keystream -> hex key -> repeating XOR), turning an
    encrypted stage-2 into scannable plaintext. "Static decryption as detection."

Usage:
  sride_triage.py FILE [FILE...]      triage report (text)
  sride_triage.py --json FILE         machine-readable
  sride_triage.py --chain-scan FILE   include ROP chain-pointer analysis
  sride_triage.py --extract-myth LOADER.exe out.dll   decrypt Myth stage-2

Requires: pefile (pip install pefile). Python 3.8+.
Defensive security research use only.
"""

import argparse
import hashlib
import json
import math
import os
import re
import struct
import sys

try:
    import pefile
except ImportError:
    sys.exit("pefile is required: pip install pefile")

ENTROPY_PACKED = 7.0     # Lyda & Hamrock 2007 threshold used by the paper
MIN_CHAIN_POINTERS = 3   # min run length of code-section pointers in data

# ---------------------------------------------------------------------------
# generic helpers
# ---------------------------------------------------------------------------

def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)

def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]

# ---------------------------------------------------------------------------
# Stage 1: triage — PE validity + per-section entropy  (paper Listing 3, fixed)
# ---------------------------------------------------------------------------

def triage(path):
    rep = {"path": path, "size": os.path.getsize(path)}
    data = open(path, "rb").read()
    rep["sha256"] = hashlib.sha256(data).hexdigest()
    rep["entropy_file"] = round(shannon(data), 3)
    try:
        pe = pefile.PE(path, fast_load=False)
    except pefile.PEFormatError as e:
        rep["pe"] = False
        rep["note"] = f"not a PE: {e}"
        rep["embedded_pe"] = find_embedded_pe(data)
        rep["rust"] = rust_fingerprints(data)
        rep["crypto"] = crypto_constants(data)
        return rep

    rep["pe"] = True
    rep["bits"] = 64 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 32
    rep["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
    rep["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
    rep["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)

    secs = []
    packed = []
    for s in pe.sections:
        raw = s.get_data()
        h = shannon(raw)
        name = s.Name.rstrip(b"\x00").decode("utf-8", "replace")
        chars = s.Characteristics
        secs.append({
            "name": name,
            "entropy": round(h, 3),
            "raw_size": s.SizeOfRawData,
            "virt_size": s.Misc_VirtualSize,
            "exec": bool(chars & 0x20000000),
            "write": bool(chars & 0x80000000),
            "va": hex(pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress),
            "raw_off": s.PointerToRawData,
        })
        if h > ENTROPY_PACKED and s.SizeOfRawData > 0x1000:
            packed.append((name, round(h, 3)))
    rep["sections"] = secs
    rep["packed_sections"] = packed

    # imports
    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in dll.imports:
                if imp.name:
                    imports.append(imp.name.decode("utf-8", "replace"))
    rep["imports"] = imports

    # ---------------------------------------------------------------
    # Stage 2: packer heuristics (DIE-style section names + import shape)
    # ---------------------------------------------------------------
    KNOWN_PACKER_SECTIONS = {
        "UPX0": "UPX", "UPX1": "UPX", "UPX!": "UPX",
        ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
        ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
        ".aspack": "ASPack", ".adata": "ASPack", ".petite": "Petite",
        ".enigma1": "Enigma", ".enigma2": "Enigma", ".nsp0": "NsPack",
        ".pec1": "PECompact", ".packed": "generic", ".rsrc0": "generic",
    }
    hits = [KNOWN_PACKER_SECTIONS[s["name"]] for s in secs
            if s["name"] in KNOWN_PACKER_SECTIONS]
    minimal = {"LoadLibraryA", "GetProcAddress", "VirtualAlloc",
               "VirtualProtect", "VirtualFree", "GetModuleHandleA",
               "GetProcAddress", "ExitProcess"}
    import_set = set(imports)
    indicators = list(hits)
    if imports and import_set <= minimal and len(import_set) <= 8:
        indicators.append(f"minimal import table ({sorted(import_set)})")
    for s in secs:
        if s["raw_size"] == 0 and s["virt_size"] > 0x10000:
            indicators.append(f"empty raw section {s['name']} (virt {s['virt_size']:#x})")
    if packed:
        indicators.append(f"high-entropy sections: {packed}")
    rep["packer_indicators"] = indicators

    rep["embedded_pe"] = find_embedded_pe(data)
    rep["rust"] = rust_fingerprints(data)
    rep["crypto"] = crypto_constants(data)

    if rep.get("chain_scan"):
        rep["rop"] = chain_scan(pe, data)
    pe.close()
    return rep

# ---------------------------------------------------------------------------
# chain-pointer verifier (fixes paper gap G1)
# ---------------------------------------------------------------------------
# The paper's thesis: an assembled ROP chain sits in a data section as a run of
# pointers into executable sections, interleaved with immediates (POP arguments).
# Its YARA rules never encode this; raw gadget bytes are matched instead.
# chain_scan() finds the pointer runs directly.

def chain_scan(pe, data, min_run=MIN_CHAIN_POINTERS):
    exec_ranges = []
    data_ranges = []
    base = pe.OPTIONAL_HEADER.ImageBase
    for s in pe.sections:
        va_lo = base + s.VirtualAddress
        va_hi = va_lo + max(s.Misc_VirtualSize, s.SizeOfRawData)
        name = s.Name.rstrip(b"\x00").decode("utf-8", "replace")
        rec = (va_lo, va_hi, s.PointerToRawData, s.SizeOfRawData)
        if s.Characteristics & 0x20000000:          # IMAGE_SCN_MEM_EXECUTE
            exec_ranges.append(rec)
        else:
            data_ranges.append(rec + (name,
                                      bool(s.Characteristics & 0x80000000)))

    width = 8 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 4
    read_ptr = u64 if width == 8 else u32

    # x64 function-start table from .pdata (RUNTIME_FUNCTION array).  Vtable /
    # shim / jump-table pointers always land on listed function starts; ROP
    # chain pointers land on mid-function gadgets.  Strongest discriminator
    # this tool has (x64 only; x86 PE32 has no .pdata).
    func_starts = set()
    func_ranges = []
    try:
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]   # IMAGE_DIRECTORY_ENTRY_EXCEPTION
        if dd.VirtualAddress and dd.Size:
            pdata_off = pe.get_offset_from_rva(dd.VirtualAddress)
            for k in range(0, dd.Size, 12):
                beg, end, _un = struct.unpack_from("<III", data, pdata_off + k)
                if beg:
                    func_starts.add(base + beg)
                    func_ranges.append((base + beg, base + end))
    except Exception:
        pass

    def in_exec(v):
        return any(lo <= v < hi for lo, hi, _, _ in exec_ranges)

    runs = []
    for va_lo, va_hi, raw_off, raw_size, sec_name, sec_write in data_ranges:
        i = 0
        run = []
        imms = 0
        avail = min(raw_size, len(data) - raw_off)
        while i + width <= avail:
            v = read_ptr(data, raw_off + i)
            if in_exec(v):
                run.append((raw_off + i, v))
                i += width
            else:
                # allow one immediate slot between pointers (POP argument)
                if run and i + 2 * width <= avail and \
                        in_exec(read_ptr(data, raw_off + i + width)):
                    imms += 1
                    i += width          # skip the immediate
                    continue
                if len(run) >= min_run:
                    runs.append({"file_off": hex(run[0][0]),
                                 "pointers": len(run),
                                 "section": sec_name, "writable": sec_write,
                                 "immediates": imms,
                                 "_t": [t for _, t in run]})
                run = []
                imms = 0
                i += width
        if len(run) >= min_run:
            runs.append({"file_off": hex(run[0][0]),
                         "pointers": len(run),
                         "section": sec_name, "writable": sec_write,
                         "immediates": imms,
                         "_t": [t for _, t in run]})

    # --- gadget typing (capstone) -------------------------------------------
    # Classify each pointer target by chain role, following the paper's
    # taxonomy: PIVOT (redirects the stack), POP (POP r;RET spine element),
    # TERM (syscall / indirect branch — final dispatch), OTHER (anything else,
    # e.g. the `xor eax,eax;ret` / `movabs;ret` leaf functions that Rust/LLVM
    # emit and that naive "ends in RET" checks cannot tell apart from gadgets).
    # A verified chain must show the spine SHAPE, not just gadget-shaped bytes:
    #   SHAPE A: >=2 POP gadgets AND (>=1 PIVOT OR >=1 TERM)
    #   SHAPE B: >=1 PIVOT AND >=1 TERM (short pivot->dispatch chains)
    def va_to_off(v):
        for lo, hi, raw_off, raw_size in exec_ranges:
            if lo <= v < hi:
                return raw_off + (v - lo)
        return None

    def gadget_type(v, max_insns=8):
        if cs is None:
            return None
        off = va_to_off(v)
        if off is None or off + 16 > len(data):
            return "OTHER"
        try:
            insns = list(cs.disasm(data[off:off + 32], 0, count=max_insns))
        except Exception:
            return "OTHER"
        if not insns:
            return "OTHER"
        term = None
        for insn in insns:
            g = insn.groups
            if cs_grp_ret and cs_grp_ret in g:
                term = "RET"
                break
            if insn.bytes[:2] in (b"\x0f\x05", b"\x0f\x34"):  # syscall/sysenter
                term = "SYS"
                break
            if insn.bytes[0] == 0xFF and len(insn.bytes) > 1 and \
                    insn.bytes[1] in (0xD0, 0xD1, 0xD2, 0xD3, 0xD6, 0xD7,
                                      0xE0, 0xE1, 0xE2, 0xE3, 0xE6, 0xE7):
                term = "BRANCH"                # call/jmp r/m
                break
            if cs_grp_jump and cs_grp_jump in g:
                return "OTHER"                 # other jump: not a gadget
        if term is None:
            return "OTHER"
        if term in ("SYS", "BRANCH"):
            return "TERM"
        f = insns[0]
        ops = f.op_str.replace(" ", "")
        stack_regs = ("esp", "rsp")
        if f.mnemonic == "leave":
            return "PIVOT"
        if f.mnemonic == "pop":
            return "PIVOT" if any(r in ops for r in stack_regs) else "POP"
        if f.mnemonic in ("xchg", "mov") and \
                any(ops.startswith(r + ",") or ops.endswith("," + r)
                    for r in stack_regs):
            return "PIVOT"
        return "OTHER"

    try:
        import capstone as _cs
        mode = _cs.CS_MODE_64 if width == 8 else _cs.CS_MODE_32
        cs = _cs.Cs(_cs.CS_ARCH_X86, mode)
        cs.detail = True                   # needed for insn.groups
        cs_grp_ret = _cs.CS_GRP_RET
        cs_grp_jump = _cs.CS_GRP_JUMP
    except ImportError:
        cs = None
        cs_grp_ret = cs_grp_jump = None

    # classic function-prologue byte patterns: vtable/jump-table targets start
    # with these; ROP chain targets (mid-function gadgets) do not.
    PROLOGUES = (b"\x55\x48\x89\xe5",          # push rbp; mov rbp,rsp
                 b"\x48\x89\x5c\x24",          # mov [rsp+x],rbx
                 b"\x48\x89\x74\x24",          # mov [rsp+x],rsi
                 b"\x48\x89\x7c\x24",          # mov [rsp+x],rdi
                 b"\x48\x89\x4c\x24",          # mov [rsp+x],rcx
                 b"\x48\x83\xec",              # sub rsp,imm8
                 b"\x48\x81\xec")              # sub rsp,imm32

    def looks_prologue(v):
        off = va_to_off(v)
        if off is None:
            return False
        head = data[off:off + 4]
        return any(head.startswith(p) for p in PROLOGUES)

    for run in runs:
        targets = run.pop("_t")
        run["targets"] = [hex(t) for t in targets[:8]]
        run["distinct_targets"] = len(set(targets))
        if cs is None:
            run["gadget_verified"] = None
            continue
        types = [gadget_type(t) for t in targets]
        run["types"] = {"PIVOT": types.count("PIVOT"),
                        "POP": types.count("POP"),
                        "TERM": types.count("TERM"),
                        "OTHER": types.count("OTHER")}
        ok = sum(1 for t in types if t != "OTHER")
        pro = sum(1 for t in targets if looks_prologue(t))
        run["gadget_ratio"] = round(ok / len(targets), 2)
        run["prologue_ratio"] = round(pro / len(targets), 2)
        # jump tables cluster: consecutive case bodies sit a few bytes apart.
        # Real chain gadgets are scattered across the address space.
        pairs = [abs(b - a) for a, b in zip(targets, targets[1:])]
        run["clustered"] = bool(pairs) and \
            sum(1 for d in pairs if d < 32) / len(pairs) >= 0.6
        # .pdata discriminator (x64): vtable/shim pointers are listed function
        # starts; chain gadgets are not.
        if func_starts:
            mid = sum(1 for t in targets if t not in func_starts)
            run["midfunc_ratio"] = round(mid / len(targets), 2)
        else:
            run["midfunc_ratio"] = None
        # jump-table discriminator: all targets of a switch table live inside
        # ONE function's [begin,end) range.  Chain gadgets are scattered over
        # multiple functions (or outside all of them).  Out-of-function
        # targets each count as their own bucket.
        if func_ranges:
            def bucket(v):
                for i, (lo, hi) in enumerate(func_ranges):
                    if lo <= v < hi:
                        return ("func", i)
                return ("out", v)        # same addr → same bucket
            run["distinct_funcs"] = len({bucket(t) for t in targets})
        else:
            run["distinct_funcs"] = None
        # tiered verdict:
        #  spine shape required (the paper's taxonomy, enforced semantically):
        #    SHAPE A: >=2 POP + (>=1 PIVOT or >=1 TERM)
        #    SHAPE B: >=1 PIVOT + >=1 TERM
        #  verified  = spine shape + distinct, prologue-free, unclustered,
        #              mostly mid-function targets spanning >=2 functions
        #              (when .pdata exists), in a writable/immediate-bearing
        #              region
        #  candidate = spine shape in read-only immediate-less region
        shape = ((run["types"]["POP"] >= 2 and
                  (run["types"]["PIVOT"] >= 1 or run["types"]["TERM"] >= 1))
                 or (run["types"]["PIVOT"] >= 1 and run["types"]["TERM"] >= 1
                     and run["pointers"] >= 3))
        structural = (shape
                      and run["gadget_ratio"] >= 0.5
                      and run["distinct_targets"] >= 2
                      and run["prologue_ratio"] <= 0.2
                      and not run["clustered"]
                      and (run["midfunc_ratio"] is None
                           or run["midfunc_ratio"] >= 0.5)
                      and (run["distinct_funcs"] is None
                           or run["distinct_funcs"] >= 2))
        run["gadget_verified"] = bool(
            structural and (run["writable"] or run["immediates"] > 0))
        run["candidate"] = bool(structural and not run["gadget_verified"])

    # gadget census: potential gadgets in code (the denominator every binary has)
    census = {"pop_ret": 0, "pivot": 0, "terminator": 0}
    pop_ret = set(range(0x58, 0x60))
    for lo, hi, raw_off, raw_size in exec_ranges:
        code = data[raw_off:raw_off + raw_size]
        for j in range(len(code) - 1):
            if code[j + 1] == 0xC3 and code[j] in pop_ret:
                census["pop_ret"] += 1
            if code[j] == 0x94 or (code[j] == 0x89 and code[j + 1] == 0xC4):
                census["pivot"] += 1
            if code[j] == 0xFF and code[j + 1] in (0xD0, 0xE0, 0xD6):
                census["terminator"] += 1

    verified = [r for r in runs if r.get("gadget_verified")]
    candidates = [r for r in runs if r.get("candidate")]
    rejected = sum(1 for r in runs
                   if not r.get("gadget_verified") and not r.get("candidate"))
    return {"verified_chains": verified,
            "candidate_chains": candidates,
            "rejected_pointer_runs": rejected,
            "gadget_census": census,
            "note": "runs of >=%d data-section pointers into executable "
                    "sections; verified = gadget-shaped, distinct, "
                    "prologue-free targets in writable/immediate-interleaved "
                    "form" % min_run}

# ---------------------------------------------------------------------------
# embedded PE hunt (reflective / packed second stages)
# ---------------------------------------------------------------------------

DOS_STUB_MSG = b"This program cannot be run in DOS mode"

def find_embedded_pe(data: bytes):
    found = []
    # an inner PE usually re-carries the DOS stub message
    offs = [m.start() for m in re.finditer(re.escape(DOS_STUB_MSG), data)]
    mz_candidates = {m.start() for m in re.finditer(b"MZ", data[:len(data)])}
    for off in mz_candidates:
        if off == 0 or off + 0x40 > len(data):
            continue
        try:
            e_lfanew = u32(data, off + 0x3C)
        except struct.error:
            continue
        if not (0 < e_lfanew < 0x1000) or off + e_lfanew + 4 > len(data):
            continue
        if data[off + e_lfanew:off + e_lfanew + 4] != b"PE\x00\x00":
            continue
        found.append({"file_off": hex(off),
                      "region_entropy": round(
                          shannon(data[max(0, off - 0x100):off + 0x1000]), 3)})
        if len(found) >= 8:
            break
    return {"plaintext_inner_pes": found,
            "dos_stub_occurrences": len(offs),
            "note": "inner MZ inside a high-entropy region = encrypted payload; "
                    "plaintext inner MZ = reflective-load / bundle candidate"}

# ---------------------------------------------------------------------------
# Rust toolchain fingerprints  (see research/04 §7)
# ---------------------------------------------------------------------------

RE_RUSTC = re.compile(rb"/rustc/([0-9a-f]{40})")
RE_CRATE_REG = re.compile(
    rb"(?:registry/src/(?:index\.crates\.io-[0-9a-f]+|github\.com-[0-9a-f]+)"
    rb"/|cargo/registry/src/[^/]{1,64}/)([a-z0-9_\-]+-[0-9][0-9a-z.\-]*)/")
RE_PANIC = re.compile(rb"called `(?:Option|Result)::(?:unwrap|expect)\(\)`")

def rust_fingerprints(data: bytes):
    rustc = sorted({m.group(1).decode() for m in RE_RUSTC.finditer(data)})
    crates = sorted({m.group(1).decode("utf-8", "replace")
                     for m in RE_CRATE_REG.finditer(data)})
    return {
        "rustc_commits": rustc,
        "crates": crates[:200],
        "panic_strings": bool(RE_PANIC.search(data)),
        "is_rust": bool(rustc or crates),
    }

# ---------------------------------------------------------------------------
# crypto constants (family anchors that survive recompilation)
# ---------------------------------------------------------------------------

CRYPTO = [
    ("TEA/XTEA delta 0x9E3779B9",     bytes.fromhex("b979379e")),
    ("TEA neg-delta 0x61C88647",      bytes.fromhex("4786c861")),
    ("ChaCha sigma 'expand 32-byte k'", b"expand 32-byte k"),
    ("AES S-box prefix",              bytes.fromhex("637c777bf26b6fc5")),
    ("SHA-256 K prefix",              bytes.fromhex("428a2f9871374491")),
    ("Myth obfstr xorshift seed 0x18385CA6", bytes.fromhex("a65c3818")),
]

def crypto_constants(data: bytes):
    out = []
    for name, pat in CRYPTO:
        off = data.find(pat)
        if off != -1:
            out.append({"const": name, "first_off": hex(off)})
    return out

# ---------------------------------------------------------------------------
# Myth loader static payload extraction (proof of concept)
# ---------------------------------------------------------------------------
# From mythstealer/reconstructed/README.md:
#   seed = 0x18385CA6; xorshift32 -> 16 x u32 LE = 64-byte keystream
#   obfstr ciphertext (64 B, file off 0x1bb7608 in the analyzed sample)
#       XOR keystream -> 64-char ASCII hex = 32-byte payload key
#   payload at file off 0x0a86c0, length 0x1b0ef2e, repeating-XOR with key
# Defaults are the analyzed sample's constants; overridable on the CLI.

MYTH = {
    "seed": 0x18385CA6,
    "key_ct_off": 0x1BB7608,
    "payload_off": 0x0A86C0,
    "payload_len": 0x1B0EF2E,
    "known_dll_sha256":
        "be2476c80ecd7819fc9c08d63e287ba933e3ab98459f02d177e662c3d7038219",
}

def xorshift32_stream(seed: int, nwords: int = 16) -> bytes:
    out = bytearray()
    x = seed & 0xFFFFFFFF
    for _ in range(nwords):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17)
        x ^= (x << 5) & 0xFFFFFFFF
        out += struct.pack("<I", x)
    return bytes(out)

def myth_derive_key(loader: bytes, key_ct_off: int, seed: int) -> bytes:
    ct = loader[key_ct_off:key_ct_off + 64]
    ks = xorshift32_stream(seed, 16)
    hexkey = bytes(c ^ k for c, k in zip(ct, ks)).decode("ascii")
    hexkey = hexkey[2:] if hexkey.startswith("0x") else hexkey
    return bytes.fromhex(hexkey)

def myth_decrypt(loader: bytes, off: int, length: int, key: bytes) -> bytes:
    blob = loader[off:off + length]
    kl = len(key)
    return bytes(b ^ key[i % kl] for i, b in enumerate(blob))

def extract_myth(path, out_path, key_ct_off, payload_off, payload_len, seed):
    loader = open(path, "rb").read()
    key = myth_derive_key(loader, key_ct_off, seed)
    print(f"[*] derived payload key: {key.hex()}")
    plain = myth_decrypt(loader, payload_off, payload_len, key)
    digest = hashlib.sha256(plain).hexdigest()
    print(f"[*] decrypted {len(plain)} bytes, sha256={digest}")
    if plain[:2] == b"MZ":
        print("[+] plaintext starts with MZ — decryption coherent")
    else:
        print("[!] plaintext does NOT start with MZ — offsets/seed wrong "
              "for this sample?")
    if digest == MYTH["known_dll_sha256"]:
        print("[+] sha256 matches the analyzed Myth stealer DLL "
              "(be2476c8…) — extractor verified")
    open(out_path, "wb").write(plain)
    print(f"[*] wrote {out_path} — feed it back to this tool / YARA rules")

# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def print_text(rep):
    if rep.get("error") and "size" not in rep:
        print(f"== {rep['path']}\n   error: {rep['error']}")
        return
    print(f"== {rep['path']}  ({rep['size']} bytes)")
    print(f"   sha256 {rep['sha256']}")
    print(f"   entropy(file) {rep['entropy_file']}")
    if not rep.get("pe"):
        print(f"   not a PE: {rep.get('note','')}")
    else:
        print(f"   PE{rep['bits']} imagebase {rep['image_base']} "
              f"{'DLL' if rep['is_dll'] else 'EXE'}")
        for s in rep["sections"]:
            flag = "  <-- PACKED?" if s["entropy"] > ENTROPY_PACKED else ""
            print(f"   sec {s['name']:<10} H={s['entropy']:<6} "
                  f"raw={s['raw_size']:<10} "
                  f"{'X' if s['exec'] else '-'}{'W' if s['write'] else '-'}"
                  f"{flag}")
        if rep["packer_indicators"]:
            print(f"   packer indicators: {rep['packer_indicators']}")
    r = rep.get("rust", {})
    if r.get("is_rust"):
        print(f"   RUST: rustc={r['rustc_commits']} crates={len(r['crates'])}")
        for c in r["crates"][:12]:
            print(f"         crate {c}")
    if rep.get("crypto"):
        for c in rep["crypto"]:
            print(f"   crypto: {c['const']} @ {c['first_off']}")
    ep = rep.get("embedded_pe", {})
    if ep.get("plaintext_inner_pes"):
        print(f"   embedded PEs: {ep['plaintext_inner_pes']}")
    if ep.get("dos_stub_occurrences", 0) > 1:
        print(f"   DOS stub message x{ep['dos_stub_occurrences']} "
              f"(inner PE likely)")
    if rep.get("rop"):
        rop = rep["rop"]
        print(f"   gadget census (potential): {rop['gadget_census']}")
        for run in rop.get("verified_chains", []):
            print(f"   VERIFIED CHAIN @ {run['file_off']} ({run['section']}"
                  f"{'/W' if run['writable'] else ''}): {run['pointers']} "
                  f"pointers, {run['immediates']} immediates, "
                  f"gadget-ratio {run.get('gadget_ratio')} "
                  f"-> {run['targets'][:4]} …")
        for run in rop.get("candidate_chains", []):
            print(f"   candidate chain @ {run['file_off']} ({run['section']}): "
                  f"{run['pointers']} pointers, "
                  f"gadget-ratio {run.get('gadget_ratio')}")
        if not rop.get("verified_chains") and not rop.get("candidate_chains"):
            print(f"   no chains found "
                  f"(rejected {rop.get('rejected_pointer_runs', '?')} "
                  f"pointer runs as jump-tables/vtables)")

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--chain-scan", action="store_true")
    ap.add_argument("--extract-myth", metavar="OUT",
                    help="decrypt Myth stage-2 payload to OUT")
    ap.add_argument("--myth-key-ct-off", type=lambda x: int(x, 0),
                    default=MYTH["key_ct_off"])
    ap.add_argument("--myth-payload-off", type=lambda x: int(x, 0),
                    default=MYTH["payload_off"])
    ap.add_argument("--myth-payload-len", type=lambda x: int(x, 0),
                    default=MYTH["payload_len"])
    ap.add_argument("--myth-seed", type=lambda x: int(x, 0),
                    default=MYTH["seed"])
    args = ap.parse_args()

    if args.extract_myth:
        extract_myth(args.files[0], args.extract_myth,
                     args.myth_key_ct_off, args.myth_payload_off,
                     args.myth_payload_len, args.myth_seed)
        return

    reps = []
    for f in args.files:
        if os.path.isdir(f):
            for root, _, names in os.walk(f):
                for n in names:
                    reps.append(collect(os.path.join(root, n), args))
        else:
            reps.append(collect(f, args))

    if args.json:
        print(json.dumps(reps, indent=2))
    else:
        for r in reps:
            print_text(r)
            print()

def collect(path, args):
    try:
        rep = triage(path)
    except Exception as e:                      # keep batch scans alive
        return {"path": path, "error": str(e)}
    if args.chain_scan and rep.get("pe"):
        try:
            pe = pefile.PE(path, fast_load=True)
            rep["rop"] = chain_scan(pe, open(path, "rb").read())
            pe.close()
        except Exception as e:
            rep["rop_error"] = str(e)
    return rep

if __name__ == "__main__":
    main()
