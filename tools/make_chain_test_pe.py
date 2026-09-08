#!/usr/bin/env python3
"""
make_chain_test_pe.py — synthetic positive/negative controls for chain-scan

Builds a minimal PE32+ (x64) containing:
  .text   real gadgets at known VAs + one normal function (prologue…ret)
  .data   an assembled ROP chain (pivot, POP;RET spine, syscall terminator)
          [POSITIVE control — must verify]
  .rdata  a fake "vtable": pointers at the normal function's start
          [NEGATIVE control — must be rejected]
  .pdata  RUNTIME_FUNCTION entry covering the normal function only

Defensive security research use only.
"""

import struct
import sys

IB = 0x140000000
FA = 0x200          # file alignment
SA = 0x1000         # section alignment

def build(path):
    # ---------------- section contents ----------------
    text = bytearray(0x200)
    # gadgets spread across .text (mid-section, NOT function starts):
    text[0x00:0x02] = b"\x5f\xc3"              # pop rdi ; ret      @ +0x1000
    text[0x40:0x42] = b"\x5e\xc3"              # pop rsi ; ret      @ +0x1040
    text[0x80:0x82] = b"\x5a\xc3"              # pop rdx ; ret      @ +0x1080
    text[0xC0:0xC3] = b"\x0f\x05\xc3"          # syscall ; ret      @ +0x10C0
    text[0xE0:0xE2] = b"\x94\xc3"              # xchg eax,esp ; ret @ +0x10E0
    # a normal function with prologue @ +0x1100 (in .pdata)
    text[0x100:0x108] = b"\x55\x48\x89\xe5\x48\x83\xec\x20"   # classic prologue
    text[0x108:0x10c] = b"\x48\x83\xc4\x20"                   # add rsp,0x20
    text[0x10c] = 0xC3                                        # ret

    chain = struct.pack("<QQQQQQ",
                        IB + 0x10E0,            # pivot
                        IB + 0x1000,            # pop rdi ; ret
                        0xDEADBEEF,             # imm (arg)
                        IB + 0x1040,            # pop rsi ; ret
                        IB + 0x1080,            # pop rdx ; ret
                        IB + 0x10C0)            # syscall ; ret
    data = chain.ljust(0x200, b"\x00")

    vtable = struct.pack("<QQQ",
                         IB + 0x1100, IB + 0x1100, IB + 0x1100)  # fn starts
    rdata = vtable.ljust(0x200, b"\x00")

    # .pdata: one RUNTIME_FUNCTION {begin,end,unwind} for the normal function
    pdata = struct.pack("<III", 0x1100, 0x110D, 0).ljust(0x200, b"\x00")

    # ---------------- headers ----------------
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)     # e_lfanew

    coff = struct.pack("<HHIIIHH",
                       0x8664,                  # AMD64
                       4,                       # sections
                       0, 0, 0,
                       0xF0,                    # sizeof optional header
                       0x0022)                  # EXECUTABLE|LARGE_ADDRESS

    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0x00, 0x20B)    # PE32+
    struct.pack_into("<I", opt, 0x10, 0x1000)   # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 0x18, IB)       # ImageBase
    struct.pack_into("<I", opt, 0x20, SA)
    struct.pack_into("<I", opt, 0x24, FA)
    struct.pack_into("<I", opt, 0x38, 0x5000)   # SizeOfImage
    struct.pack_into("<I", opt, 0x3C, 0x400)    # SizeOfHeaders
    struct.pack_into("<H", opt, 0x44, 3)        # subsystem CUI
    struct.pack_into("<I", opt, 0x6C, 16)       # NumberOfRvaAndSizes
    # data directory [3] = exception (.pdata)
    struct.pack_into("<II", opt, 0x60 + 3 * 8, 0x4000, 12)

    def sec_hdr(name, vsize, va, raw_size, raw_ptr, chars):
        return struct.pack("<8sIIIIIIHHI", name, vsize, va, raw_size,
                           raw_ptr, 0, 0, 0, 0, chars)

    hdrs = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt)
    sh = b"".join([
        sec_hdr(b".text\0\0\0", 0x200, 0x1000, 0x200, 0x400, 0x60000020),
        sec_hdr(b".data\0\0\0", 0x200, 0x2000, 0x200, 0x600, 0xC0000040),
        sec_hdr(b".rdata\0\0", 0x200, 0x3000, 0x200, 0x800, 0x40000040),
        sec_hdr(b".pdata\0\0", 0x200, 0x4000, 0x200, 0xA00, 0x40000040),
    ])
    blob = (hdrs + sh).ljust(0x400, b"\x00") + bytes(text) + data + rdata + pdata
    open(path, "wb").write(blob)
    print(f"wrote {path} ({len(blob)} bytes)")
    print("positive control: chain in .data -> gadgets at "
          "0x1400010E0/1000/1040/1080/10C0")
    print("negative control: vtable in .rdata -> function start 0x140001100")

if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "chain_test.exe")
