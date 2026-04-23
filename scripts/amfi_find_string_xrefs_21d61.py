#!/usr/bin/env python3
"""
Disassemble AMFI kext __TEXT_EXEC.__text (arm64) and find ADRP(+ADD)/ADR
that reference a known cstring vmaddr (e.g. cs_enforcement_disable).
"""

from __future__ import annotations

import argparse
import struct
import sys

try:
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
except ImportError:
    print("Need: pip install capstone", file=sys.stderr)
    raise

import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
from offline_ios17_kernelmap import MachOMap

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19


def _u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


def _u64(d: bytes, o: int) -> int:
    return struct.unpack_from("<Q", d, o)[0]


def _cstr16(b: bytes) -> str:
    return b.rstrip(b"\x00").decode("utf-8", errors="replace")


def find_section_file_range(
    data: bytes, seg: str, sect: str
) -> tuple[int, int, int] | None:
    """Return (vmaddr_start, fileoff_start, size) for section."""
    if _u32(data, 0) != MH_MAGIC_64:
        return None
    ncmds = _u32(data, 16)
    o = 32
    for _ in range(ncmds):
        cmd = _u32(data, o)
        csz = _u32(data, o + 4)
        if cmd == LC_SEGMENT_64:
            nsects = _u32(data, o + 64)
            sect_off = o + 72
            for _i in range(nsects):
                sectname = _cstr16(data[sect_off : sect_off + 16])
                seg_n = _cstr16(data[sect_off + 16 : sect_off + 32])
                s_addr = _u64(data, sect_off + 32)
                s_size = _u64(data, sect_off + 40)
                s_off = _u32(data, sect_off + 48)
                if seg_n == seg and sectname == sect:
                    return (int(s_addr), int(s_off), int(s_size))
                sect_off += 80
        o += csz
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--amfi",
        default="iPad8,9_Analysis/21D61/kernelcache_decompressed/kexts/com.apple.driver.AppleMobileFileIntegrity",
    )
    ap.add_argument(
        "--target-vm",
        default="0xFFFFFFF007410E50",
        help="KVA of cstring (e.g. cs_enforcement_disable)",
    )
    args = ap.parse_args()
    target = int(args.target_vm, 16)
    target_page = target & ~0xFFF

    with open(args.amfi, "rb") as f:
        data = f.read()

    r = find_section_file_range(data, "__TEXT_EXEC", "__text")
    if not r:
        print("no __TEXT_EXEC.__text", file=sys.stderr)
        return 1
    vm0, fo, sz = r
    code = data[fo : fo + sz]
    km = MachOMap(args.amfi)  # for fileoff->vm in edge cases
    _ = km

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    hits: list[dict] = []
    for insn in md.disasm(code, vm0):
        if insn.mnemonic not in ("adrp", "adr", "add", "adds"):
            continue
        s = insn.op_str
        if f"0x{target:08x}" in s or f"0x{target:016x}" in s or f"#{target}" in s:
            hits.append({"addr": f"0x{insn.address:016X}", "asm": f"{insn.mnemonic} {s}"})
            continue
        if insn.mnemonic == "adrp" and f"0x{target_page:08x}" in s:
            hits.append({"addr": f"0x{insn.address:016X}", "asm": f"{insn.mnemonic} {s}"})

    # second pass: print insns that mention '410e' (page fragment)
    if not hits:
        for insn in md.disasm(code, vm0):
            s = insn.op_str
            if "0x41" in s and "0x4" in s and len(s) < 80:
                if "0x410" in s or "0x410e" in s.lower():
                    hits.append(
                        {
                            "addr": f"0x{insn.address:016X}",
                            "asm": f"{insn.mnemonic} {s}",
                        }
                    )

    print("target", hex(target), "page", hex(target_page), "text", hex(vm0), "-", hex(vm0 + sz))
    for h in hits[:40]:
        print(h)
    if not hits:
        print("No direct operand match; try manual analysis or different string.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
