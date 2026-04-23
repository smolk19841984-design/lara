#!/usr/bin/env python3
"""
Offline: locate evidence for P0 kernel targets on 21D61 iPad8,9 kernelcache.
Uses MachOMap: cstring hits + 8-byte values at known candidate offsets.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from typing import List, Optional, Tuple

# allow import from same directory
SCRIPT_DIR = __import__("os").path.dirname(__import__("os").path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
from offline_ios17_kernelmap import MachOMap

MH_KERN_PTR_MIN = 0xFFFFFF8000000000
MH_KERN_PTR_MAX = 0xFFFFFFFFFFFFFFFF


def is_plausible_kptr(q: int) -> bool:
    if q == 0:
        return True
    return MH_KERN_PTR_MIN <= q <= MH_KERN_PTR_MAX


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--kernel",
        default="iPad8,9_Analysis/21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed",
    )
    ap.add_argument("--json", action="store_true", help="print one JSON object")
    args = ap.parse_args()
    km = MachOMap(args.kernel)
    kbase = min(s.vmaddr for s in km.segments)

    needles: List[bytes] = [
        b"kernproc",
        b"allproc",
        b"rootvnode",
        b"pmap_image4_trust_caches",
        b"PE_i_can_has_debugger",
        b"cs_enforcement_disable",
        b"IPE_i_can_has_debugger",  # sometimes I-prefix in panic strings
    ]

    string_hits: dict = {}
    for n in needles:
        hits: List[Tuple[str, str]] = []
        for vm, fo in km.vm_find(n):
            sec = km.section_for_vm(vm)
            sname = f"{sec.segname}.{sec.sectname}" if sec else "?"
            hits.append((f"0x{vm:016X}", sname))
        if hits:
            string_hits[n.decode("ascii", errors="replace")] = hits[:8]

    # Offsets from repo verified_offsets.json (candidates to validate)
    test_globals = {
        "_kernproc": 0x96B928,
        "_rootvnode": 0x3213640,
        "pmap_image4_trust_caches": 0xABE968,
        "PE_i_can_has_debugger": 0x81E3D8,
    }
    at_offset: dict = {}
    for name, off in test_globals.items():
        va = int(kbase + off)
        try:
            b8 = km.vm_read(va, 8)
        except ValueError as e:
            at_offset[name] = {"err": str(e), "koffset": f"0x{off:08X}"}
            continue
        q = struct.unpack("<Q", b8)[0]
        one = b8[0] if b8 else 0
        sec = km.section_for_vm(va)
        at_offset[name] = {
            "koffset": f"0x{off:08X}",
            "va": f"0x{va:016X}",
            "u64": f"0x{q:016X}",
            "low_u8": int(one),  # PE is often a byte flag
            "section": f"{sec.segname}.{sec.sectname}" if sec else None,
            "kptr_plausible_64": is_plausible_kptr(q) if one != 0 else "zero_or_undef",
        }

    # allproc: often next to / referenced from code; no fixed offset in JSON
    at_offset["_allproc"] = {"note": "no static offset in verified_offsets; search xref from kernproc chain"}

    out = {
        "kernel": args.kernel,
        "KERNEL_BASE": f"0x{kbase:016X}",
        "string_hits_cstring": string_hits,
        "read_at_offset_from_kbase": at_offset,
    }
    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print("KERNEL_BASE", f"0x{kbase:016X}")
        print("\n[Strings in mapped Mach-O]:")
        for k, v in string_hits.items():
            print(" ", k, "->", v[:3], ("..." if len(v) > 3 else ""))
        print("\n[8-byte / byte read at kbase + offset]:")
        for k, v in at_offset.items():
            print(" ", k, v)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
