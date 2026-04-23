#!/usr/bin/env python3
"""
lookup_macho_symtab.py

Offline: parse LC_SYMTAB / string table in Mach-O arm64, find symbols by name
and print absolute vmaddr, offset from kernel image base, and file offset.

iOS 17+ kernelcaches are often *stripped*; release builds may have 0 or few
useful nlist names. This still answers "are there symbol-table proofs?" when
you have the on-disk dump.

Usage (after placing dumps per doc/AI_TASK_OFFSETS_21D61.md):

  python3 scripts/lookup_macho_symtab.py \\
    --kernel iPad8,9_Analysis/21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed \\
    --amfi   iPad8,9_Analysis/21D61/kernelcache_decompressed/kexts/com.apple.driver.AppleMobileFileIntegrity

  # Or a single file:
  python3 scripts/lookup_macho_symtab.py -f kext --want cs_enforcement_disable,check_amfi
"""

from __future__ import annotations

import argparse
import json
import os
import struct
from dataclasses import dataclass
from typing import List, Optional, Set, Tuple

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2


def _u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


def _u64(d: bytes, o: int) -> int:
    return struct.unpack_from("<Q", d, o)[0]


@dataclass(frozen=True)
class SymTabCmd:
    symoff: int
    nsyms: int
    stroff: int
    strsize: int


@dataclass(frozen=True)
class Nlist64:
    n_strx: int
    n_type: int
    n_sect: int
    n_desc: int
    n_value: int


def _parse_nlist64(data: bytes, off: int) -> Nlist64:
    return Nlist64(
        n_strx=_u32(data, off + 0),
        n_type=data[off + 4],
        n_sect=data[off + 5],
        n_desc=struct.unpack_from("<H", data, off + 6)[0],
        n_value=_u64(data, off + 8),
    )


def _cstr_strtab(d: bytes, strtab: bytes, strx: int) -> str:
    if strx < 0 or strx >= len(strtab):
        return ""
    end = strtab.find(b"\x00", strx)
    if end < 0:
        s = strtab[strx:]
    else:
        s = strtab[strx:end]
    return s.decode("utf-8", errors="replace")


def _lowest_segment_vmaddr(d: bytes) -> Optional[int]:
    if _u32(d, 0) != MH_MAGIC_64:
        return None
    ncmds = _u32(d, 16)
    o = 32
    m: Optional[int] = None
    for _ in range(ncmds):
        cmd = _u32(d, o)
        csz = _u32(d, o + 4)
        if cmd == LC_SEGMENT_64:
            vm = _u64(d, o + 24)
            m = vm if m is None else min(m, vm)
        o += csz
    return m


def _find_symtab(d: bytes) -> Optional[SymTabCmd]:
    ncmds = _u32(d, 16)
    o = 32
    for _ in range(ncmds):
        cmd = _u32(d, o)
        csz = _u32(d, o + 4)
        if cmd == LC_SYMTAB:
            return SymTabCmd(
                symoff=_u32(d, o + 8),
                nsyms=_u32(d, o + 12),
                stroff=_u32(d, o + 16),
                strsize=_u32(d, o + 20),
            )
        o += csz
    return None


def _fileoff_for_vm(d: bytes, vmaddr: int) -> Optional[int]:
    ncmds = _u32(d, 16)
    o = 32
    for _ in range(ncmds):
        cmd = _u32(d, o)
        csz = _u32(d, o + 4)
        if cmd == LC_SEGMENT_64:
            seg_vm = _u64(d, o + 24)
            vmsize = _u64(d, o + 32)
            fileoff = _u64(d, o + 40)
            filesz = _u64(d, o + 48)
            if seg_vm <= vmaddr < (seg_vm + vmsize):
                delta = vmaddr - seg_vm
                if delta < filesz:
                    return int(fileoff + delta)
        o += csz
    return None


def _name_variants(name: str) -> Set[str]:
    s = {name, name.lstrip("_")}
    u = {n if n.startswith("_") else "_" + n for n in s}
    return s | u


def parse_symbols(
    d: bytes, path: str, want: Set[str]
) -> List[dict]:
    st = _find_symtab(d)
    if not st:
        return [{"_error": f"{path}: no LC_SYMTAB"}]
    if st.nsyms == 0 or st.symoff + st.nsyms * 16 > len(d):
        return [{"_error": f"{path}: bad symtab (nsyms={st.nsyms}, symoff=0x{st.symoff:X})"}]
    if st.stroff + st.strsize > len(d):
        return [{"_error": f"{path}: bad strtab size"}]

    strtab = d[st.stroff : st.stroff + st.strsize]
    wantv: Set[str] = set()
    for w in want:
        wantv |= _name_variants(w)

    out: List[dict] = []
    symo = st.symoff
    for i in range(st.nsyms):
        nl = _parse_nlist64(d, symo)
        symo += 16
        nam = _cstr_strtab(d, strtab, nl.n_strx)
        if not nam or nam not in wantv:
            continue
        fo = _fileoff_for_vm(d, int(nl.n_value))
        out.append(
            {
                "name": nam,
                "n_type": f"0x{nl.n_type:02X}",
                "n_sect": int(nl.n_sect),
                "vmaddr": f"0x{nl.n_value:016X}",
                "fileoff": f"0x{fo:X}" if fo is not None else None,
            }
        )
    if not out:
        return [
            {
                "_note": f"{path}: symtab has {st.nsyms} entries, none of {sorted(want)} (often stripped in release).",
            }
        ]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--kernel",
        help="Kernelcache Mach-O: used to report image_base (min LC_SEGMENT_64 vmaddr) for offset_from_image_base",
    )
    ap.add_argument("--amfi", help="AMFI kext (optional) for cs_enforcement_disable, etc.")
    ap.add_argument("-f", "--file", help="Any single Mach-O to scan (optional if --kernel/--amfi set)")
    ap.add_argument(
        "--want",
        default="_kernproc,_allproc,_rootvnode,pmap_image4_trust_caches,PE_i_can_has_debugger,cs_enforcement_disable,check_amfi",
    )
    args = ap.parse_args()
    want = {x.strip() for x in args.want.split(",") if x.strip()}

    def load(p: str) -> bytes:
        with open(p, "rb") as fp:
            return fp.read()

    report: dict = {
        "want": sorted(want),
        "files": {},
    }

    image_base: Optional[int] = None
    if args.kernel and os.path.isfile(args.kernel):
        kd = load(args.kernel)
        image_base = _lowest_segment_vmaddr(kd)
        report["kernel"] = {
            "path": args.kernel,
            "lowest_LCsegment_vmaddr": f"0x{image_base:016X}" if image_base else None,
        }
    files: List[Tuple[str, str]] = []
    if args.file:
        files.append(("file", args.file))
    if args.kernel:
        files.append(("kernelcache", args.kernel))
    if args.amfi:
        files.append(("amfi", args.amfi))
    for label, path in files:
        if not os.path.isfile(path):
            report["files"][label] = {"path": path, "error": "file not found"}
            continue
        d = load(path)
        res = parse_symbols(d, path, want)
        entry: dict = {"path": path, "results": res}
        this_base = _lowest_segment_vmaddr(d)
        if this_base is not None:
            entry["file_lowest_segment_vmaddr"] = f"0x{this_base:016X}"
        base_for_off = image_base if label in ("kernelcache", "file") and image_base is not None else this_base
        if base_for_off is not None:
            for r in res:
                if "vmaddr" in r:
                    v = int(r["vmaddr"], 16)
                    okey = "offset_from_kernel_image_base" if label in ("kernelcache", "file") and image_base else "offset_from_this_macho_base"
                    entry.setdefault(okey, {})[r["name"]] = f"0x{(v - base_for_off):08X}"
        report["files"][label] = entry

    print(json.dumps(report, ensure_ascii=False, indent=2))
    found = any("vmaddr" in x for t in report["files"].values() for x in t.get("results", []))
    return 0 if found else 2


if __name__ == "__main__":
    raise SystemExit(main())
