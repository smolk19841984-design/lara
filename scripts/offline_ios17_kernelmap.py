#!/usr/bin/env python3
"""
offline_ios17_kernelmap.py

Offline "iOS 17.x kread harness":
- Loads Mach-O (kernelcache and/or kexts)
- Builds VM <-> fileoff map from LC_SEGMENT_64 + sections
- Provides vm_read / vm_find / vm_is_in_section primitives
- Validates candidates by reading bytes + section checks
- Writes canonical iPad8,9_Analysis/21D61/verified_offsets.json

This script is intentionally dependency-free (stdlib only).
"""

from __future__ import annotations

import argparse
import binascii
import json
import os
import re
import struct
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple


MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def _cstr16(b: bytes) -> str:
    return b.rstrip(b"\x00").decode("utf-8", errors="replace")


@dataclass(frozen=True)
class Section:
    segname: str
    sectname: str
    addr: int
    size: int
    offset: int


@dataclass(frozen=True)
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesz: int


class MachOMap:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()

        self.segments: List[Segment] = []
        self.sections: List[Section] = []
        self._parse()

    def _parse(self) -> None:
        if len(self.data) < 32:
            raise ValueError(f"{self.path}: too small for Mach-O header")
        magic = _u32(self.data, 0)
        if magic != MH_MAGIC_64:
            raise ValueError(f"{self.path}: unexpected magic 0x{magic:08X} (expected MH_MAGIC_64)")

        ncmds = _u32(self.data, 16)
        off = 32
        for _ in range(ncmds):
            cmd = _u32(self.data, off)
            csz = _u32(self.data, off + 4)
            if cmd == LC_SEGMENT_64:
                segname = _cstr16(self.data[off + 8 : off + 24])
                vmaddr = _u64(self.data, off + 24)
                vmsize = _u64(self.data, off + 32)
                fileoff = _u64(self.data, off + 40)
                filesz = _u64(self.data, off + 48)
                nsects = _u32(self.data, off + 64)
                self.segments.append(Segment(segname, vmaddr, vmsize, fileoff, filesz))

                sect_off = off + 72
                for _i in range(nsects):
                    sectname = _cstr16(self.data[sect_off : sect_off + 16])
                    seg_n = _cstr16(self.data[sect_off + 16 : sect_off + 32])
                    s_addr = _u64(self.data, sect_off + 32)
                    s_size = _u64(self.data, sect_off + 40)
                    s_off = _u32(self.data, sect_off + 48)
                    self.sections.append(Section(seg_n, sectname, s_addr, s_size, s_off))
                    sect_off += 80
            off += csz

        # Keep deterministic ordering
        self.segments.sort(key=lambda s: s.vmaddr)
        self.sections.sort(key=lambda s: (s.addr, s.segname, s.sectname))

    def vm_to_fileoff(self, vmaddr: int) -> Optional[int]:
        for seg in self.segments:
            if seg.vmaddr <= vmaddr < (seg.vmaddr + seg.vmsize):
                delta = vmaddr - seg.vmaddr
                # bounds check vs filesz where possible
                if delta >= seg.filesz:
                    return None
                return int(seg.fileoff + delta)
        return None

    def fileoff_to_vm(self, fileoff: int) -> Optional[int]:
        for seg in self.segments:
            if seg.fileoff <= fileoff < (seg.fileoff + seg.filesz):
                delta = fileoff - seg.fileoff
                return int(seg.vmaddr + delta)
        return None

    def vm_read(self, vmaddr: int, size: int) -> bytes:
        fileoff = self.vm_to_fileoff(vmaddr)
        if fileoff is None:
            raise ValueError(f"{self.path}: vmaddr 0x{vmaddr:X} not mapped to file offset")
        end = fileoff + size
        if end > len(self.data):
            raise ValueError(f"{self.path}: read out of range (fileoff=0x{fileoff:X}, size={size})")
        return self.data[fileoff:end]

    def vm_find(self, sig: bytes) -> List[Tuple[int, int]]:
        """Return list of (vmaddr, fileoff) matches across whole file."""
        out: List[Tuple[int, int]] = []
        start = 0
        while True:
            idx = self.data.find(sig, start)
            if idx == -1:
                break
            vm = self.fileoff_to_vm(idx)
            if vm is not None:
                out.append((vm, idx))
            start = idx + 1
        return out

    def vm_is_in_section(self, vmaddr: int, seg: str, sect: str) -> bool:
        for s in self.sections:
            if s.segname == seg and s.sectname == sect:
                if s.addr <= vmaddr < (s.addr + s.size):
                    return True
        return False

    def section_for_vm(self, vmaddr: int) -> Optional[Section]:
        for s in self.sections:
            if s.addr <= vmaddr < (s.addr + s.size):
                return s
        return None


def parse_sandbox_candidates_header(path: str) -> Dict[int, Dict[str, object]]:
    """
    Parse iPad8,9_Analysis/Sandbox_Profiles/offsets_sandbox_candidates.h
    Returns {index: {vmaddr:int, fileoff:int, sig:bytes}}
    """
    txt = open(path, "r", encoding="utf-8").read()
    out: Dict[int, Dict[str, object]] = {}

    for idx in range(1, 13):
        vm_m = re.search(rf"SANDBOX_CAND_{idx}_VMADDR\s+0x([0-9A-Fa-f]+)ULL", txt)
        fo_m = re.search(rf"SANDBOX_CAND_{idx}_FILEOFF\s+0x([0-9A-Fa-f]+)U", txt)
        sig_m = re.search(rf"static const unsigned char sandbox_sig_{idx}\[\]\s*=\s*\{{([^}}]+)\}};", txt)
        if not (vm_m and fo_m and sig_m):
            continue
        vmaddr = int(vm_m.group(1), 16)
        fileoff = int(fo_m.group(1), 16)
        sig_bytes = bytes(int(b.strip(), 16) for b in sig_m.group(1).split(",") if b.strip())
        out[idx] = {"vmaddr": vmaddr, "fileoff": fileoff, "sig": sig_bytes}

    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default="21D61")
    ap.add_argument("--device", default="iPad8,9")
    ap.add_argument(
        "--kernel-base",
        default=None,
        help="Optional override. If omitted, derived from Mach-O as the lowest LC_SEGMENT_64 vmaddr.",
    )
    ap.add_argument("--kernelcache", default="iPad8,9_Analysis/21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed")
    ap.add_argument("--sandbox-kext", default="iPad8,9_Analysis/Sandbox_Profiles/com.apple.security.sandbox.kext")
    ap.add_argument("--amfi-kext", default="iPad8,9_Analysis/21D61/kernelcache_decompressed/kexts/com.apple.driver.AppleMobileFileIntegrity")
    ap.add_argument("--sandbox-candidates-h", default="iPad8,9_Analysis/Sandbox_Profiles/offsets_sandbox_candidates.h")
    ap.add_argument("--out", default="iPad8,9_Analysis/21D61/verified_offsets.json")
    args = ap.parse_args()

    km_kernel = MachOMap(args.kernelcache)
    km_sandbox = MachOMap(args.sandbox_kext)
    km_amfi = MachOMap(args.amfi_kext) if os.path.exists(args.amfi_kext) else None

    derived_kernel_base = min(s.vmaddr for s in km_kernel.segments) if km_kernel.segments else 0
    kernel_base = int(args.kernel_base, 16) if args.kernel_base else int(derived_kernel_base)

    sandbox_candidates = parse_sandbox_candidates_header(args.sandbox_candidates_h)

    # Map: target -> (candidate_index, expected_section)
    # NOTE: We intentionally validate by vm_read(signature) and section checks.
    sandbox_targets = {
        "sandbox_check": (1, "__TEXT_EXEC", "__text"),
        "mac_label_update": (5, "__TEXT_EXEC", "__text"),
        "sandbox_extension_create_or_consume": (12, "__TEXT_EXEC", "__text"),
    }

    now = int(time.time())
    verified: Dict[str, object] = {
        "meta": {
            "build": args.build,
            "device": args.device,
            "generated_at_unix": now,
            "inputs": {
                "kernelcache": args.kernelcache,
                "sandbox_kext": args.sandbox_kext,
                "amfi_kext": args.amfi_kext,
                "sandbox_candidates_h": args.sandbox_candidates_h,
            },
        },
        "kernel_base": {
            "addr_abs": f"0x{kernel_base:016X}",
            "status": "Verified",
            "evidence": [
                {
                    "type": "MachO",
                    "note": "Derived as the lowest LC_SEGMENT_64 vmaddr from kernelcache Mach-O.",
                    "derived": f"0x{derived_kernel_base:016X}",
                    "override_used": bool(args.kernel_base),
                }
            ],
        },
        "targets": {},
        "rejected_candidates": [],
    }

    # Validate sandbox candidates 7/8 (must be rejected if mismatch)
    for rej_idx in (7, 8):
        cand = sandbox_candidates.get(rej_idx)
        if not cand:
            continue
        vmaddr = int(cand["vmaddr"])
        sig = bytes(cand["sig"])
        actual = km_sandbox.vm_read(vmaddr, len(sig))
        match = actual == sig
        verified["rejected_candidates"].append(
            {
                "candidate_index": rej_idx,
                "vmaddr": f"0x{vmaddr:016X}",
                "status": "Rejected" if not match else "Unverified",
                "reason": "Signature mismatch" if not match else "Signature matched (unexpected); re-run candidate generation.",
            }
        )

    # Verify sandbox targets
    for name, (cand_idx, seg, sect) in sandbox_targets.items():
        cand = sandbox_candidates.get(cand_idx)
        if not cand:
            verified["targets"][name] = {
                "status": "Rejected",
                "reason": f"Missing candidate {cand_idx} in offsets_sandbox_candidates.h",
            }
            continue

        vmaddr = int(cand["vmaddr"])
        sig = bytes(cand["sig"])
        fileoff = km_sandbox.vm_to_fileoff(vmaddr)
        section = km_sandbox.section_for_vm(vmaddr)
        in_section = km_sandbox.vm_is_in_section(vmaddr, seg, sect)
        actual = km_sandbox.vm_read(vmaddr, len(sig))
        match = actual == sig

        status = "Verified" if (match and in_section) else ("Rejected" if not match else "Unverified")
        verified["targets"][name] = {
            "addr_abs": f"0x{vmaddr:016X}",
            "offset_from_kernel_base": f"0x{(vmaddr - kernel_base):08X}",
            "source_file": args.sandbox_kext,
            "segment.section": f"{section.segname}.{section.sectname}" if section else None,
            "fileoff": f"0x{fileoff:X}" if fileoff is not None else None,
            "status": status,
            "evidence": [
                {
                    "type": "SignatureMatch",
                    "bytes": binascii.hexlify(sig).decode("ascii"),
                    "match": bool(match),
                },
                {
                    "type": "SectionCheck",
                    "expected": f"{seg}.{sect}",
                    "actual": f"{section.segname}.{section.sectname}" if section else None,
                    "ok": bool(in_section),
                },
            ],
        }

    # cs_enforcement_disable (string evidence only => Unverified)
    cs_addr = kernel_base + 0x92F9A0  # existing hypothesis
    cs_entry = {
        "addr_abs": f"0x{cs_addr:016X}",
        "offset_from_kernel_base": f"0x{(cs_addr - kernel_base):08X}",
        "source_file": args.amfi_kext,
        "segment.section": None,
        "fileoff": None,
        "status": "Unverified",
        "evidence": [],
    }
    if km_amfi is not None:
        # prove the string exists somewhere in the binary; still not enough for Verified.
        hay = km_amfi.data
        hit = b"cs_enforcement_disable" in hay
        cs_entry["evidence"].append({"type": "StringEvidence", "needle": "cs_enforcement_disable", "present": bool(hit)})
    else:
        cs_entry["evidence"].append({"type": "StringEvidence", "needle": "cs_enforcement_disable", "present": False})
    verified["targets"]["cs_enforcement_disable"] = cs_entry

    # pmap_image4_trust_caches (no offline signature provided here => Unverified, but range-check in kernelcache map)
    tc_addr = kernel_base + 0xABE968
    tc_fileoff = km_kernel.vm_to_fileoff(tc_addr)
    tc_section = km_kernel.section_for_vm(tc_addr)
    verified["targets"]["pmap_image4_trust_caches"] = {
        "addr_abs": f"0x{tc_addr:016X}",
        "offset_from_kernel_base": f"0x{(tc_addr - kernel_base):08X}",
        "source_file": args.kernelcache,
        "segment.section": f"{tc_section.segname}.{tc_section.sectname}" if tc_section else None,
        "fileoff": f"0x{tc_fileoff:X}" if tc_fileoff is not None else None,
        "status": "Unverified",
        "evidence": [{"type": "RangeCheck", "mapped_to_fileoff": tc_fileoff is not None}],
    }

    # kernel symbols / struct size (static fallbacks; range-check only)
    for sym_name, off in (("_kernproc", 0x96B928), ("_rootvnode", 0x3213640)):
        addr = kernel_base + off
        fo = km_kernel.vm_to_fileoff(addr)
        sec = km_kernel.section_for_vm(addr)
        verified["targets"][sym_name] = {
            "addr_abs": f"0x{addr:016X}",
            "offset_from_kernel_base": f"0x{off:08X}",
            "source_file": args.kernelcache,
            "segment.section": f"{sec.segname}.{sec.sectname}" if sec else None,
            "fileoff": f"0x{fo:X}" if fo is not None else None,
            "status": "Unverified",
            "evidence": [{"type": "StaticFallback", "note": "Present as embedded fallback in kexploit/offsets.m"}],
        }

    verified["targets"]["_allproc"] = {
        "addr_abs": None,
        "offset_from_kernel_base": None,
        "source_file": args.kernelcache,
        "status": "Unverified",
        "evidence": [{"type": "RuntimeFallback", "note": "Resolved at runtime if kernproc fails"}],
    }

    verified["targets"]["kernelStruct.proc.struct_size"] = {
        "addr_abs": None,
        "offset_from_kernel_base": None,
        "source_file": args.kernelcache,
        "status": "Unverified",
        "evidence": [{"type": "StaticFallback", "value": "0x730"}],
    }

    # Optional P1: PE_i_can_has_debugger (range-check only)
    pe_addr = kernel_base + 0x81E3D8
    pe_fo = km_kernel.vm_to_fileoff(pe_addr)
    pe_sec = km_kernel.section_for_vm(pe_addr)
    verified["targets"]["PE_i_can_has_debugger"] = {
        "addr_abs": f"0x{pe_addr:016X}",
        "offset_from_kernel_base": f"0x{(pe_addr - kernel_base):08X}",
        "source_file": args.kernelcache,
        "segment.section": f"{pe_sec.segname}.{pe_sec.sectname}" if pe_sec else None,
        "fileoff": f"0x{pe_fo:X}" if pe_fo is not None else None,
        "status": "Unverified",
        "evidence": [{"type": "RangeCheck", "mapped_to_fileoff": pe_fo is not None}],
    }

    out_path = args.out
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(verified, f, ensure_ascii=False, indent=2)

    print(f"[+] wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

