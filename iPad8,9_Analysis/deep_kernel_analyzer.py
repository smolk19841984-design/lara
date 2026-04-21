#!/usr/bin/env python3
"""
deep_kernel_analyzer.py

Advanced static kernel analyzer for iPad8,9 iOS 17.3.1 kernelcache
Uses lief (Mach-O parsing) and capstone (ARM64 disassembly) to heuristically
resolve function starts, string xrefs, MOVZ/MOVK-immediate pointer reconstructions,
and AMFI struct field offsets.

Usage:
  python deep_kernel_analyzer.py /path/to/kernelcache.release.ipad8.decompressed

Produces: static_analysis_offsets.h in current directory.

Notes:
- This script uses heuristics; results may be "best candidate" and confidence
  levels are reported in the generated header.
- Requires: lief, capstone
  pip install lief capstone
"""

import argparse
import logging
import struct
import sys
from collections import defaultdict, deque

try:
    import lief
except Exception as e:
    print("Missing dependency: lief. Install with: pip install lief")
    raise

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except Exception as e:
    print("Missing dependency: capstone. Install with: pip install capstone")
    raise

# Constants
KERNEL_BASE_HINT = 0xfffffff007004000  # provided base hint
PROLOGUE_INSTRUCTION = "stp"
PROLOGUE_OPSTR_CONTAINS = ("x29", "x30", "sp", "!")
MAX_INSN_WINDOW = 50
SIG_BYTES = 32

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("deep_analyzer")


def read_file_bytes(path):
    with open(path, "rb") as f:
        return f.read()


class MachOMapper:
    def __init__(self, binary, file_bytes):
        self.binary = binary
        self.file_bytes = file_bytes
        self.segs = {}
        for seg in self.binary.segments:
            name = seg.name
            vaddr = seg.virtual_address
            size = seg.virtual_size if seg.virtual_size else seg.size
            foff = seg.file_offset
            self.segs[name] = {
                "vaddr": vaddr,
                "size": size,
                "foff": foff,
            }

    def fileoff_to_vm(self, fo):
        for name, s in self.segs.items():
            if s["foff"] <= fo < s["foff"] + s["size"]:
                return s["vaddr"] + (fo - s["foff"])
        # fallback: assume base hint slide mapping
        return KERNEL_BASE_HINT + fo

    def vm_to_fileoff(self, vm):
        for name, s in self.segs.items():
            if s["vaddr"] <= vm < s["vaddr"] + s["size"]:
                return s["foff"] + (vm - s["vaddr"])
        # fallback
        return vm - KERNEL_BASE_HINT

    def get_segment_bytes(self, name):
        if name not in self.segs:
            return None, None
        s = self.segs[name]
        fo = s["foff"]
        size = s["size"]
        return self.file_bytes[fo:fo+size], s["vaddr"]


def find_string_locations(file_bytes, mapper, strings):
    hits = {}
    for s in strings:
        bs = s.encode()
        start = 0
        hits[s] = []
        while True:
            idx = file_bytes.find(bs, start)
            if idx == -1:
                break
            vm = mapper.fileoff_to_vm(idx)
            hits[s].append((idx, vm))
            start = idx + 1
    return hits


def disassemble_region(cs, data, base):
    return list(cs.disasm(data, base))


def is_prologue_insn(insn):
    if insn.mnemonic != PROLOGUE_INSTRUCTION:
        return False
    op = insn.op_str.lower()
    return all(token in op for token in PROLOGUE_OPSTR_CONTAINS)


def parse_imm_from_opstr(op_str):
    # crude parse for immediate tokens like #0x1234 or #123
    for part in op_str.split(','):
        part = part.strip()
        if part.startswith('#'):
            tok = part[1:]
            try:
                if tok.startswith('0x'):
                    return int(tok, 16)
                return int(tok, 0)
            except Exception:
                continue
    return None


def analyze_mov_chains(insns):
    # simple register->value tracker within a small window
    reg_vals = {}
    # store mapping of insn.address -> resolved immediate values loaded into regs
    resolved = {}

    for insn in insns:
        m = insn.mnemonic.lower()
        op = insn.op_str
        # MOVZ/MOVK/MOVN patterns
        if m in ("movz", "movk", "movn"):
            # op_str example: "x0, #0x1234, lsl #16"
            parts = [p.strip() for p in op.split(',')]
            if len(parts) >= 2:
                dst = parts[0]
                imm = parse_imm_from_opstr(','.join(parts[1:]))
                lsl = 0
                if 'lsl' in op:
                    # crude parse
                    try:
                        lsl_str = op.split('lsl')[-1]
                        lsl = int(lsl_str.replace('#', '').strip())
                    except Exception:
                        lsl = 0
                if imm is None:
                    continue
                if m == 'movz':
                    reg_vals[dst] = (imm << lsl) & 0xffffffffffffffff
                elif m == 'movk':
                    prev = reg_vals.get(dst, 0)
                    reg_vals[dst] = (prev & ~(0xffff << lsl)) | ((imm << lsl) & 0xffffffffffffffff)
                elif m == 'movn':
                    # movn writes bitwise-not of imm immediate (16-bit chunk) then shifted
                    # approximate: write as ~imm for the shifted region
                    prev = reg_vals.get(dst, 0)
                    mask = 0xffff << lsl
                    reg_vals[dst] = (prev & ~mask) | (((~imm & 0xffff) << lsl) & 0xffffffffffffffff)
                resolved[insn.address] = (dst, reg_vals[dst])
        elif m == 'add':
            # add x0, x0, #imm or add x0, x1, x2
            parts = [p.strip() for p in op.split(',')]
            if len(parts) >= 3:
                dst = parts[0]
                src = parts[1]
                imm = parse_imm_from_opstr(parts[2])
                if imm is not None and src in reg_vals:
                    reg_vals[dst] = (reg_vals[src] + imm) & 0xffffffffffffffff
                    resolved[insn.address] = (dst, reg_vals[dst])
        elif m in ('orr', 'orrs'):
            # orr x0, x1, #imm
            parts = [p.strip() for p in op.split(',')]
            if len(parts) >= 3:
                dst = parts[0]
                src = parts[1]
                imm = parse_imm_from_opstr(parts[2])
                if imm is not None:
                    val_src = reg_vals.get(src, 0)
                    reg_vals[dst] = val_src | imm
                    resolved[insn.address] = (dst, reg_vals[dst])
        elif m == 'adrp':
            # ADRP x0, #0x12345000 style in op_str
            parts = [p.strip() for p in op.split(',')]
            if len(parts) >= 2:
                dst = parts[0]
                imm = parse_imm_from_opstr(parts[1])
                if imm is not None:
                    # Capstone returns page-based imm; treat imm as full value
                    reg_vals[dst] = imm
                    resolved[insn.address] = (dst, reg_vals[dst])
        elif m == 'ldr':
            # ldr x0, #0xaddr (literal) or ldr x0, [x1, #offset]
            parts = [p.strip() for p in op.split(',')]
            if len(parts) >= 2:
                dst = parts[0]
                src = parts[1]
                imm = parse_imm_from_opstr(src)
                if imm is not None:
                    reg_vals[dst] = imm
                    resolved[insn.address] = (dst, imm)
                else:
                    # ldr x0, [x1, #off]
                    if src.startswith('[') and ']' in src:
                        inner = src.strip('[]')
                        baseparts = [p.strip() for p in inner.split(',')]
                        base = baseparts[0]
                        off = parse_imm_from_opstr(','.join(baseparts[1:]))
                        if base in reg_vals and off is not None:
                            reg_vals[dst] = (reg_vals[base] + off) & 0xffffffffffffffff
                            resolved[insn.address] = (dst, reg_vals[dst])
        elif m in ('bl', 'blr'):
            # check for BLR to register: blr x0
            pass
    return reg_vals, resolved


def scan_prologues_and_resolve(cs, seg_bytes, seg_base, mapper, string_locations, amfi_vm):
    results = {
        'functions': {},  # start_addr -> {'strings':[], 'calls':[], 'mov_resolves':{}}
    }

    log.info(f"Scanning segment at {hex(seg_base)} size {len(seg_bytes):,} bytes")
    all_insns = disassemble_region(cs, seg_bytes, seg_base)
    addr_to_index = {ins.address: i for i, ins in enumerate(all_insns)}

    for i, ins in enumerate(all_insns):
        try:
            if is_prologue_insn(ins):
                func_addr = ins.address
                # disassemble window
                window = all_insns[i:i+MAX_INSN_WINDOW]
                mv, resolved = analyze_mov_chains(window)

                # detect references to known strings
                referenced_strings = []
                calls = []
                for w in window:
                    # direct BL to absolute
                    if w.mnemonic.lower() == 'bl':
                        op = w.op_str.strip()
                        # bl 0xfffffff00...
                        if op.startswith('0x'):
                            try:
                                target = int(op, 16)
                                calls.append((w.address, target, 'direct'))
                            except Exception:
                                pass
                    elif w.mnemonic.lower() == 'blr':
                        # br to register e.g., blr x0
                        op = w.op_str.strip()
                        reg = op
                        if reg in mv:
                            calls.append((w.address, mv[reg], 'reconstructed'))
                    # ldr literal that may load a string pointer
                    if w.mnemonic.lower() == 'ldr':
                        op = w.op_str
                        imm = parse_imm_from_opstr(op)
                        if imm is not None:
                            # is imm equal to any known string address?
                            for s, locs in string_locations.items():
                                for (fo, vm) in locs:
                                    if vm == imm:
                                        referenced_strings.append((s, vm))
                    # adrp/add patterns resolved earlier
                    if w.address in resolved:
                        dst, val = resolved[w.address]
                        # if val matches a string address
                        for s, locs in string_locations.items():
                            for (fo, vm) in locs:
                                if vm == val:
                                    referenced_strings.append((s, vm))
                results['functions'][func_addr] = {
                    'strings': list(set(referenced_strings)),
                    'calls': calls,
                    'mov_resolves': resolved,
                }
        except Exception:
            continue
    return results


def find_global_field_accesses(cs, seg_bytes, seg_base, mapper, amfi_vm):
    # Look for LDR/STR with base equal to amfi VM (or adrp resolved to that page)
    accesses = []
    insns = disassemble_region(cs, seg_bytes, seg_base)
    for ins in insns:
        m = ins.mnemonic.lower()
        if m in ('ldr', 'str'):
            op = ins.op_str
            # patterns: ldr w0, [x0, #offset] or ldr w0, [x1]
            if '[' in op and ']' in op:
                inner = op.split('[', 1)[1].split(']')[0]
                parts = [p.strip() for p in inner.split(',')]
                base = parts[0]
                off = None
                if len(parts) >= 2:
                    off = parse_imm_from_opstr(parts[1])
                # crude: if base is like x?, we can't know its runtime value here
                # But some binaries use adrp to load amfi base into a register earlier; we attempt to detect nearby adrp with same reg
                # We'll look backwards few instructions for adrp of that register
                if base.startswith('x'):
                    lookback = 6
                    for back in range(1, lookback+1):
                        idx = None
                        try:
                            # find index of ins
                            idx = next(i for i, x in enumerate(insns) if x.address == ins.address)
                        except StopIteration:
                            idx = None
                        if idx is None or idx-back < 0:
                            break
                        prev = insns[idx-back]
                        if prev.mnemonic.lower() == 'adrp' and prev.op_str.split(',')[0].strip() == base:
                            imm = parse_imm_from_opstr(prev.op_str)
                            if imm is not None:
                                # adrp imm is a page-aligned value; compute
                                base_val = imm
                                if off is not None:
                                    accesses.append((ins.address, base_val + off, off))
                                else:
                                    accesses.append((ins.address, base_val, 0))
                                break
    # filter accesses that resolve near amfi_vm
    filtered = []
    for a in accesses:
        addr = a[1]
        # compare pages
        if (addr & ~0xfff) == (amfi_vm & ~0xfff):
            filtered.append(a)
    return filtered


def vm_to_file_byteslice(mapper, vm, size, file_bytes):
    fo = mapper.vm_to_fileoff(vm)
    if fo < 0 or fo + size > len(file_bytes):
        return None, None
    return fo, file_bytes[fo:fo+size]


def write_header(output_path, resolved, signatures):
    with open(output_path, 'w') as fh:
        fh.write("// Auto-generated by deep_kernel_analyzer.py\n")
        fh.write("// Review and verify before use. Confidence levels are heuristic.\n\n")
        def emit_define(name, val, conf):
            if val is None:
                fh.write(f"#define {name:<28} 0ULL // UNRESOLVED\n")
            else:
                fh.write(f"#define {name:<28} 0x{val:016x}ULL // Confidence: {conf}\n")
        emit_define('VN_OPEN_ADDR', resolved.get('vn_open'), resolved.get('conf_vn_open', 'Low'))
        emit_define('VN_WRITE_ADDR', resolved.get('vn_write'), resolved.get('conf_vn_write', 'Low'))
        emit_define('VN_CLOSE_ADDR', resolved.get('vn_close'), resolved.get('conf_vn_close', 'Low'))
        emit_define('VFS_CONTEXT_CURRENT_ADDR', resolved.get('vfs_context_current'), resolved.get('conf_vfs', 'Low'))
        emit_define('KERN_TRUSTCACHE_ADDR', resolved.get('kern_trustcache'), resolved.get('conf_trust', 'Low'))
        amfi_offset = resolved.get('amfi_cs_offset')
        if amfi_offset is None:
            fh.write(f"#define AMFI_CS_ENFORCEMENT_OFFSET 0x0 // UNRESOLVED\n")
        else:
            fh.write(f"#define AMFI_CS_ENFORCEMENT_OFFSET 0x{amfi_offset:x} // Confidence: {resolved.get('conf_amfi','Low')}\n")

        fh.write("\n// Verification Signatures (first 32 bytes)\n")
        for k, v in signatures.items():
            if v is None:
                fh.write(f"// {k} : UNRESOLVED\n")
                continue
            fh.write(f"static const uint8_t SIG_{k.upper()}[] = {" + "{\n")
            # write as byte list
            fh.write('    ')
            fh.write(', '.join(f"0x{b:02x}" for b in v))
            fh.write("\n};\n\n")

    log.info(f"Wrote header to {output_path}")


def main():
    parser = argparse.ArgumentParser(description='deep kernel static analyzer')
    parser.add_argument('kernel', help='path to kernelcache.decompressed')
    parser.add_argument('--amfi-vm', help='AMFI global vm address (hex)', default=None)
    args = parser.parse_args()

    file_bytes = read_file_bytes(args.kernel)
    log.info(f"Loaded kernel file: {args.kernel}, {len(file_bytes):,} bytes")

    binary = lief.parse(args.kernel)
    if binary is None:
        log.error("Failed to parse Mach-O with lief")
        sys.exit(1)

    mapper = MachOMapper(binary, file_bytes)

    # gather segments
    targets = ['__TEXT_EXEC', '__PRELINK_TEXT', '__DATA_CONST', '__LINKEDIT']

    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    cs.detail = False

    # find strings of interest
    interesting_strings = [
        'vn_open', 'vn_write', 'vn_close', 'vnode_put', 'vfs_context_current', 'trust_cache', 'cs_enforcement_disable'
    ]
    string_locs = find_string_locations(file_bytes, mapper, interesting_strings)
    for k, v in string_locs.items():
        if v:
            log.info(f"Found string '{k}' occurrences: {len(v)}")

    # scan prologues in code segments
    aggregated_funcs = {}
    for segname in ('__TEXT_EXEC', '__PRELINK_TEXT'):
        seg_bytes, seg_base = mapper.get_segment_bytes(segname)
        if not seg_bytes:
            continue
        log.info(f"Scanning {segname}...")
        r = scan_prologues_and_resolve(cs, seg_bytes, seg_base, mapper, string_locs, 0)
        aggregated_funcs.update(r.get('functions', {}))

    # map string->function candidates
    symbol_candidates = defaultdict(list)
    for faddr, meta in aggregated_funcs.items():
        for s in meta['strings']:
            name = s[0]
            symbol_candidates[name].append((faddr, meta))
            log.info(f"Function {hex(faddr)} references string {name}")

    # attempt to resolve AMFI fields by scanning for LDR/STR referencing amfi page
    amfi_vm = None
    if args.amfi_vm:
        amfi_vm = int(args.amfi_vm, 16)
    else:
        # try to find amfi symbol via previously-generated offsets files if present
        # fallback: look for 'amfi' occurrences in file
        amfi_hits = find_string_locations(file_bytes, mapper, ['amfi'])
        if amfi_hits.get('amfi'):
            amfi_vm = amfi_hits['amfi'][0][1]
            log.info(f"Heuristic AMFI vm set to {hex(amfi_vm)} from string 'amfi'")
    if amfi_vm is None:
        log.info("No AMFI VM provided; AMFI struct analysis will be limited")

    amfi_accesses = []
    if amfi_vm is not None:
        for segname in ('__TEXT_EXEC', '__PRELINK_TEXT'):
            seg_bytes, seg_base = mapper.get_segment_bytes(segname)
            if not seg_bytes:
                continue
            a = find_global_field_accesses(cs, seg_bytes, seg_base, mapper, amfi_vm)
            amfi_accesses.extend(a)
        log.info(f"Found {len(amfi_accesses)} potential amfi field accesses (page-matched)")

    # trust cache heuristic: find functions referencing 'trust_cache' string
    trust_candidates = symbol_candidates.get('trust_cache', [])

    # assemble results
    resolved = {}
    signatures = {}

    def pick_best(cands):
        if not cands:
            return None, 'Low'
        # choose lowest address as heuristic
        c = sorted(cands, key=lambda x: x[0])[0]
        return c[0], 'Medium'

    vn_open_addr, conf = pick_best(symbol_candidates.get('vn_open', []))
    resolved['vn_open'] = vn_open_addr
    resolved['conf_vn_open'] = conf

    vn_write_addr, conf = pick_best(symbol_candidates.get('vn_write', []))
    resolved['vn_write'] = vn_write_addr
    resolved['conf_vn_write'] = conf

    vn_close_addr, conf = pick_best(symbol_candidates.get('vn_close', []))
    resolved['vn_close'] = vn_close_addr
    resolved['conf_vn_close'] = conf

    vfs_ctx_addr, conf = pick_best(symbol_candidates.get('vfs_context_current', []))
    resolved['vfs_context_current'] = vfs_ctx_addr
    resolved['conf_vfs'] = conf

    trust_addr, conf = pick_best(trust_candidates)
    resolved['kern_trustcache'] = trust_addr
    resolved['conf_trust'] = conf

    # AMFI offset heuristic: if we saw LDR/STR resolves to addresses in same page as amfi_vm, compute offset
    amfi_offset = None
    conf_amfi = 'Low'
    if amfi_accesses:
        # pick first access and compute offset
        _, resolved_addr, off = amfi_accesses[0]
        amfi_offset = resolved_addr - amfi_vm
        conf_amfi = 'Medium'
        log.info(f"AMFI field candidate offset: 0x{amfi_offset:x}")
    resolved['amfi_cs_offset'] = amfi_offset
    resolved['conf_amfi'] = conf_amfi

    # signatures: extract 32 bytes at file offsets for targets
    def sig_for_vm(vm):
        if vm is None:
            return None
        fo = mapper.vm_to_fileoff(vm)
        if fo < 0 or fo + SIG_BYTES > len(file_bytes):
            return None
        return file_bytes[fo:fo+SIG_BYTES]

    signatures['vn_open'] = sig_for_vm(resolved['vn_open'])
    signatures['vn_write'] = sig_for_vm(resolved['vn_write'])
    signatures['vn_close'] = sig_for_vm(resolved['vn_close'])
    signatures['vfs_context_current'] = sig_for_vm(resolved['vfs_context_current'])
    signatures['kern_trustcache'] = sig_for_vm(resolved['kern_trustcache'])
    if amfi_vm is not None:
        # signature for amfi base
        signatures['amfi'] = sig_for_vm(amfi_vm)
    else:
        signatures['amfi'] = None

    # write header
    write_header('static_analysis_offsets.h', resolved, signatures)

    # print a small report
    log.info('\nSummary:')
    for k, v in resolved.items():
        log.info(f" - {k}: {v} (conf {resolved.get('conf_' + k.split('_')[0], 'N/A')})")

    log.info('Done.')


if __name__ == '__main__':
    main()
