#!/usr/bin/env python3
"""Recursively expand BL/BLR call graph (depth-limited), disassemble each
callee function window, find ADRP->ADD/LDR loads that resolve into data segments,
and compare loaded qwords against lh_first and PAC candidate sets.
Writes bl_recursive_adrp_matches.json
"""
import re, json, struct
from collections import deque
from pathlib import Path
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except Exception:
    raise

OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
LH_JSON = 'offsets_iPad8_9_17.3.1_pcomm_mapped_printable.json'
PAC_JSON = 'offsets_iPad8_9_17.3.1_pac_candidates_expanded.json'
OUT = 'bl_recursive_adrp_matches.json'

HEX_RE = re.compile(r'0x[0-9a-fA-F]+')

def load_segments():
    j = json.load(open(OFF_JSON))
    segs = {}
    for name,info in j.get('segments', {}).items():
        segs[name] = {'vmaddr': int(info['vmaddr'],16),'vmsize': int(info['vmsize'],16),'fileoff': int(info['fileoff'],16),'filesize': int(info['filesize'],16)}
    return segs

def vm_to_file(vm, segments):
    for name, seg in segments.items():
        if seg['vmaddr'] <= vm < seg['vmaddr'] + seg['vmsize']:
            return name, seg['fileoff'] + (vm - seg['vmaddr'])
    return None, None

def find_bl_targets_in_segment(data, base_vm, fileoff, size):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    buf = data[fileoff:fileoff+size]
    targets = set()
    for insn in md.disasm(buf, base_vm):
        if insn.mnemonic in ('bl','blr'):
            m = HEX_RE.search(insn.op_str)
            if m:
                try:
                    targets.add(int(m.group(0),16))
                except Exception:
                    pass
    return sorted(targets)

def disasm_function_window(data, segments, addr, back=64, forward=1024):
    segname, fo = vm_to_file(addr - back, segments)
    if fo is None:
        segname, fo = vm_to_file(addr, segments)
        if fo is None:
            return []
        start = fo
    else:
        start = fo
    size = back + forward
    buf = data[start:start+size]
    base_vm = addr - back
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    return list(md.disasm(buf, base_vm))

def find_adrp_pairs(insns):
    res = []
    for i,ins in enumerate(insns):
        if ins.mnemonic == 'adrp':
            imm = None
            try:
                imm = ins.operands[1].imm
            except Exception:
                m = HEX_RE.search(ins.op_str)
                imm = int(m.group(0),16) if m else None
            for j in range(1,12):
                if i+j >= len(insns):
                    break
                ins2 = insns[i+j]
                if ins2.mnemonic in ('add','adds'):
                    m2 = HEX_RE.search(ins2.op_str)
                    addv = int(m2.group(0),16) if m2 else 0
                    res.append((ins.address, imm, 'add', addv, ins2.address))
                    break
                if ins2.mnemonic == 'ldr':
                    m2 = HEX_RE.search(ins2.op_str)
                    off = int(m2.group(0),16) if m2 else 0
                    res.append((ins.address, imm, 'ldr', off, ins2.address))
                    break
    return res

def main(depth_limit=2):
    segments = load_segments()
    data = open(KERNEL_FILE,'rb').read()
    text = segments.get('__TEXT_EXEC') or segments.get('__TEXT')
    if not text:
        print('No __TEXT segment')
        return

    # initial BL targets
    initial_targets = find_bl_targets_in_segment(data, text['vmaddr'], text['fileoff'], text['vmsize'])
    print('Initial BL targets:', len(initial_targets))

    # load lh_first set
    lh = json.load(open(LH_JSON))
    lh_set = set()
    for e in lh.get('mapped', []):
        try:
            lh_set.add(int(e.get('lh_first'),16))
        except Exception:
            pass

    # load PAC candidates (only VM keys)
    pac_vms = set()
    try:
        pac = json.load(open(PAC_JSON))
        for e in pac.get('ranked_candidates', []):
            try:
                pac_vms.add(int(e.get('vm','0'),16))
            except Exception:
                pass
    except Exception:
        pac_vms = set()

    matches = []
    visited = set()
    q = deque([(t,0) for t in initial_targets])
    while q:
        addr, depth = q.popleft()
        if addr in visited or depth > depth_limit:
            continue
        visited.add(addr)
        insns = disasm_function_window(data, segments, addr)
        if not insns:
            continue
        # find nested BLs to follow
        for ins in insns:
            if ins.mnemonic in ('bl','blr'):
                m = HEX_RE.search(ins.op_str)
                if m:
                    try:
                        tgt = int(m.group(0),16)
                        if tgt not in visited:
                            q.append((tgt, depth+1))
                    except Exception:
                        pass
        # find adrp pairs in this function window
        adrp_hits = find_adrp_pairs(insns)
        for adrp_addr, imm, typ, off_or_add, op_addr in adrp_hits:
            if imm is None:
                continue
            page = imm & ~0xfff
            target = page + off_or_add
            segname, fo = vm_to_file(target, segments)
            if segname is None:
                continue
            try:
                qval = struct.unpack_from('<Q', data, fo)[0]
            except Exception:
                continue
            is_lh = qval in lh_set
            is_pac = qval in pac_vms
            if is_lh or is_pac:
                matches.append({'start_bl': hex(addr), 'depth': depth, 'adrp_addr': hex(adrp_addr), 'op_addr': hex(op_addr), 'resolved_target': hex(target), 'loaded_q': hex(qval), 'is_lh': is_lh, 'is_pac': is_pac, 'segment': segname})

    json.dump({'initial_bl': len(initial_targets), 'visited': len(visited), 'matches': matches, 'count': len(matches)}, open(OUT,'w'), indent=2)
    print('Wrote', OUT, 'matches=', len(matches))

if __name__=='__main__':
    main()
