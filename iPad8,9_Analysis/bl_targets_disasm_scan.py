#!/usr/bin/env python3
"""Find BL/BLR targets in __TEXT_EXEC, disassemble target functions, and
check ADRP->ADD/LDR loads that point into data segments. Compare loaded
qwords against mapped lh_first values and expanded PAC candidates.
Writes bl_adrp_data_matches.json
"""
import re, json, struct
from pathlib import Path
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except Exception:
    raise

OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
LH_JSON = 'offsets_iPad8_9_17.3.1_pcomm_mapped_printable.json'
PAC_JSON = 'offsets_iPad8_9_17.3.1_pac_candidates_expanded.json'
OUT = 'bl_adrp_data_matches.json'

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

def find_bl_targets(data, base_vm, fileoff, size):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    buf = data[fileoff:fileoff+size]
    targets = set()
    for insn in md.disasm(buf, base_vm):
        if insn.mnemonic in ('bl','blr'):
            # try to parse immediate target from op_str
            m = HEX_RE.search(insn.op_str)
            if m:
                try:
                    targets.add(int(m.group(0), 16))
                except Exception:
                    pass
    return sorted(targets)

def disasm_window(data, segments, addr, back=32, forward=512):
    # produce bytes slice for disasm window
    segname, fo = vm_to_file(addr - back, segments)
    if fo is None:
        # try exact addr
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

def find_adrp_add_or_ldr(md_insns):
    # find adrp then add/ldr within next 8 insns
    res = []
    for i,ins in enumerate(md_insns):
        if ins.mnemonic == 'adrp':
            imm = None
            try:
                imm = ins.operands[1].imm
            except Exception:
                m = HEX_RE.search(ins.op_str)
                imm = int(m.group(0),16) if m else None
            dst = ins.op_str.split(',')[0].strip()
            for j in range(1,9):
                if i+j >= len(md_insns):
                    break
                ins2 = md_insns[i+j]
                if ins2.mnemonic in ('add','adds'):
                    m2 = HEX_RE.search(ins2.op_str)
                    addv = int(m2.group(0),16) if m2 else 0
                    res.append((ins.address, imm, 'add', addv, ins2.address))
                    break
                if ins2.mnemonic == 'ldr':
                    # parse offset
                    m2 = HEX_RE.search(ins2.op_str)
                    off = int(m2.group(0),16) if m2 else 0
                    res.append((ins.address, imm, 'ldr', off, ins2.address))
                    break
    return res

def main():
    segments = load_segments()
    data = open(KERNEL_FILE,'rb').read()
    text = segments.get('__TEXT_EXEC') or segments.get('__TEXT')
    if not text:
        print('No __TEXT segment')
        return
    print('Scanning for BL/BLR targets in __TEXT_EXEC...')
    targets = find_bl_targets(data, text['vmaddr'], text['fileoff'], text['vmsize'])
    print('BL targets found:', len(targets))

    # load lh_first set
    lh = json.load(open(LH_JSON))
    lh_set = set(int(e['lh_first'],16) for e in lh.get('mapped',[]) if e.get('lh_first'))
    # load PAC set (may be large)
    pac_vms = set()
    try:
        pac = json.load(open(PAC_JSON))
        for e in pac.get('ranked_candidates',[]):
            try:
                pac_vms.add(int(e.get('vm','0'),16))
            except Exception:
                pass
    except Exception:
        pac_vms = set()

    matches = []
    for t in targets:
        insns = disasm_window(data, segments, t)
        if not insns:
            continue
        adrp_hits = find_adrp_add_or_ldr(insns)
        for adrp_addr, imm, typ, off_or_add, op_addr in adrp_hits:
            if imm is None:
                continue
            page = imm & ~0xfff
            target = page + off_or_add
            segname, fo = vm_to_file(target, segments)
            if segname is None:
                continue
            try:
                q = struct.unpack_from('<Q', data, fo)[0]
            except Exception:
                continue
            is_lh = q in lh_set
            is_pac = q in pac_vms
            if is_lh or is_pac:
                matches.append({'bl_target': hex(t), 'adrp_addr': hex(adrp_addr), 'op_addr': hex(op_addr), 'resolved_target': hex(target), 'loaded_q': hex(q), 'is_lh': is_lh, 'is_pac': is_pac, 'segment': segname})

    json.dump({'bl_targets': len(targets), 'matches': matches, 'count': len(matches)}, open(OUT,'w'), indent=2)
    print('Wrote', OUT, 'matches=', len(matches))

if __name__=='__main__':
    main()
