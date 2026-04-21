#!/usr/bin/env python3
import json, struct, re
from pathlib import Path
from collections import deque
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except Exception:
    raise

OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
PAC_JSON = 'pac_candidates_top1000.json'
OUT_ADRP = 'adrp_to_data_topN_matches.json'
OUT_BL = 'bl_recursive_topN_matches.json'

HEX_RE = re.compile(r'0x[0-9a-fA-F]+')

def load_segments():
    j = json.load(open(OFF_JSON))
    segs = {}
    for name,info in j.get('segments', {}).items():
        segs[name] = {
            'vmaddr': int(info['vmaddr'],16),
            'vmsize': int(info['vmsize'],16),
            'fileoff': int(info['fileoff'],16),
            'filesize': int(info['filesize'],16),
        }
    return segs

def vm_to_file(vm, segments):
    for name, seg in segments.items():
        if seg['vmaddr'] <= vm < seg['vmaddr'] + seg['vmsize']:
            return name, seg['fileoff'] + (vm - seg['vmaddr'])
    return None, None

def find_adrp_sites(data, base_vm, fileoff, size):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    buf = data[fileoff:fileoff+size]
    results = []
    for insn in md.disasm(buf, base_vm):
        if insn.mnemonic == 'adrp':
            imm = None
            try:
                imm = insn.operands[1].imm
            except Exception:
                pass
            results.append({'addr': insn.address, 'imm': imm, 'op_str': insn.op_str})
    return results

def resolve_following(insn_addr, data, base_vm, max_look=8):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    addr = insn_addr + 4
    resolved = None
    ctx = []
    for _ in range(max_look):
        try:
            ins = next(md.disasm(data[(addr-base_vm):], addr))
        except Exception:
            break
        ctx.append({'addr': hex(ins.address), 'mnem': ins.mnemonic, 'op_str': ins.op_str})
        if ins.mnemonic in ('add','adds'):
            parts = [p.strip() for p in ins.op_str.split(',')]
            if len(parts) >= 3:
                try:
                    imm = int(parts[2].lstrip('#'), 16)
                except Exception:
                    try:
                        imm = int(parts[2], 0)
                    except Exception:
                        imm = 0
                resolved = ('add', imm, ins.address)
                break
        if ins.mnemonic == 'ldr':
            if '[' in ins.op_str:
                m = ins.op_str.split('[')[1].split(']')[0]
                if ',' in m:
                    parts = m.split(',')
                    try:
                        off = int(parts[1].strip().lstrip('#'), 16)
                    except Exception:
                        try:
                            off = int(parts[1].strip(), 0)
                        except Exception:
                            off = 0
                else:
                    off = 0
                resolved = ('ldr', off, ins.address)
                break
        addr = ins.address + 4
    return resolved, ctx

def run_adrp_check(segments, data, pac_vms):
    text = segments.get('__TEXT_EXEC') or segments.get('__TEXT')
    if not text:
        print('No __TEXT segment')
        return []
    adrp_sites = find_adrp_sites(data, text['vmaddr'], text['fileoff'], text['vmsize'])
    print('Found adrp sites:', len(adrp_sites))
    matches = []
    for site in adrp_sites:
        imm = site['imm']
        if imm is None:
            continue
        page = imm & ~0xfff
        resolved, ctx = resolve_following(site['addr'], data, text['vmaddr'])
        if resolved is None:
            continue
        typ, off_or_add, ins_addr = resolved
        target = page + off_or_add
        segname, fo = vm_to_file(target, segments)
        if segname is None:
            continue
        try:
            q = struct.unpack_from('<Q', data, fo)[0]
        except Exception:
            continue
        if q in pac_vms:
            matches.append({'adrp_addr': hex(site['addr']), 'ins_addr': hex(ins_addr), 'resolved_target': hex(target), 'loaded_q': hex(q), 'segment': segname, 'context': ctx})
    return matches

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

def run_bl_recursive(segments, data, pac_vms, lh_set, depth_limit=2):
    text = segments.get('__TEXT_EXEC') or segments.get('__TEXT')
    if not text:
        print('No __TEXT segment')
        return []
    initial_targets = find_bl_targets_in_segment(data, text['vmaddr'], text['fileoff'], text['vmsize'])
    print('Initial BL targets:', len(initial_targets))
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
    return {'initial_bl': len(initial_targets), 'visited': len(visited), 'matches': matches}

def main():
    import argparse
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--depth', type=int, default=2, help='BL recursion depth')
    ap.add_argument('--pac', help='Path to PAC candidates JSON (top-N)')
    args = ap.parse_args()

    segments = load_segments()
    data = open(KERNEL_FILE,'rb').read()
    # load pac (file may be provided)
    pac_file = args.pac if getattr(args, 'pac', None) else PAC_JSON
    pac = json.load(open(pac_file))
    pac_vms = set()
    for e in pac:
        try:
            pac_vms.add(int(e.get('vm'),16))
        except Exception:
            pass
    print('PAC loaded from', pac_file, 'count:', len(pac_vms))

    adrp_matches = run_adrp_check(segments, data, pac_vms)
    json.dump({'matches': adrp_matches, 'count': len(adrp_matches)}, open(OUT_ADRP,'w'), indent=2)
    print('Wrote', OUT_ADRP, 'matches=', len(adrp_matches))

    # load LH set if available
    lh_set = set()
    try:
        lh = json.load(open('offsets_iPad8_9_17.3.1_pcomm_mapped_printable.json'))
        for e in lh.get('mapped', []):
            try:
                lh_set.add(int(e.get('lh_first'),16))
            except Exception:
                pass
    except Exception:
        pass

    bl_res = run_bl_recursive(segments, data, pac_vms, lh_set, depth_limit=args.depth)
    json.dump(bl_res, open(OUT_BL,'w'), indent=2)
    print('Wrote', OUT_BL, 'matches=', len(bl_res.get('matches',[])))

if __name__=='__main__':
    main()
