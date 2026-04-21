#!/usr/bin/env python3
import json, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
import argparse

OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'

def load_segments():
    j = json.load(open(OFF_JSON))
    segs = {}
    for name,info in j.get('segments', {}).items():
        segs[name] = {'vmaddr': int(info['vmaddr'],16),'vmsize': int(info['vmsize'],16),'fileoff': int(info['fileoff'],16),'filesize': int(info['filesize'],16)}
    return segs

def vm_to_fileoff(segments, vm):
    for s in segments.values():
        va = s['vmaddr']; vs = s['vmsize']
        if vs and va <= vm < va + vs:
            return s['fileoff'] + (vm - va)
    return None

def disasm_window(data, base_vm, fo, back=64, forward=4096):
    start = max(0, fo - back)
    end = min(len(data), fo + forward)
    buf = data[start:end]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    return list(md.disasm(buf, base_vm - (fo - start)))

def find_reg_sequences(insns):
    # look for ADRP dst_reg then within next 12 insns an ADD/ LDR that uses same reg
    matches = []
    for i, ins in enumerate(insns):
        if ins.mnemonic == 'adrp':
            # get dest reg and imm if available
            try:
                dst = ins.operands[0].reg
            except Exception:
                dst = None
            imm = None
            try:
                imm = ins.operands[1].imm
            except Exception:
                pass
            ctx = [ {'addr': hex(ins.address), 'mnem': ins.mnemonic, 'op_str': ins.op_str} ]
            for j in range(1,13):
                if i+j >= len(insns): break
                ins2 = insns[i+j]
                ctx.append({'addr': hex(ins2.address), 'mnem': ins2.mnemonic, 'op_str': ins2.op_str})
                if ins2.mnemonic in ('add','adds'):
                    # check if one of operands is the dst reg
                    try:
                        regs = [op.reg for op in ins2.operands if op.type == 1]
                    except Exception:
                        regs = []
                    if dst in regs:
                        # get imm from add operand
                        imm_add = None
                        try:
                            for op in ins2.operands:
                                if op.type == 2:
                                    imm_add = op.imm
                                    break
                        except Exception:
                            pass
                        matches.append({'adrp_addr': hex(ins.address), 'dst_reg': int(dst) if dst else None, 'adrp_imm': imm, 'follow_type': 'add', 'follow_ins': ins2.op_str, 'add_imm': imm_add, 'context': ctx})
                        break
                if ins2.mnemonic == 'ldr':
                    # inspect mem operand for base reg
                    try:
                        for op in ins2.operands:
                            if op.type == 3:  # mem
                                base = op.mem.base
                                disp = op.mem.disp
                                if base == dst:
                                    matches.append({'adrp_addr': hex(ins.address), 'dst_reg': int(dst) if dst else None, 'adrp_imm': imm, 'follow_type': 'ldr', 'follow_ins': ins2.op_str, 'disp': disp, 'context': ctx})
                                    raise StopIteration
                    except StopIteration:
                        break
                    except Exception:
                        pass
    return matches

def resolve_target(page, add_or_disp):
    return (page & ~0xfff) + add_or_disp

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', '-i', default='pac_candidates_top2000.json')
    ap.add_argument('--n', type=int, default=200)
    ap.add_argument('--out', '-o', default='fine_disasm_top200_matches.json')
    args = ap.parse_args()

    pac = json.load(open(args.input))
    candidates = pac[:args.n]
    segments = load_segments()
    data = open(KERNEL_FILE,'rb').read()

    results = []
    for idx, entry in enumerate(candidates, start=1):
        try:
            vm = int(entry.get('vm'), 16)
        except Exception:
            continue
        fo = vm_to_fileoff(segments, vm)
        if fo is None:
            continue
        insns = disasm_window(data, vm, fo, back=128, forward=4096)
        matches = find_reg_sequences(insns)
        # resolve targets for matches where possible
        for m in matches:
            adr_page = m.get('adrp_imm')
            if isinstance(adr_page, int):
                if m['follow_type'] == 'add':
                    addv = m.get('add_imm') or 0
                    targ = resolve_target(adr_page, addv)
                    m['resolved_target_vm'] = hex(targ)
                    fo2 = vm_to_fileoff(segments, targ)
                    m['resolved_fileoff'] = hex(fo2) if fo2 else None
                    try:
                        if fo2 and fo2 + 8 <= len(data):
                            m['loaded_q'] = hex(struct.unpack_from('<Q', data, fo2)[0])
                    except Exception:
                        pass
                elif m['follow_type'] == 'ldr':
                    disp = m.get('disp') or 0
                    targ = resolve_target(adr_page, disp)
                    m['resolved_target_vm'] = hex(targ)
                    fo2 = vm_to_fileoff(segments, targ)
                    m['resolved_fileoff'] = hex(fo2) if fo2 else None
                    try:
                        if fo2 and fo2 + 8 <= len(data):
                            m['loaded_q'] = hex(struct.unpack_from('<Q', data, fo2)[0])
                    except Exception:
                        pass
        if matches:
            results.append({'candidate_index': idx, 'vm': hex(vm), 'fileoff': hex(fo), 'matches': matches})

    open(args.out, 'w').write(json.dumps({'count': len(results), 'results': results}, indent=2))
    print('Wrote', args.out, 'matches=', len(results))

if __name__ == '__main__':
    main()
