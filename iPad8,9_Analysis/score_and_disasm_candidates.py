#!/usr/bin/env python3
"""Score prologue candidates and disassemble top matches for _pmap_in_ppl search.

Inputs:
 - prologue_scan JSON (from scan_prologues.py)
 - kernel binary
 - segments JSON (kernel_symbols_21D61.json)

Outputs:
 - top10 JSON
 - topN disassembly text
"""
import argparse
import json
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


def hex_to_int(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 16) if v.startswith('0x') or v.startswith('-0x') else int(v, 0)
    return int(v)


def vm_fileoff_from_segments(segments, vm):
    for s in segments:
        va = s['vmaddr']
        vs = s['vmsize']
        if vm >= va and vm < va + vs:
            return s['fileoff'] + (vm - va), s
    return None, None


def disasm_region(data, fileoff, vm_start, max_bytes=0x400, max_insns=400):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    code = data[fileoff:fileoff + max_bytes]
    insns = []
    for ins in md.disasm(code, vm_start):
        insns.append((ins.address, ins.mnemonic, ins.op_str, ins.bytes))
        if len(insns) >= max_insns:
            break
        if ins.mnemonic == 'ret':
            break
    return insns


def analyze_function(data, fileoff, vm_start):
    insns = disasm_region(data, fileoff, vm_start, max_bytes=0x800, max_insns=400)
    instr_count = len(insns)
    ret_pos = None
    bl_count = 0
    cmp_found = False
    cond_branch_found = False
    adrp_hits = []

    reg_adrp = {}
    for idx, (addr, mnem, op, bts) in enumerate(insns):
        if mnem == 'ret' and ret_pos is None:
            ret_pos = idx + 1
        if mnem.startswith('bl'):
            bl_count += 1
        if mnem in ('cmp', 'subs', 'tst'):
            cmp_found = True
        if mnem.startswith('b') and mnem != 'b':
            cond_branch_found = True
        if mnem == 'adrp':
            adrp_hits.append({'addr': addr, 'op': op})
            # record register used
            try:
                reg = op.split(',')[0].strip()
                reg_adrp[reg] = op
            except Exception:
                pass
    return {
        'instr_count': instr_count,
        'ret_pos': ret_pos,
        'bl_count': bl_count,
        'cmp_found': cmp_found,
        'cond_branch_found': cond_branch_found,
        'adrp_hits': adrp_hits,
        'insns': insns,
    }


def score_entry(entry, analysis):
    score = 0
    # prefer small bl_count
    bl = analysis['bl_count']
    if bl <= 1:
        score += 20
    elif bl <= 3:
        score += 10
    else:
        score += 0

    if analysis['cmp_found'] and analysis['cond_branch_found']:
        score += 25
    elif analysis['cmp_found'] or analysis['cond_branch_found']:
        score += 10

    if analysis['ret_pos'] is not None and analysis['ret_pos'] <= 50:
        score += 20

    # prefer short functions
    if analysis['instr_count'] <= 50:
        score += 15
    elif analysis['instr_count'] <= 150:
        score += 5

    # small penalty for many bls
    score -= analysis['bl_count'] * 2

    return score


def hexdump_region(data, fo, length=256, base=0):
    s = []
    for i in range(0, length, 16):
        chunk = data[fo + i:fo + i + 16]
        if not chunk:
            break
        hexb = ' '.join(f"{c:02x}" for c in chunk)
        ascii_repr = ''.join((chr(c) if 32 <= c < 127 else '.') for c in chunk)
        s.append(f"{base + i:016x}  {hexb:<48}  {ascii_repr}")
    return '\n'.join(s)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('-k', '--kernel', required=True)
    p.add_argument('-p', '--prologue', required=True)
    p.add_argument('-s', '--segments', required=True)
    p.add_argument('-o', '--outprefix', required=True)
    p.add_argument('--topn', type=int, default=10)
    p.add_argument('--disasm_n', type=int, default=5)
    args = p.parse_args()

    prog = json.load(open(args.prologue, 'r', encoding='utf-8'))
    segs = json.load(open(args.segments, 'r', encoding='utf-8'))['segments']
    with open(args.kernel, 'rb') as f:
        data = f.read()

    candidates = []
    for e in prog.get('functions', []):
        # parse function fileoff and vm
        ffo = hex_to_int(e['func_fileoff']) if isinstance(e['func_fileoff'], str) else e['func_fileoff']
        fvm = hex_to_int(e['func_vm']) if isinstance(e['func_vm'], str) else e['func_vm']
        # filter small BLs first
        if e.get('bl_count', 0) <= 3:
            analysis = analyze_function(data, ffo, fvm)
            # replace bl_count with local measured bl_count
            analysis['bl_count'] = analysis.get('bl_count', 0)
            # compute score
            sc = score_entry(e, analysis)
            candidates.append({'fileoff': ffo, 'vm': fvm, 'orig_bl': e.get('bl_count',0), 'analysis': analysis, 'score': sc})

    # sort
    candidates.sort(key=lambda x: x['score'], reverse=True)

    topn = candidates[:args.topn]
    with open(args.outprefix + '_top10.json', 'w', encoding='utf-8') as f:
        json.dump({'top': [{ 'fileoff': hex(c['fileoff']), 'vm': hex(c['vm']), 'score': c['score'], 'orig_bl': c['orig_bl'], 'instr_count': c['analysis']['instr_count'], 'ret_pos': c['analysis']['ret_pos'], 'cmp': c['analysis']['cmp_found'], 'cond': c['analysis']['cond_branch_found'], 'adrp_count': len(c['analysis']['adrp_hits']) } for c in topn]}, f, indent=2)

    # write human-readable top10
    with open(args.outprefix + '_top10.txt', 'w', encoding='utf-8') as f:
        for i,c in enumerate(topn,1):
            f.write(f"#{i} fileoff=0x{c['fileoff']:x} vm=0x{c['vm']:x} score={c['score']} orig_bl={c['orig_bl']} instr_count={c['analysis']['instr_count']} ret_pos={c['analysis']['ret_pos']} cmp={c['analysis']['cmp_found']} cond={c['analysis']['cond_branch_found']} adrp={len(c['analysis']['adrp_hits'])}\n")

    # disassemble top disasm_n
    dn = args.disasm_n if args.disasm_n <= len(topn) else len(topn)
    with open(args.outprefix + '_top_disasm.txt', 'w', encoding='utf-8') as f:
        for i,c in enumerate(topn[:dn],1):
            f.write('#'*60 + '\n')
            f.write(f"# Candidate {i}: fileoff=0x{c['fileoff']:x} vm=0x{c['vm']:x} score={c['score']}\n")
            f.write('HEXDUMP:\n')
            f.write(hexdump_region(data, c['fileoff'], length=256, base=c['vm']))
            f.write('\n\nDISASM:\n')
            for addr,mnem,op,bts in c['analysis']['insns']:
                f.write(f"0x{addr:016x}: {mnem}\t{op}\t; {bts.hex()}\n")
            f.write('\nADRP hits:\n')
            for a in c['analysis']['adrp_hits']:
                f.write(str(a) + '\n')

    print('Wrote:', args.outprefix + '_top10.json', args.outprefix + '_top10.txt', args.outprefix + '_top_disasm.txt')


if __name__ == '__main__':
    main()
