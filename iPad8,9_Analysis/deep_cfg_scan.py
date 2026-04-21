#!/usr/bin/env python3
import json, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT_JSON = 'offsets_iPad8_9_17.3.1_deep_candidates.json'

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
    for seg in segments.values():
        if seg['vmaddr'] <= vm < seg['vmaddr'] + seg['vmsize']:
            return seg['fileoff'] + (vm - seg['vmaddr'])
    return None

def file_to_vm(fileoff, segments):
    for seg in segments.values():
        if seg['fileoff'] <= fileoff < seg['fileoff'] + seg['filesize']:
            return seg['vmaddr'] + (fileoff - seg['fileoff'])
    return None

def disasm_all(code, base_vm):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return list(md.disasm(code, base_vm))

def adrp_add_resolution(insns):
    targets = {}
    for i, ins in enumerate(insns):
        if ins.mnemonic == 'adrp':
            # try robust operand extraction
            try:
                dst = ins.operands[0].reg
                imm = ins.operands[1].imm
            except Exception:
                # fallback parse from op_str: 'x0, #0x1234'
                parts = ins.op_str.split(',')
                if len(parts) < 2:
                    continue
                dst = parts[0].strip()
                try:
                    imm = int(parts[1].strip().split()[0],0)
                except Exception:
                    continue
            adrp_page = (ins.address & ~0xfff) + imm
            # look ahead
            for j in range(i+1, min(i+30, len(insns))):
                ins2 = insns[j]
                if ins2.mnemonic in ('add','adds'):
                    try:
                        d2 = ins2.operands[0].reg
                        s2 = ins2.operands[1].reg
                        imm2 = ins2.operands[2].imm
                    except Exception:
                        # parse op_str
                        parts = ins2.op_str.split(',')
                        if len(parts) < 3:
                            continue
                        d2 = parts[0].strip()
                        s2 = parts[1].strip()
                        try:
                            imm2 = int(parts[2].strip(),0)
                        except Exception:
                            continue
                    if str(s2).endswith(str(dst)) or str(d2).endswith(str(dst)) or d2==dst or s2==dst:
                        target = adrp_page + imm2
                        targets.setdefault(target,[]).append({'adrp':hex(ins.address),'add':hex(ins2.address)})
                        break
    return targets

def ldr_literal_resolution(insns, segments):
    targets = {}
    for ins in insns:
        if ins.mnemonic == 'ldr':
            # try mem operand
            try:
                op = ins.operands[1]
                if op.type == 3: # MEM
                    disp = op.mem.disp
                    lit = ins.address + disp
                else:
                    continue
            except Exception:
                # fallback parse
                try:
                    parts = ins.op_str.split(',')
                    if len(parts) < 2:
                        continue
                    # second part like [x0, #0x123]
                    p = parts[1]
                    if '#' in p:
                        disp = int(p.split('#')[-1].split(']')[0],0)
                        lit = ins.address + disp
                    else:
                        continue
                except Exception:
                    continue
            # check into segments
            for seg in segments.values():
                if seg['vmaddr'] <= lit < seg['vmaddr'] + seg['vmsize']:
                    targets.setdefault(lit,[]).append({'ldr_site':hex(ins.address)})
                    break
    return targets

def collect_bl_targets(insns, segments):
    funcs = set()
    for ins in insns:
        if ins.mnemonic == 'bl' or ins.mnemonic == 'blr':
            # capstone gives op imm for bl
            try:
                target = ins.operands[0].imm
            except Exception:
                # parse op_str
                try:
                    target = int(ins.op_str.strip(),0)
                except Exception:
                    continue
            for seg in segments.values():
                if seg['vmaddr'] <= target < seg['vmaddr'] + seg['vmsize']:
                    funcs.add(target)
                    break
    return sorted(funcs)

def analyze_samples(data, segments, targets):
    out = {}
    for vm, refs in targets.items():
        fo = vm_to_file(vm, segments)
        if fo is None or fo<0 or fo>=len(data):
            continue
        sample = data[fo:fo+256]
        ascii = ''.join([chr(c) if 32<=c<127 else '.' for c in sample])
        out[hex(vm)] = {'fileoff':hex(fo),'refs':refs,'ascii':ascii[:200],'hex':sample.hex()[:512]}
    return out

def main():
    segments = load_segments()
    data = open(KERNEL_FILE,'rb').read()
    if '__TEXT_EXEC' in segments:
        text = segments['__TEXT_EXEC']
    elif '__TEXT' in segments:
        text = segments['__TEXT']
    else:
        print('no text')
        return
    code = data[text['fileoff']:text['fileoff']+text['filesize']]
    insns = disasm_all(code, text['vmaddr'])
    print('Disassembled', len(insns), 'instructions')
    adrp = adrp_add_resolution(insns)
    print('ADRP+ADD targets:', len(adrp))
    ldr = ldr_literal_resolution(insns, segments)
    print('LDR literal targets:', len(ldr))
    bls = collect_bl_targets(insns, segments)
    print('Collected', len(bls), 'BL targets')
    combined = {}
    for d in (adrp, ldr):
        for k,v in d.items():
            combined.setdefault(k,[])
            combined[k].extend(v)
    analyzed = analyze_samples(data, segments, combined)
    out = {'kernel_base':hex(segments['__TEXT']['vmaddr'] - segments['__TEXT']['fileoff']), 'adrp_add': {hex(k):v for k,v in adrp.items()}, 'ldr_literals': {hex(k):v for k,v in ldr.items()}, 'bl_targets':[hex(x) for x in bls], 'candidates': analyzed}
    json.dump(out, open(OUT_JSON,'w'), indent=2)
    print('Wrote', OUT_JSON)

if __name__=='__main__':
    main()
