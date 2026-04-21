#!/usr/bin/env python3
import json, sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

# Config
OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT_JSON = 'offsets_iPad8_9_17.3.1_candidates.json'

MIN_TARGET=0xfffffff000000000

def load_segments():
    j = json.load(open(OFF_JSON))
    segs = {}
    for name,info in j.get('segments', {}).items():
        segs[name] = {
            'vmaddr': int(info['vmaddr'],16),
            'vmsize': int(info['vmsize'],16),
            'fileoff': int(info['fileoff'],16),
            'filesize': int(info['filesize'],16),
            'cmd_off': info.get('cmd_off')
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


def scan_adrp_add(data, text_seg, segments):
    base = text_seg['fileoff']
    size = text_seg['filesize']
    code = data[base:base+size]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(code, text_seg['vmaddr']))
    targets = {}
    for i, ins in enumerate(insns):
        if ins.mnemonic == 'adrp':
            # get operands
            try:
                dst = ins.operands[0].reg
                imm = ins.operands[1].imm
            except Exception:
                # fallback parse
                continue
            adrp_page = (ins.address & ~0xfff) + imm
            # look ahead for add using same reg
            for j in range(i+1, min(i+10, len(insns))):
                ins2 = insns[j]
                if ins2.mnemonic in ('add','adds'):
                    try:
                        d2 = ins2.operands[0].reg
                        s2 = ins2.operands[1].reg
                        imm2 = ins2.operands[2].imm
                    except Exception:
                        continue
                    if s2 == dst or d2 == dst:
                        target = adrp_page + imm2
                        targets.setdefault(target, []).append({'type':'adrp_add','code_site':hex(ins.address),'add_site':hex(ins2.address)})
                        break
    return targets


def scan_ldr_literals(data, text_seg, segments):
    base = text_seg['fileoff']
    size = text_seg['filesize']
    code = data[base:base+size]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    targets = {}
    for ins in md.disasm(code, text_seg['vmaddr']):
        if ins.mnemonic == 'ldr':
            # check operand 1 mem displacement (guard access)
            try:
                if not hasattr(ins, 'operands'):
                    continue
                if len(ins.operands) < 2:
                    continue
                op = ins.operands[1]
            except Exception:
                continue
            try:
                mem = op.mem
                disp = getattr(mem,'disp',0)
                # approximate literal address
                lit_addr = ins.address + disp
                # if points into segments record
                for seg in segments.values():
                    if seg['vmaddr'] <= lit_addr < seg['vmaddr'] + seg['vmsize']:
                        targets.setdefault(lit_addr, []).append({'type':'ldr_literal','code_site':hex(ins.address)})
                        break
            except Exception:
                continue
    return targets


def scan_64bit_literals(data, text_seg, segments):
    # reuse previous function implemented in extract_offsets
    base = text_seg['fileoff']
    size = text_seg['filesize']
    code = data[base:base+size]
    ln = len(code)
    results = {}
    for i in range(0, ln-8, 1):
        val = struct.unpack_from('<Q', code, i)[0]
        if val == 0 or (val & 0xffff000000000000) != 0:
            continue
        for seg in segments.values():
            if seg['vmaddr'] <= val < seg['vmaddr'] + seg['vmsize']:
                results.setdefault(val, []).append(hex(base+i))
                break
    return results


def scan_data_for_pointers(data, segments, min_ptrs=1):
    # Scan __DATA_CONST and __DATA segments for 8-byte values that point into kernel VM ranges
    results = {}
    for name in ('__DATA_CONST','__DATA'):
        if name not in segments:
            continue
        seg = segments[name]
        base = seg['fileoff']
        size = seg['filesize']
        blob = data[base:base+size]
        for i in range(0, len(blob)-8, 8):
            val = struct.unpack_from('<Q', blob, i)[0]
            if val == 0:
                continue
            # filter: value inside kernel vm ranges
            for s in segments.values():
                if s['vmaddr'] <= val < s['vmaddr'] + s['vmsize']:
                    # record candidate: vm -> file offset of pointer
                    vm = val
                    fileoff = base + i
                    results.setdefault(vm, []).append({'from_segment': name, 'fileoff': hex(fileoff)})
                    break
    return results


def analyze_targets(data, segments, targets, max_sample=256):
    out = {}
    for vm, refs in targets.items():
        fileoff = vm_to_file(vm, segments)
        if fileoff is None:
            continue
        if fileoff <0 or fileoff >= len(data):
            continue
        sample = data[fileoff:fileoff+max_sample]
        ascii = ''.join([c if 32<=c<127 else '.' for c in sample])
        # check if sample begins with pointer to text (possible list head)
        points_to_text = False
        if len(sample) >=8:
            firstq = struct.unpack_from('<Q', sample, 0)[0]
            for seg in segments.values():
                if seg['vmaddr'] <= firstq < seg['vmaddr'] + seg['vmsize']:
                    points_to_text = True
                    break
        out[hex(vm)] = {
            'fileoff': hex(fileoff),
            'refs': refs,
            'sample_hex': sample.hex()[:max_sample*2],
            'sample_ascii': ascii[:200],
            'points_to_text': points_to_text
        }
    return out


def main():
    segments = load_segments()
    data = open(KERNEL_FILE,'rb').read()
    # choose text segment
    if '__TEXT_EXEC' in segments:
        text = segments['__TEXT_EXEC']
    elif '__PRELINK_TEXT' in segments:
        text = segments['__PRELINK_TEXT']
    elif '__TEXT' in segments:
        text = segments['__TEXT']
    else:
        print('No text segment found')
        return

    print('Scanning ADRP+ADD...')
    adr = scan_adrp_add(data, text, segments)
    print('Found', len(adr), 'adrp_add targets')
    print('Scanning LDR literals...')
    ldr = scan_ldr_literals(data, text, segments)
    print('Found', len(ldr), 'ldr literal targets')
    print('Scanning 64-bit literals in code...')
    lit = scan_64bit_literals(data, text, segments)
    print('Found', len(lit), '64-bit literal targets')

    # merge
    combined = {}
    for d in (adr, ldr, lit):
        for k,v in d.items():
            combined.setdefault(k,[])
            combined[k].extend(v)

    print('Total combined targets:', len(combined))
    analyzed = analyze_targets(data, segments, combined)
    json.dump({'kernel_base': hex(segments['__TEXT']['vmaddr'] - segments['__TEXT']['fileoff']), 'candidates': analyzed}, open(OUT_JSON,'w'), indent=2)
    print('Wrote', OUT_JSON)

if __name__=='__main__':
    main()
