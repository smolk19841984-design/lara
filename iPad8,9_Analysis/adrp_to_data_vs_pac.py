#!/usr/bin/env python3
"""Like adrp_to_data_check.py but compare the loaded qword against the
expanded PAC candidates set (large). Emits adrp_to_data_pac_matches.json
"""
import json, struct
from pathlib import Path
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except Exception:
    raise

OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
PAC_JSON = 'offsets_iPad8_9_17.3.1_pac_candidates_expanded.json'
OUT = 'adrp_to_data_pac_matches.json'

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

def main():
    segments = load_segments()
    data = open(KERNEL_FILE,'rb').read()
    text = segments.get('__TEXT_EXEC') or segments.get('__TEXT')
    if not text:
        print('No __TEXT segment')
        return
    adrp_sites = find_adrp_sites(data, text['vmaddr'], text['fileoff'], text['vmsize'])
    print('Found adrp sites:', len(adrp_sites))

    # load PAC candidates VM set (may be large)
    pac = json.load(open(PAC_JSON))
    pac_vms = set()
    for e in pac.get('ranked_candidates', []):
        try:
            pac_vms.add(int(e.get('vm', '0'), 16))
        except Exception:
            pass
    print('PAC candidate VMs loaded:', len(pac_vms))

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

    json.dump({'matches': matches, 'count': len(matches)}, open(OUT, 'w'), indent=2)
    print('Wrote', OUT, 'matches=', len(matches))

if __name__=='__main__':
    main()
