#!/usr/bin/env python3
import json, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SUMMARY = Path('manual_re_priority_top50/summary.json')
OFF_JSON = Path('offsets_iPad8_9_17.3.1.json')
KERNEL = Path('21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed')
OUTDIR = Path('manual_re_priority_top50/hexdump_disasm')
ZIPOUT = Path('manual_re_priority_top50_hexdump_disasm.zip')

def load_segments():
    j = json.loads(OFF_JSON.read_text())
    segs = []
    for info in j.get('segments', {}).values():
        segs.append({'vmaddr': int(info['vmaddr'],16),'vmsize': int(info['vmsize'],16),'fileoff': int(info['fileoff'],16)})
    return segs

def vm_to_fileoff(segs, vm):
    for s in segs:
        if s['vmaddr'] <= vm < s['vmaddr'] + s['vmsize']:
            return s['fileoff'] + (vm - s['vmaddr'])
    return None

def hexdump(data):
    return data.hex()

def disasm_bytes(buf, base_vm, max_insn=100):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    out = []
    for i,ins in enumerate(md.disasm(buf, base_vm)):
        out.append({'addr': hex(ins.address), 'mnem': ins.mnemonic, 'op_str': ins.op_str})
        if i+1 >= max_insn:
            break
    return out

def main():
    OUTDIR.mkdir(parents=True, exist_ok=True)
    segs = load_segments()
    kernel = KERNEL.read_bytes()
    summary = json.loads(SUMMARY.read_text())
    results = []
    for entry in summary:
        vm = int(entry['candidate_vm'], 16)
        fo = vm_to_fileoff(segs, vm)
        if fo is None:
            continue
        start = max(0, fo - 256)
        end = min(len(kernel), fo + 256)
        buf = kernel[start:end]
        h = hexdump(buf)
        dis = disasm_bytes(buf, vm - (fo - start), max_insn=100)
        name = Path(entry['file']).name
        outj = {'candidate_vm': entry['candidate_vm'], 'file': name, 'fileoff': hex(fo), 'hexdump': h, 'disasm': dis}
        outpath = OUTDIR / (name + '.json')
        outpath.write_text(json.dumps(outj, indent=2))
        results.append(outpath)

    # zip
    import zipfile
    with zipfile.ZipFile(ZIPOUT, 'w') as z:
        for p in results:
            z.write(p, arcname=p.name)

    print('Wrote', len(results), 'hexdump+disasm files to', OUTDIR, 'and', ZIPOUT)

if __name__ == '__main__':
    import json
    main()
