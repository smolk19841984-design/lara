import json, struct, sys, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

MAPFILE='offsets_iPad8_9_17.3.1_pcomm_mapped_printable.json'
SEG_FILE='offsets_iPad8_9_17.3.1.json'
KERNEL='21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT_TXT='allproc_review.txt'
OUT_JSON='allproc_review.json'

# load
mapj=json.load(open(MAPFILE))
mapped=mapj.get('mapped',[])
segj=json.load(open(SEG_FILE))
segs={}
for name,info in segj.get('segments',{}).items():
    segs[name]={'vmaddr':int(info['vmaddr'],16),'vmsize':int(info['vmsize'],16),'fileoff':int(info['fileoff'],16),'filesize':int(info['filesize'],16)}

def vm_to_file(vm):
    for s in segs.values():
        if s['vmaddr']<=vm< s['vmaddr']+s['vmsize']:
            return s['fileoff'] + (vm - s['vmaddr'])
    return None

data=open(KERNEL,'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

results=[]

def hexdump_region(b, start_vm, width=16):
    lines=[]
    for i in range(0,len(b),width):
        chunk = b[i:i+width]
        hexpart = ' '.join(['%02x' % x for x in chunk])
        asc = ''.join([chr(x) if 32<=x<127 else '.' for x in chunk])
        lines.append('%016x: %-48s  %s' % (start_vm+i, hexpart, asc))
    return '\n'.join(lines)

for entry in mapped:
    cand_vm = entry.get('candidate_vm')
    lh_first = entry.get('lh_first')
    try:
        cand = int(cand_vm,16)
    except:
        cand=None
    try:
        lh = int(lh_first,16)
    except:
        lh=None
    rec={'candidate_vm':cand_vm,'lh_first':lh_first,'hexdump':{},'disasm':{}}
    # candidate VM region (code) hexdump+disasm
    if cand:
        cand_fo = vm_to_file(cand)
        if cand_fo:
            start_fo = max(0,cand_fo-0x40)
            buf = data[start_fo:start_fo+0x100]
            rec['hexdump']['candidate'] = hexdump_region(buf, cand-0x40)
            # disasm starting at candidate
            code = data[cand_fo:cand_fo+0x80]
            disasm_lines=[]
            for i in md.disasm(code, cand):
                disasm_lines.append('0x%x:\t%s\t%s' % (i.address, i.mnemonic, i.op_str))
            rec['disasm']['candidate'] = '\n'.join(disasm_lines[:40])
        else:
            rec['note_candidate']='candidate vm not mapped'
    # lh_first region (proc sample)
    if lh:
        lh_fo = vm_to_file(lh)
        if lh_fo:
            buf = data[lh_fo:lh_fo+0x200]
            rec['hexdump']['lh_first'] = hexdump_region(buf, lh)
            # try disasm as well (may be data)
            code = data[lh_fo:lh_fo+0x80]
            disasm_lines=[]
            for i in md.disasm(code, lh):
                disasm_lines.append('0x%x:\t%s\t%s' % (i.address, i.mnemonic, i.op_str))
            rec['disasm']['lh_first'] = '\n'.join(disasm_lines[:40])
        else:
            rec['note_lh']='lh_first not mapped'
    results.append(rec)

# write outputs
open(OUT_JSON,'w').write(json.dumps(results, indent=2))
open(OUT_TXT,'w',encoding='utf-8').write('\n\n'.join([('CAND %s LH %s\n-----\n' % (r['candidate_vm'], r['lh_first'])) + '\n-- candidate hexdump --\n' + r.get('hexdump',{}).get('candidate','') + '\n-- candidate disasm --\n' + r.get('disasm',{}).get('candidate','') + '\n-- lh_first hexdump --\n' + r.get('hexdump',{}).get('lh_first','') + '\n-- lh_first disasm --\n' + r.get('disasm',{}).get('lh_first','') for r in results]))
print('Wrote',OUT_TXT,OUT_JSON)
