import json, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

MAP='offsets_iPad8_9_17.3.1_pcomm_mapped_printable.json'
SEG='offsets_iPad8_9_17.3.1.json'
KERNEL='21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT='allproc_adrp_add_hits.json'
OUT_TXT='allproc_review.txt'

mapj=json.load(open(MAP))
mapped=mapj.get('mapped',[])
segj=json.load(open(SEG))
segs={}
for name,info in segj.get('segments',{}).items():
    segs[name]={'vmaddr':int(info['vmaddr'],16),'vmsize':int(info['vmsize'],16),'fileoff':int(info['fileoff'],16),'filesize':int(info['filesize'],16)}

def vm_to_file(vm):
    for s in segs.values():
        if s['vmaddr']<=vm< s['vmaddr']+s['vmsize']:
            return s['fileoff'] + (vm - s['vmaddr'])
    return None

code=open(KERNEL,'rb').read()
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = False

hex_re = re.compile(r'0x[0-9a-fA-F]+')
dec_re = re.compile(r'#(\d+)')
results=[]

for entry in mapped:
    cand_vm = entry.get('candidate_vm')
    lh_first = entry.get('lh_first')
    try:
        cand = int(cand_vm,16)
        lh = int(lh_first,16)
    except:
        continue
    cand_fo = vm_to_file(cand)
    if cand_fo is None:
        continue
    start_fo = max(0, cand_fo-0x800)
    end_fo = min(len(code), cand_fo+0x800)
    segment = code[start_fo:end_fo]
    base_vm = cand - (cand_fo - start_fo)
    insns = list(cs.disasm(segment, base_vm))
    # scan for ADRP
    for i,ins in enumerate(insns):
        if ins.mnemonic == 'adrp':
            # extract hex immediate from op_str
            hexs = hex_re.findall(ins.op_str)
            if hexs:
                adrp_val = int(hexs[-1],16)
            else:
                # skip if no hex
                continue
            # look ahead for add using same register
            m = re.match(r'(x\d+),', ins.op_str)
            if m:
                reg = m.group(1)
            else:
                # operand may be like 'x0, #0x..' skip
                continue
            for j in range(i+1, min(i+8, len(insns))):
                ins2 = insns[j]
                if ins2.mnemonic in ('add','addw') and reg in ins2.op_str:
                    # find immediate in op_str
                    hi = hex_re.search(ins2.op_str)
                    if hi:
                        add_imm = int(hi.group(0),16)
                    else:
                        dm = dec_re.search(ins2.op_str)
                        add_imm = int(dm.group(1)) if dm else 0
                    target = (adrp_val & ~0xfff) + add_imm
                    # Alternative: if adrp_val seems already page base, sum directly
                    # Compare with lh
                    if target == lh or (adrp_val + add_imm) == lh:
                        # record surrounding disasm
                        context = '\n'.join(['0x%016x:\t%s\t%s' % (k.address,k.mnemonic,k.op_str) for k in insns[max(0,i-8):min(len(insns),i+8)]])
                        results.append({'candidate_vm':hex(cand),'lh_first':hex(lh),'adrp_ins':{'address':hex(ins.address),'op_str':ins.op_str},'add_ins':{'address':hex(ins2.address),'op_str':ins2.op_str},'target':hex(target),'context':context})

# write results
json.dump(results, open(OUT,'w'), indent=2)
# append to review txt
if results:
    with open(OUT_TXT,'a',encoding='utf-8') as f:
        f.write('\n\nADRP+ADD hits:\n')
        for r in results:
            f.write(str(r)+'\n\n')
print('Wrote',OUT, 'hits=', len(results))
