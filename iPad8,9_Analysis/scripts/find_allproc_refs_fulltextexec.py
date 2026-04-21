import json, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SEG='offsets_iPad8_9_17.3.1.json'
MAP='offsets_iPad8_9_17.3.1_pcomm_mapped_printable.json'
KERNEL='21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT='allproc_adrp_add_ldr_hits.json'
OUT_TXT='allproc_review.txt'

segj=json.load(open(SEG))
segs=segj.get('segments',{})
text_exec=None
for name,info in segs.items():
    if name == '__TEXT_EXEC' or name.lower().startswith('__text_exec'):
        text_exec=info
        break
if not text_exec:
    # fallback to __TEXT
    text_exec=segs.get('__TEXT')

if not text_exec:
    print('No __TEXT_EXEC or __TEXT segment found')
    raise SystemExit(1)

text_vm = int(text_exec['vmaddr'],16)
text_size = int(text_exec['vmsize'],16)
text_fileoff = int(text_exec['fileoff'],16)

# load target lh_firsts
mapj=json.load(open(MAP))
mapped=mapj.get('mapped',[])
lh_set=set()
for m in mapped:
    try:
        lh=int(m['lh_first'],16)
        lh_set.add(lh)
    except:
        pass

code=open(KERNEL,'rb').read()
segment = code[text_fileoff:text_fileoff+text_size]
base_vm = text_vm

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = False

hex_re = re.compile(r'0x[0-9a-fA-F]+')
dec_re = re.compile(r'#(\d+)')

insns = list(cs.disasm(segment, base_vm))
addr_to_index = {i.address: idx for idx,i in enumerate(insns)}

results=[]
# ADRP+ADD scan across entire insns
for i,ins in enumerate(insns):
    if ins.mnemonic == 'adrp':
        # get immediate as hex if present
        hs = hex_re.findall(ins.op_str)
        if not hs:
            continue
        try:
            adrp_val = int(hs[-1],16)
        except:
            continue
        # get dest reg
        m = re.match(r'(x\d+)', ins.op_str.strip())
        if not m:
            continue
        reg = m.group(1)
        # look ahead for add up to 12 instructions
        for j in range(i+1, min(i+12, len(insns))):
            ins2 = insns[j]
            if ins2.mnemonic.startswith('add') and reg in ins2.op_str:
                # find immediate
                hs2 = hex_re.findall(ins2.op_str)
                if hs2:
                    add_imm = int(hs2[-1],16)
                else:
                    dm = dec_re.search(ins2.op_str)
                    add_imm = int(dm.group(1)) if dm else 0
                # compute target
                target = (adrp_val & ~0xfff) + add_imm
                if target in lh_set:
                    context = '\n'.join(['0x%016x:\t%s\t%s' % (k.address,k.mnemonic,k.op_str) for k in insns[max(0,i-8):min(len(insns),j+8)]])
                    results.append({'type':'adrp+add','adrp_addr':hex(ins.address),'adrp_op':ins.op_str,'add_addr':hex(ins2.address),'add_op':ins2.op_str,'target':hex(target),'lh_first':hex(target),'context':context})

# LDR literal scan
for ins in insns:
    if ins.mnemonic == 'ldr' and 'pc' in ins.op_str or 'literal' in ins.op_str:
        # attempt to extract immediate
        hs = hex_re.findall(ins.op_str)
        imm = None
        if hs:
            try:
                imm = int(hs[-1],16)
            except:
                imm = None
        if imm is None:
            dm = dec_re.search(ins.op_str)
            imm = int(dm.group(1)) if dm else 0
        # compute target as ins.address + imm (approx)
        target = ins.address + imm
        if target in lh_set:
            results.append({'type':'ldr_literal','ins_addr':hex(ins.address),'op':ins.op_str,'target':hex(target)})

json.dump(results, open(OUT,'w'), indent=2)
# append to review txt
if results:
    with open(OUT_TXT,'a',encoding='utf-8') as f:
        f.write('\n\nFull-textexec ADRP/ADD and LDR hits:\n')
        for r in results:
            f.write(str(r)+'\n\n')
print('Wrote',OUT,'hits=',len(results))
