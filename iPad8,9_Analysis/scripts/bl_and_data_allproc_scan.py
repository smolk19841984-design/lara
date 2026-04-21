import json, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SEG='offsets_iPad8_9_17.3.1.json'
MAP='offsets_iPad8_9_17.3.1_pcomm_mapped_printable.json'
KERNEL='21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT_BL='allproc_bl_targets_hits.json'
OUT_DATA='allproc_data_segment_hits.json'

segj=json.load(open(SEG))
segs=segj.get('segments',{})
text_exec=None
for name,info in segs.items():
    if name == '__TEXT_EXEC' or name.lower().startswith('__text_exec'):
        text_exec=info
        break
if not text_exec:
    text_exec=segs.get('__TEXT')
if not text_exec:
    raise SystemExit('no text segment')

text_vm=int(text_exec['vmaddr'],16)
text_off=int(text_exec['fileoff'],16)
text_size=int(text_exec['vmsize'],16)

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
seg_bytes=code[text_off:text_off+text_size]
cs=Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail=False
insns=list(cs.disasm(seg_bytes, text_vm))

hex_re=re.compile(r'0x[0-9a-fA-F]+')
dec_re=re.compile(r'#(\d+)')

# collect BL immediate targets
bl_targets=set()
for ins in insns:
    if ins.mnemonic == 'bl':
        m=hex_re.search(ins.op_str)
        if m:
            try:
                t=int(m.group(0),16)
                bl_targets.add(t)
            except:
                pass

print('Found',len(bl_targets),'BL targets')

# function to scan insn list around target for ADRP+ADD or LDR hitting lh
ins_map={i.address:i for i in insns}
addr_list=[i.address for i in insns]
addr_to_idx={addr:i for i,addr in enumerate(addr_list)}

results_bl=[]
for t in sorted(bl_targets):
    # find nearest index
    if t not in addr_to_idx:
        # try next lower address
        keys=[a for a in addr_list if a<=t]
        if not keys:
            continue
        idx=addr_to_idx[keys[-1]]
    else:
        idx=addr_to_idx[t]
    start=max(0,idx-64)
    end=min(len(insns), idx+256)
    window=insns[start:end]
    for i,ins in enumerate(window):
        if ins.mnemonic == 'adrp':
            hs=hex_re.findall(ins.op_str)
            if not hs: continue
            try:
                adrp_val=int(hs[-1],16)
            except:
                continue
            # dest reg
            dest = ins.op_str.split(',')[0].strip()
            for j in range(i+1, min(i+16, len(window))):
                ins2=window[j]
                if ins2.mnemonic.startswith('add') and dest in ins2.op_str:
                    hs2=hex_re.findall(ins2.op_str)
                    if hs2:
                        add_imm=int(hs2[-1],16)
                    else:
                        dm=dec_re.search(ins2.op_str)
                        add_imm=int(dm.group(1)) if dm else 0
                    target=(adrp_val & ~0xfff)+add_imm
                    if target in lh_set:
                        results_bl.append({'bl_target':hex(t),'adrp_addr':hex(ins.address),'adrp_op':ins.op_str,'add_addr':hex(ins2.address),'add_op':ins2.op_str,'lh_first':hex(target)})
        if ins.mnemonic == 'ldr' and ('literal' in ins.op_str or 'pc' in ins.op_str or '[' in ins.op_str):
            hs=hex_re.findall(ins.op_str)
            imm=None
            if hs:
                try:
                    imm=int(hs[-1],16)
                except:
                    imm=None
            if imm is None:
                dm=dec_re.search(ins.op_str)
                imm=int(dm.group(1)) if dm else 0
            # approximate target
            tars = ins.address + imm
            if tars in lh_set:
                results_bl.append({'bl_target':hex(t),'ldr_addr':hex(ins.address),'ldr_op':ins.op_str,'lh_first':hex(tars)})

json.dump(results_bl, open(OUT_BL,'w'), indent=2)
print('Wrote',OUT_BL,'hits=',len(results_bl))

# Data segment scan for exact 8-byte matches and masked low-bit matches
data_hits=[]
data_segments=[]
for name,info in segs.items():
    if name.startswith('__DATA') or name.startswith('__data') or name.startswith('__DATA_CONST'):
        data_segments.append(info)

masks=[(1<<n)-1 for n in (36,40,44,48,52,56)]

for seg in data_segments:
    off=int(seg['fileoff'],16)
    size=int(seg['filesize'],16)
    buf=code[off:off+size]
    for i in range(0,len(buf)-8,8):
        v=int.from_bytes(buf[i:i+8],'little')
        if v in lh_set:
            data_hits.append({'seg':seg,'fileoff':hex(off+i),'value':hex(v),'type':'exact'})
        else:
            for m in masks:
                for lh in lh_set:
                    if (v & m) == (lh & m):
                        data_hits.append({'seg':seg,'fileoff':hex(off+i),'value':hex(v),'mask_bits':m,'lh':hex(lh)})
                        break
                else:
                    continue
                break

json.dump(data_hits, open(OUT_DATA,'w'), indent=2)
print('Wrote',OUT_DATA,'hits=',len(data_hits))
