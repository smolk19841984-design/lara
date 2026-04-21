#!/usr/bin/env python3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
import json,sys,os
BASE=os.path.dirname(__file__)
CAND_JSON=os.path.join(BASE,'sandbox_text_exec_functions.json')
KEXT=os.path.join(BASE,'com.apple.security.sandbox.kext')
with open(CAND_JSON) as f:
    data=json.load(f)
with open(KEXT,'rb') as f:
    k=f.read()
md=Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail=False
hints={}
offsets=[0x78,0x10,0x40,0x48,0x30,0x34]
for c in data['candidates']:
    vm=c['vmaddr']; fo=c['fileoff']
    foff=fo
    blob=k[fo:fo+256]
    hits=[]
    for ins in md.disasm(blob, vm):
        for off in offsets:
            if ('#0x%x' % off) in ins.op_str or ('#%d' % off) in ins.op_str:
                hits.append((hex(ins.address), ins.mnemonic, ins.op_str))
    hints[hex(vm)]=hits
for k,v in hints.items():
    print(k, 'hits', len(v))
    for it in v:
        print(' ',it)
