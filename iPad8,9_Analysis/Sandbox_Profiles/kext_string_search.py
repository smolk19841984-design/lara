#!/usr/bin/env python3
import os,sys
BASE=os.path.dirname(__file__)
KEXT=os.path.join(BASE,'com.apple.security.sandbox.kext')
if not os.path.isfile(KEXT):
    print('kext missing')
    sys.exit(1)
with open(KEXT,'rb') as f:
    data=f.read()
keys=[b'sandbox_check',b'sandbox_extension',b'extension_create',b'extension_consume',b'mac_label',b'mac_proc_set_label',b'cs_enforcement',b'cs_enforcement_disable',b'amfi',b'codesign']
for k in keys:
    i=0; hits=[]
    while True:
        idx=data.find(k,i)
        if idx==-1: break
        hits.append(idx)
        i=idx+1
    print(k.decode(), 'hits', len(hits))
    for h in hits[:10]:
        print('  offset=0x%X' % h)
print('done')
