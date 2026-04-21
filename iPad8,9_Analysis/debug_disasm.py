import json, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

j = json.load(open('offsets_iPad8_9_17.3.1.json'))
segs = j.get('segments', {})
if '__TEXT_EXEC' in segs:
    seg = segs['__TEXT_EXEC']
elif '__TEXT' in segs:
    seg = segs['__TEXT']
else:
    print('No text segment in JSON')
    sys.exit(1)

fileoff = int(seg['fileoff'], 16)
filesize = int(seg['filesize'], 16)
vmaddr = int(seg['vmaddr'], 16)

with open('21D61\kernelcache_decompressed\kernelcache.release.ipad8.decompressed','rb') as f:
    f.seek(fileoff)
    code = f.read(min(filesize, 0x100000))

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
ad=0
adrp_count=0
add_count=0
ldr_count=0
for i, insn in enumerate(md.disasm(code, vmaddr)):
    if i>500: break
    if insn.mnemonic=='adrp': adrp_count+=1
    if insn.mnemonic in ('add','adds'): add_count+=1
    if insn.mnemonic=='ldr': ldr_count+=1
    ad+=1
print('insn_count',ad,'adrp',adrp_count,'add',add_count,'ldr',ldr_count)
for insn in md.disasm(code[:256], vmaddr):
    print(hex(insn.address), insn.mnemonic, insn.op_str)
