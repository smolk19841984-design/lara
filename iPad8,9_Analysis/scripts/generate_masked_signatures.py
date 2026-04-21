import json,struct

IN='offsets_iPad8_9_17.3.1_signatures.json'
OUT='offsets_iPad8_9_17.3.1_signatures_masked.json'

j=json.load(open(IN))
res=[]
for s in j.get('signatures',[]):
    name=s['name']
    hexs=s.get('bytes_hex')
    if not hexs:
        res.append({'name':name,'masked':None})
        continue
    data=bytes.fromhex(hexs)
    mask = bytearray()
    # mask any 8-byte LE qword that looks like a kernel pointer (0xfffffff0xxxxxxx0..)
    for i in range(len(data)):
        mask.append(0)
    for i in range(len(data)-7):
        q=struct.unpack_from('<Q', data, i)[0]
        if (q & 0xfffffff000000000) == 0xfffffff000000000:
            for k in range(8):
                mask[i+k]=1
    # produce masked hex string where masked bytes become '??'
    masked_parts=[]
    for i,b in enumerate(data):
        if mask[i]:
            masked_parts.append('??')
        else:
            masked_parts.append('%02x' % b)
    masked = ''.join(masked_parts)
    res.append({'name':name,'masked_hex':masked,'original_hex':hexs})

json.dump({'masked_signatures':res}, open(OUT,'w'), indent=2)
print('Wrote',OUT)
