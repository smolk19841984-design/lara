import json, struct, sys

IN='offsets_iPad8_9_17.3.1_pcomm_expanded.json'
SEG_FILE='offsets_iPad8_9_17.3.1.json'
KERNEL_FILE='21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT='offsets_iPad8_9_17.3.1_pid_offsets_top5000.json'
TOP=5000
OFFSETS=[0x1c,0x30,0x34,0x44,0x4c]
WINDOW=256

base=json.load(open(SEG_FILE))
segs={}
for name,info in base.get('segments',{}).items():
    segs[name]={'vmaddr':int(info['vmaddr'],16),'vmsize':int(info['vmsize'],16),'fileoff':int(info['fileoff'],16),'filesize':int(info['filesize'],16)}

def vm_to_file(vm):
    for s in segs.values():
        if s['vmaddr']<=vm< s['vmaddr']+s['vmsize']:
            return s['fileoff'] + (vm - s['vmaddr'])
    return None

j=json.load(open(IN))
matches=j.get('matches',[])
N=min(TOP,len(matches))
print('Checking',N,'candidates')

data=open(KERNEL_FILE,'rb').read()
results=[]
counts={hex(o):{'zero':0,'small':0,'total':0,'mapped':0} for o in OFFSETS}

for i in range(N):
    m=matches[i]
    lh_hex=m.get('lh_first')
    try:
        lh=int(lh_hex,16)
    except Exception:
        continue
    pfo=vm_to_file(lh)
    rec={'index':i,'candidate_vm':m.get('candidate_vm'),'lh_first':lh_hex,'values':{},'printable':[]}
    if pfo is None or pfo<0 or pfo>=len(data):
        rec['note']='lh_first not in mapped segments'
        results.append(rec)
        continue
    counts_any=False
    counts_map=False
    for off in OFFSETS:
        addr_file = pfo + off
        if addr_file+4 > len(data):
            val=None
        else:
            val=struct.unpack_from('<I', data, addr_file)[0]
        rec['values'][hex(off)] = val
        if val is not None:
            counts[hex(off)]['total'] += 1
            counts[hex(off)]['mapped'] += 1
            counts_map=True
            if val == 0:
                counts[hex(off)]['zero'] += 1
            if val>0 and val<10000:
                counts[hex(off)]['small'] += 1
    # capture printable near p_comm candidate area
    try:
        sample = data[pfo:pfo+WINDOW]
        import re
        runs = re.findall(b'[\x20-\x7e]{6,}', sample)
        rec['printable'] = [r.decode('ascii','ignore') for r in runs[:6]]
    except Exception:
        rec['printable']=[]
    results.append(rec)

out={'scanned_top':N,'counts':counts,'samples':results[:200]}
json.dump(out, open(OUT,'w'), indent=2)
print('Wrote',OUT)
