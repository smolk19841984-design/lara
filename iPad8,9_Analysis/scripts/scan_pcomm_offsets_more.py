import json,struct,re

MAP='offsets_iPad8_9_17.3.1_pcomm_mapped_printable.json'
SEG='offsets_iPad8_9_17.3.1.json'
KERNEL='21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT='offsets_iPad8_9_17.3.1_pcomm_offsets_scan.json'

mapj=json.load(open(MAP))
mapped=mapj.get('mapped',[])
base=json.load(open(SEG))
segs={}
for name,info in base.get('segments',{}).items():
    segs[name]={'vmaddr':int(info['vmaddr'],16),'vmsize':int(info['vmsize'],16),'fileoff':int(info['fileoff'],16),'filesize':int(info['filesize'],16)}

def vm_to_file(vm):
    for s in segs.values():
        if s['vmaddr']<=vm< s['vmaddr']+s['vmsize']:
            return s['fileoff'] + (vm - s['vmaddr'])
    return None

data=open(KERNEL,'rb').read()
results=[]
pattern=re.compile(b'[\x20-\x7e]{4,}')
check_offsets=list(range(0x20,0x201,8))
for m in mapped:
    lh=m.get('lh_first')
    try:
        lh_val=int(lh,16)
    except:
        continue
    pfo=vm_to_file(lh_val)
    rec={'candidate_vm':m.get('candidate_vm'),'lh_first':lh,'pfo':hex(pfo) if pfo else None,'offsets':{}}
    if pfo is None:
        results.append(rec)
        continue
    for off in check_offsets:
        s_off=pfo+off
        if s_off+256 > len(data):
            rec['offsets'][hex(off)]={'printable':[]}
            continue
        sample=data[s_off:s_off+256]
        runs=pattern.findall(sample)
        rec['offsets'][hex(off)]={'printable':[r.decode('ascii','ignore') for r in runs[:6]]}
        # check for kernel_task/kernal/task
        hits=[]
        for pat in (b'kernel_task',b'kernel',b'task'):
            for mm in re.finditer(re.escape(pat), sample, flags=re.IGNORECASE):
                hits.append({'pat':pat.decode(),'off':hex(off),'match_fileoff':hex(s_off+mm.start())})
        if hits:
            rec.setdefault('hits',[]).extend(hits)
    results.append(rec)

# aggregate
agg={}
for r in results:
    for off,data_off in r['offsets'].items():
        agg.setdefault(off,{'count':0,'hits':0})
        if data_off['printable']:
            agg[off]['count']+=1
    for h in r.get('hits',[]):
        agg[h['off']]['hits']+=1

json.dump({'entries':results,'aggregate':agg}, open(OUT,'w'), indent=2)
print('Wrote',OUT)
