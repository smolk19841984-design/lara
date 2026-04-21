#!/usr/bin/env python3
import os,sys,json,binascii
BASE=os.path.dirname(__file__)
SANDBOX_KEXT=os.path.join(BASE,'com.apple.security.sandbox.kext')
CAND_JSON=os.path.join(BASE,'sandbox_text_exec_functions.json')
VERIFIED_HEADER=os.path.join(BASE,'sandbox_verified_offsets.h')
AMFI_PATH=os.path.join(os.path.dirname(BASE),'21D61','kernelcache_decompressed','kexts','com.apple.driver.AppleMobileFileIntegrity')

if not os.path.isfile(SANDBOX_KEXT):
    print('Sandbox kext not found:', SANDBOX_KEXT); sys.exit(1)
if not os.path.isfile(CAND_JSON):
    print('Candidates JSON not found:', CAND_JSON); sys.exit(1)

with open(CAND_JSON,'r',encoding='utf-8') as f:
    data=json.load(f)

# load signatures from offsets_sandbox_candidates.h by reading that file
sigs_file=os.path.join(BASE,'offsets_sandbox_candidates.h')
if not os.path.isfile(sigs_file):
    print('Signatures header missing:', sigs_file); sys.exit(1)

# parse signatures by simple heuristic: find sandbox_sig_N arrays
sigs={}
with open(sigs_file,'r',encoding='utf-8') as f:
    txt=f.read()
import re
for m in re.finditer(r'static const unsigned char (sandbox_sig_\d+)\[\] = \{([^}]+)\};', txt):
    name=m.group(1);
    bytes_txt=m.group(2)
    vals=[int(x.strip(),16) for x in bytes_txt.split(',') if x.strip()]
    sigs[name]=bytes(vals)

# map candidate vmaddr to sig name heuristically by order (as created earlier)
candidates=data['candidates']
mapped=[]
with open(SANDBOX_KEXT,'rb') as f:
    k=f.read()
for i,c in enumerate(candidates, start=1):
    sig_name=f'sandbox_sig_{i}'
    expected=sigs.get(sig_name)
    fileoff=int(c['fileoff'])
    actual=k[fileoff:fileoff+32]
    match = actual==expected
    mapped.append({'index':i,'vmaddr':c['vmaddr'],'fileoff':fileoff,'match':match,'expected_hex':expected.hex(),'actual_hex':actual.hex()})

print('Validation results for sandbox kext candidates:')
for m in mapped:
    print(f"candidate {m['index']}: fileoff=0x{m['fileoff']:X} vm=0x{m['vmaddr']:X} match={m['match']}")

# If mismatches, try find expected signature nearby +/-512 bytes
for m in mapped:
    if not m['match']:
        expected=bytes.fromhex(m['expected_hex'])
        fo=m['fileoff']
        start=max(0,fo-512); end=min(len(k), fo+512)
        idx=k.find(expected,start,end)
        if idx!=-1:
            print(f"  Found expected signature for candidate {m['index']} at nearby fileoff 0x{idx:X}")
            m['found_nearby']=idx
        else:
            m['found_nearby']=None

# Now search AMFI kext for cs_enforcement_disable
print('\nSearching AMFI kext for cs_enforcement_disable and disable patterns...')
if not os.path.isfile(AMFI_PATH):
    print('AMFI kext not found at expected path:', AMFI_PATH)
    # try alternative path under Sandbox_Profiles
    alt=os.path.join(BASE,'com.apple.driver.AppleMobileFileIntegrity.kext')
    if os.path.isfile(alt):
        AMFI_PATH=alt
        print('Using alternative AMFI path:', AMFI_PATH)
    else:
        print('No AMFI kext available in workspace to search. Aborting AMFI scan.'); AMFI_PATH=None

if AMFI_PATH:
    with open(AMFI_PATH,'rb') as f:
        a=f.read()
    # search for ascii strings
    def extract_strings(b, minlen=4):
        out=[]; cur=[]
        for ch in b:
            if 32<=ch<127:
                cur.append(chr(ch))
            else:
                if len(cur)>=minlen:
                    out.append(''.join(cur))
                cur=[]
        if len(cur)>=minlen: out.append(''.join(cur))
        return out
    strings=extract_strings(a,4)
    hits=[s for s in strings if 'cs_enforcement' in s or 'cs_enforce' in s or 'cs_enforcement_disable' in s]
    print('String hits in AMFI for cs_enforcement*:', len(hits))
    for h in hits[:20]: print(' ',h)
    # search for byte patterns: mov w0, #0 ; str w0, [x0, #imm]
    # mov w0, #0 often encoded as movz w0, #0 => 0x52800000 little-endian? but mov immediate forms vary
    # look for sequence: 00 00 80 52 (mov w0, #0) little-endian -> bytes 0x52 0x80 0x00 0x00
    pattern=b'\x52\x80\x00\x00'
    occurrences=[i for i in range(len(a)) if a.startswith(pattern,i)]
    print('mov w0,#0 pattern occurrences:', len(occurrences))
    # For each occurrence, check next 8-12 bytes for store into [x0,#imm] pattern: STR (register) encodings vary; look for 0xF9 or 0xF8 sequences
    candidates_cs=[]
    for off in occurrences[:200]:
        seq=a[off:off+16]
        # naive: look for 0xF9 or 0xF8 in following bytes indicating STR/STRB/STRH
        if b'\xF9' in seq or b'\xF8' in seq:
            candidates_cs.append(off)
    print('mov+store heuristic hits:', len(candidates_cs))
    for o in candidates_cs[:20]:
        print(' candidate at fileoff 0x%X' % o)

# write JSON results
out={'sandbox_validation':mapped}
with open(os.path.join(BASE,'sandbox_validation_results.json'),'w',encoding='utf-8') as f:
    json.dump(out,f,indent=2)

print('\nResults saved to sandbox_validation_results.json')
