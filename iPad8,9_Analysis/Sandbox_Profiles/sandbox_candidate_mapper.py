#!/usr/bin/env python3
"""
Map extracted signatures to likely symbol names using nearby strings and disassembly.
Outputs sandbox_sigs_mapped.json and prints a C struct ready block.
"""
import json, os, sys, re
from collections import defaultdict

BASE = os.path.dirname(__file__)
KEXT = os.path.join(BASE, 'com.apple.security.sandbox.kext')
CAND_JSON = os.path.join(BASE, 'sandbox_text_exec_functions.json')
OUT_JSON = os.path.join(BASE, 'sandbox_sigs_mapped.json')

if not os.path.isfile(KEXT) or not os.path.isfile(CAND_JSON):
    print('Missing files')
    sys.exit(1)

with open(CAND_JSON,'r',encoding='utf-8') as f:
    data = json.load(f)

text_fileoff = data['text_section']['fileoff']
vmbase = data['text_section'].get('vmaddr')

with open(KEXT,'rb') as f:
    kb = f.read()

candidates = data['candidates']

# helper to extract printable strings near file offset
import string

def extract_strings_around(buf, off, radius=512):
    start = max(0, off - radius)
    end = min(len(buf), off + radius)
    seg = buf[start:end]
    # find null-terminated ASCII strings >=4
    strs = []
    cur = []
    for b in seg:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= 4:
                s = ''.join(cur)
                strs.append(s)
            cur = []
    # final
    if len(cur) >= 4:
        strs.append(''.join(cur))
    # dedupe preserving order
    seen = set(); out=[]
    for s in strs:
        if s not in seen:
            seen.add(s); out.append(s)
    return out

# attempt disassembly validation via capstone
have_cs = False
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    have_cs = True
except Exception:
    have_cs = False

mapped = []

for c in candidates:
    fileoff = int(c['fileoff'])
    # read 64 bytes
    start = fileoff
    sig_bytes = bytes.fromhex(c['sig'])
    # Strings around
    strs = extract_strings_around(kb, fileoff, radius=1024)
    # disasm first few instructions
    is_code = False
    disasm = []
    if have_cs:
        try:
            for i,ins in enumerate(md.disasm(sig_bytes, c.get('vmaddr',0))):
                disasm.append((ins.address, ins.mnemonic, ins.op_str))
                if i>10: break
            # heuristic: if we got at least 2 instructions, treat as code
            if len(disasm) >= 2:
                is_code = True
        except Exception:
            is_code = False
    else:
        # fallback heuristic: check for frequent instruction bytes such as 0xFD (STP) or 0xF9 (STR/ADR/ADD)
        if sig_bytes.count(b'\xFD'[0:1]) + sig_bytes.count(b'\xF9'[0:1]) > 3:
            is_code = True

    mapped.append({
        'vmaddr': c['vmaddr'],
        'fileoff': c['fileoff'],
        'sig': c['sig'],
        'is_code': is_code,
        'nearby_strings': strs[:40],
        'disasm_sample': [(hex(a),m,o) for (a,m,o) in disasm]
    })

# Heuristic matching to target symbols
# keywords for symbols
sym_keys = {
    'sandbox_check': [r'sandbox', r'violation', r'Unenforced', r'file-read', r'process-exec', r'profile', r'sbpl', r'sbpl', r'default'],
    'sandbox_extension_create': [r'extension', r'sandbox_extension', r'extension_create', r'external', r'ext', r'extension_consume'],
    'mac_label_update': [r'mac_label', r'mac_proc', r'proc_set_label', r'mac_label_update', r'label'],
    'cs_enforcement_disable': [r'cs_enforcement', r'cs', r'amfi', r'codesign', r'code-sign', r'enforcement']
}

# score candidates
for entry in mapped:
    scores = {k:0 for k in sym_keys}
    stext = ' '.join(entry['nearby_strings']).lower()
    for sym,keys in sym_keys.items():
        for kw in keys:
            if re.search(kw, stext, re.IGNORECASE):
                scores[sym] += 2
    # disasm hints: if calls/blr to known functions might indicate certain roles - skip for now
    # is_code increases confidence
    if entry['is_code']:
        for k in scores: scores[k] += 1
    # pick best
    best_sym = max(scores.items(), key=lambda x: x[1])
    confidence = 'Low'
    if best_sym[1] >= 4:
        confidence = 'High'
    elif best_sym[1] >= 2:
        confidence = 'Medium'
    else:
        confidence = 'Low'
    entry['match'] = best_sym[0]
    entry['score'] = best_sym[1]
    entry['confidence'] = confidence

# save
with open(OUT_JSON,'w',encoding='utf-8') as f:
    json.dump({'mapped': mapped}, f, indent=2)

# Print C-ready struct for matches: convert vmaddr to relative to kernel base if possible
# Kernel base anchor known? Try reading offsets_generated file for amfi anchor to compute kernel base
kernel_base = None
try:
    import re
    ofile = os.path.join(BASE, '..', 'offsets_generated_iPad8_9_17_3_1.json')
    if os.path.isfile(ofile):
        j = json.load(open(ofile,'r',encoding='utf-8'))
        amfi = j.get('amfi')
        if amfi:
            # amfi absolute - in their earlier notes kernel base 0xfffffff007004000 known
            kernel_base = 0xfffffff007004000
except Exception:
    kernel_base = None

print('\n=== Mapping Results ===\n')
for e in mapped:
    vm_abs = e['vmaddr']
    if kernel_base and vm_abs > (1<<63):
        # vmaddr in JSON may be large unsigned; keep as hex string
        vm_hex = hex(vm_abs & ((1<<64)-1))
    else:
        vm_hex = hex(vm_abs)
    print(f"vm={vm_hex} fileoff=0x{e['fileoff']:X} is_code={e['is_code']} match={e['match']} conf={e['confidence']} score={e['score']}")
    print('  nearby strings:', e['nearby_strings'][:8])
    if e['disasm_sample']:
        print('  disasm sample:', e['disasm_sample'][:6])
    print('')

# Also emit a final C struct block for high/medium confidence matches
print('\n/* C struct with confirmed addresses and signatures (confidence >= Medium) */')
print('typedef struct { uint64_t vmaddr; const unsigned char *sig; size_t siglen; const char *name; const char *confidence; } sandbox_confirm_t;')
print('static sandbox_confirm_t sandbox_confirmed[] = {')
for e in mapped:
    if e['confidence'] in ('High','Medium'):
        name = e['match']
        print(f"  {{ 0x{e['vmaddr']:X}ULL, (const unsigned char*)\"{e['sig']}\", 32, \"{name}\", \"{e['confidence']}\" }},")
print('};')

print('\n[+] Wrote', OUT_JSON)
print('\nDone')
