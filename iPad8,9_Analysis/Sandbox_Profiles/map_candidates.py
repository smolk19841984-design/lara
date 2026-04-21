#!/usr/bin/env python3
import json, os, sys, re
from collections import defaultdict

BASE = os.path.dirname(__file__)
KEXT = os.path.join(BASE, 'com.apple.security.sandbox.kext')
CAND = os.path.join(BASE, 'sandbox_text_exec_functions.json')
OUT = os.path.join(BASE, 'sandbox_candidates_mapped.json')

if not os.path.isfile(KEXT) or not os.path.isfile(CAND):
    print('Required files missing')
    sys.exit(1)

with open(CAND,'r',encoding='utf-8') as f:
    data = json.load(f)

candidates = data.get('candidates', [])

# helper to extract printable strings from bytes
printable_re = re.compile(rb'[ -~]{4,}')

with open(KEXT,'rb') as f:
    kext = f.read()

# try capstone
use_cs = False
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    use_cs = True
except Exception:
    use_cs = False

results = []
keywords = [b'sandbox', b'extension', b'extension_create', b'extension_consume', b'mac_label', b'mac_proc', b'cs_enforcement', b'cs_disable', b'amfi', b'sandbox_check', b'error', b'proc', b'vnode', b'file', b'permission']

for c in candidates:
    fileoff = c['fileoff']
    vm = c['vmaddr']
    sig = bytes.fromhex(c['sig'])
    start = max(0, fileoff - 1024)
    end = min(len(kext), fileoff + 1024)
    chunk = kext[start:end]
    strings = [m.group(0).decode('utf-8',errors='replace') for m in printable_re.finditer(chunk)]
    # find relevant keywords
    hits = []
    for s in strings:
        low = s.lower()
        for kw in keywords:
            if kw.decode('utf-8') in low:
                hits.append({'string': s, 'context': low})
                break
    # disasm signature
    disasm_ok = False
    prologue = False
    insn_text = []
    if use_cs:
        try:
            for i in md.disasm(sig, vm):
                insn_text.append((i.address,i.mnemonic,i.op_str))
            if len(insn_text) >= 1:
                disasm_ok = True
                # check for stp x29, x30 pattern
                for idx in range(len(insn_text)):
                    mnem = insn_text[idx][1]
                    ops = insn_text[idx][2]
                    if mnem == 'stp' and 'x29' in ops and 'x30' in ops and 'sp' in ops:
                        # next should be mov x29, sp or add/sub
                        if idx+1 < len(insn_text):
                            nm2 = insn_text[idx+1][1]
                            ops2 = insn_text[idx+1][2]
                            if nm2 in ('mov','add','sub') and 'x29' in ops2:
                                prologue = True
                                break
        except Exception:
            pass
    else:
        # quick heuristic: check first byte sequence for 0xA9 (STP) bytes
        if sig[:1] == b'\xFD' or b'\xA9' in sig[:4]:
            disasm_ok = True

    # confidence
    confidence = 'Low'
    # High: disasm ok + prologue + keyword nearby
    if disasm_ok and prologue and hits:
        confidence = 'High'
    elif disasm_ok and (prologue or hits):
        confidence = 'Medium'
    else:
        confidence = 'Low'

    # attempt name mapping by checking exact nearby symbol-like strings
    name_guess = None
    # check for explicit symbol-like patterns
    for s in strings[:40]:
        if 'sandbox_check' in s:
            name_guess = 'sandbox_check'
            break
        if 'extension_create' in s or 'sandbox_extension_create' in s:
            name_guess = 'sandbox_extension_create'
            break
        if 'extension_consume' in s or 'sandbox_extension_consume' in s:
            name_guess = 'sandbox_extension_consume'
            break
        if 'mac_label' in s or 'mac_proc_set_label' in s or 'mac_label_update' in s:
            name_guess = 'mac_label_update'
            break
        if 'cs_enforcement' in s or 'cs_enforcement_disable' in s or 'cs_enforcement_disabled' in s:
            name_guess = 'cs_enforcement_disable'
            break
    # fallback: check any keyword hits for likely mapping
    if not name_guess and hits:
        h0 = hits[0]['string']
        if 'extension' in h0:
            name_guess = 'sandbox_extension_*'
        elif 'mac' in h0:
            name_guess = 'mac_label_*'
        elif 'cs_' in h0 or 'amfi' in h0:
            name_guess = 'cs_enforcement_*'
        elif 'sandbox' in h0:
            name_guess = 'sandbox_misc_*'

    results.append({
        'vmaddr': vm,
        'fileoff': fileoff,
        'sig': c['sig'],
        'disasm_ok': disasm_ok,
        'prologue': prologue,
        'nearby_strings_count': len(strings),
        'keyword_hits': hits[:10],
        'name_guess': name_guess,
        'confidence': confidence
    })

with open(OUT,'w',encoding='utf-8') as f:
    json.dump({'mapped': results}, f, indent=2)

print('[+] Wrote mapping to', OUT)

