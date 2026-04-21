#!/usr/bin/env python3
"""
Scan __TEXT_EXEC.__text for ARM64 function prologues and extract 16-32 byte signatures.
Produces: sandbox_text_exec_functions.json and plaintext summary.
"""
import json, os, sys, binascii
from collections import Counter

BASE_DIR = os.path.dirname(__file__)
KEXT = os.path.join(BASE_DIR, 'com.apple.security.sandbox.kext')
ANALYSIS = os.path.join(BASE_DIR, 'macho_analysis.json')
OUT_JSON = os.path.join(BASE_DIR, 'sandbox_text_exec_functions.json')

if not os.path.isfile(KEXT):
    print('[!] Kext not found:', KEXT)
    sys.exit(1)
if not os.path.isfile(ANALYSIS):
    print('[!] Analysis JSON not found:', ANALYSIS)
    sys.exit(1)

with open(ANALYSIS, 'r', encoding='utf-8') as f:
    info = json.load(f)

# find __TEXT_EXEC.__text entry
text_sec = None
for s in info.get('header', {}).get('sections', []):
    if s.get('segname') == '__TEXT_EXEC' and s.get('sectname') == '__text':
        text_sec = s
        break
if text_sec is None:
    # fallback to sections_summary
    for s in info.get('sections_summary', []):
        if s['name'] == '__TEXT_EXEC.__text':
            text_sec = {'offset': s['offset'], 'size': s['size']}
            break
if text_sec is None:
    print('[!] __TEXT_EXEC.__text section not found in analysis JSON')
    sys.exit(1)

fileoff = int(text_sec.get('offset'))
size = int(text_sec.get('size'))
# VM addr if available
vmaddr = None
try:
    vmaddr = int(text_sec.get('addr'))
except Exception:
    # try header vmaddr mapping
    vmaddr = info.get('header', {}).get('sections', [{}])[0].get('addr')

print(f"[*] __TEXT_EXEC.__text: fileoff=0x{fileoff:X} size=0x{size:X} vmaddr={vmaddr}")

with open(KEXT, 'rb') as f:
    f.seek(fileoff)
    blob = f.read(size)

candidates = []

# Attempt to use Capstone if available
use_cs = False
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    use_cs = True
    print('[*] Capstone available: using disassembly heuristics')
except Exception:
    print('[*] Capstone not available: using byte-pattern heuristics')

if use_cs:
    # Disassemble and look for typical prologue: stp x29, x30, [sp, #-imm]!  followed by mov x29, sp
    insns = list(md.disasm(blob, vmaddr or 0))
    for i in range(len(insns)-1):
        a = insns[i]
        b = insns[i+1]
        try:
            if a.mnemonic == 'stp' and 'x29' in a.op_str and 'x30' in a.op_str and 'sp' in a.op_str and '!' in a.op_str:
                if b.mnemonic in ('mov', 'add', 'sub') and 'x29' in b.op_str:
                    off_in_blob = a.address - (vmaddr or 0)
                    if 0 <= off_in_blob < len(blob):
                        sig = blob[off_in_blob:off_in_blob+32]
                        candidates.append({'vmaddr': a.address, 'fileoff': fileoff + off_in_blob, 'sig': sig.hex()})
        except Exception:
            continue
else:
    # Basic byte-pattern search: look for likely STP opcode prefixes (little-endian patterns containing 0xA9)
    # Search for common bytes 0xA9 0x... which start STP immediate encodings
    hits = []
    i = 0
    while True:
        idx = blob.find(b'\xA9', i)
        if idx == -1:
            break
        # take next 4 bytes as potential instruction
        if idx + 4 <= len(blob):
            ins = blob[idx:idx+4]
            hits.append(idx)
        i = idx + 1
    # reduce duplicates, and for each hit extract signature
    for idx in sorted(set(hits)):
        sig = blob[idx:idx+32]
        candidates.append({'vmaddr': (vmaddr or 0) + idx, 'fileoff': fileoff + idx, 'sig': sig.hex()})

# Deduplicate signatures and compute counts
sig_counts = Counter([c['sig'] for c in candidates])
unique = []
for c in candidates:
    unique.append({
        'vmaddr': c['vmaddr'],
        'fileoff': c['fileoff'],
        'sig': c['sig'],
        'unique': sig_counts[c['sig']] == 1,
        'dup_count': sig_counts[c['sig']]
    })

# Sort by fileoff
unique = sorted(unique, key=lambda x: x['fileoff'])

with open(OUT_JSON, 'w', encoding='utf-8') as f:
    json.dump({'text_section': {'fileoff': fileoff, 'size': size, 'vmaddr': vmaddr}, 'candidates': unique}, f, indent=2)

# Print brief summary
print('\n[+] Candidate function prologue signatures written to:', OUT_JSON)
print('[+] Candidates found:', len(unique))
print('\nTop 20 candidates:')
for c in unique[:20]:
    print(f"  vm=0x{c['vmaddr']:X} fileoff=0x{c['fileoff']:X} unique={c['unique']} dup={c['dup_count']} sig={c['sig'][:64]}")

print('\n[*] Done')
