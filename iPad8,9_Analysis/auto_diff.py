import os
import sys
import re

def parse_asm(filepath):
    blocks = {}
    current_addr = None
    current_instructions = []

    # Format: 0xfffffff0089f1c90:  5f 24 03 d5   bti  c
    insn_pattern = re.compile(r'^(0x[0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s+(.*)')

    with open(filepath, 'r', encoding='utf-16le', errors='ignore') as f:
        for line in f:
            insn_m = insn_pattern.match(line.strip())
            if insn_m:
                addr = insn_m.group(1)
                mnem = insn_m.group(2).strip()
                
                # Strip comments
                idx = mnem.find('//')
                if idx != -1:
                    mnem = mnem[:idx].strip()
                
                if mnem in ['bti  c', 'pacibsp'] or not current_addr:
                    if current_addr:
                        blocks[current_addr] = current_instructions
                    current_addr = addr
                    current_instructions = []
                    
                current_instructions.append(mnem)

        if current_addr:
            blocks[current_addr] = current_instructions

    return blocks

def main():
    vuln_asm = r"iPad8,9_Analysis\kexts_21D61\asm.txt"
    patch_asm = r"iPad8,9_Analysis\kexts_21E219\asm.txt"

    print("[*] Parsing Vulnerable ASM (21D61)...")
    funcs_vuln = parse_asm(vuln_asm)
    print(f"[*] Found {len(funcs_vuln)} raw code blocks in Vulnerable.\n")
    
    print("[*] Parsing Patched ASM (21E219)...")
    funcs_patch = parse_asm(patch_asm)
    print(f"[*] Found {len(funcs_patch)} raw code blocks in Patched.\n")

    print("[*] Looking for the CVE-2024-23265 patch pattern (checks against -1).")
    print("    Often implemented as `cmn xN, #0x1` or similar.")
    
    # Store blocks by index to compare Vuln and Patched
    vuln_blocks = list(funcs_vuln.values())
    patch_blocks = list(funcs_patch.values())
    
    vuln_addrs = list(funcs_vuln.keys())
    patch_addrs = list(funcs_patch.keys())

    suspicious_blocks = []
    for i in range(min(len(vuln_blocks), len(patch_blocks))):
        insns_v = vuln_blocks[i]
        insns_p = patch_blocks[i]
        
        joined_p = '\n'.join(insns_p)
        if 'cmn' in joined_p and '0x1' in joined_p:
            # Did it change?
            if len(insns_p) > len(insns_v):
                suspicious_blocks.append((patch_addrs[i], insns_p, len(insns_p) - len(insns_v)))

    print(f"\n[+] Found {len(suspicious_blocks)} modified functions in Patched with 'cmn' additions.")
    for addr, insns, diff_len in suspicious_blocks:
        print(f"  -> Block starting at {addr} has {diff_len} NEW instructions!")
        for j, ins in enumerate(insns):
            if 'cmn' in ins or 'ccmn' in ins:
                # print 2 instructions before and after
                ctx = insns[max(0, j-2):min(len(insns), j+3)]
                print(f"       Context around check:")
                for c in ctx:
                    print(f"         {c}")
                print()

if __name__ == "__main__":
    main()
