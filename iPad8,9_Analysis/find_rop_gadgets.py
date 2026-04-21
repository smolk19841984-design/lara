import struct
import json
import os
import sys

def is_ldr_x0_sp_imm(instr):
    return (instr & 0xFFC003FF) == 0xF94003E0

def is_ldr_x1_sp_imm(instr):
    return (instr & 0xFFC003FF) == 0xF94003E1

def is_ldr_x2_sp_imm(instr):
    return (instr & 0xFFC003FF) == 0xF94003E2

def is_ldr_x3_sp_imm(instr):
    return (instr & 0xFFC003FF) == 0xF94003E3

def is_ldp_x0_x1_sp(instr):
    return (instr & 0xFFC003FF) == 0xA8C003E0

def is_ldp_x2_x3_sp(instr):
    return (instr & 0xFFC003FF) == 0xA8C003E2

def is_ldp_x1_x2_sp(instr):
    return (instr & 0xFFC003FF) == 0xA8C003E1

def is_blr(instr):
    return (instr & 0xFFFFFC1F) == 0xD63F0000

def is_ret(instr):
    return instr == 0xD65F03C0

def is_ldp_x29_x30_sp(instr):
    return (instr & 0xFFC007FF) == 0xA8C007FD

def get_ldr_imm(instr):
    imm = (instr >> 10) & 0xFFF
    return imm * 8

def get_ldp_imm(instr):
    imm = (instr >> 15) & 0x7F
    return imm * 8

def get_blr_reg(instr):
    return (instr >> 5) & 0x1F

def analyze_gadgets(data, base_vm, base_fileoff):
    gadgets = {
        'ldr_x0_sp': [],
        'ldr_x1_sp': [],
        'ldr_x2_sp': [],
        'ldr_x3_sp': [],
        'ldp_x0_x1_sp': [],
        'ldp_x1_x2_sp': [],
        'ldp_x2_x3_sp': [],
        'ldp_x29_x30_sp': [],
        'blr': [],
        'ret': [],
    }
    
    for i in range(0, len(data) - 4, 4):
        instr = struct.unpack('<I', data[i:i+4])[0]
        vm_addr = base_vm + i
        
        if is_ldr_x0_sp_imm(instr):
            gadgets['ldr_x0_sp'].append({'addr': vm_addr, 'fileoff': base_fileoff + i, 'imm': get_ldr_imm(instr)})
        if is_ldr_x1_sp_imm(instr):
            gadgets['ldr_x1_sp'].append({'addr': vm_addr, 'fileoff': base_fileoff + i, 'imm': get_ldr_imm(instr)})
        if is_ldr_x2_sp_imm(instr):
            gadgets['ldr_x2_sp'].append({'addr': vm_addr, 'fileoff': base_fileoff + i, 'imm': get_ldr_imm(instr)})
        if is_ldr_x3_sp_imm(instr):
            gadgets['ldr_x3_sp'].append({'addr': vm_addr, 'fileoff': base_fileoff + i, 'imm': get_ldr_imm(instr)})
        if is_ldp_x0_x1_sp(instr):
            gadgets['ldp_x0_x1_sp'].append({'addr': vm_addr, 'fileoff': base_fileoff + i, 'imm': get_ldp_imm(instr)})
        if is_ldp_x1_x2_sp(instr):
            gadgets['ldp_x1_x2_sp'].append({'addr': vm_addr, 'fileoff': base_fileoff + i, 'imm': get_ldp_imm(instr)})
        if is_ldp_x2_x3_sp(instr):
            gadgets['ldp_x2_x3_sp'].append({'addr': vm_addr, 'fileoff': base_fileoff + i, 'imm': get_ldp_imm(instr)})
        if is_ldp_x29_x30_sp(instr):
            gadgets['ldp_x29_x30_sp'].append({'addr': vm_addr, 'fileoff': base_fileoff + i, 'imm': get_ldp_imm(instr)})
        if is_blr(instr):
            reg = get_blr_reg(instr)
            gadgets['blr'].append({'addr': vm_addr, 'fileoff': base_fileoff + i, 'reg': reg})
        if is_ret(instr):
            gadgets['ret'].append({'addr': vm_addr, 'fileoff': base_fileoff + i})
    
    return gadgets

def main():
    kernel_path = sys.argv[1] if len(sys.argv) > 1 else None
    if not kernel_path or not os.path.exists(kernel_path):
        candidates = [
            r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed',
        ]
        for p in candidates:
            if os.path.exists(p):
                kernel_path = p
                break
        if not kernel_path:
            print('Kernel binary not found.')
            return
    
    print('Loading kernel: ' + kernel_path)
    with open(kernel_path, 'rb') as f:
        data = f.read()
    
    size_mb = len(data) / 1024 / 1024
    print('Kernel size: ' + str(len(data)) + ' bytes (' + str(round(size_mb, 1)) + ' MB)')
    
    base_vm = 0xfffffff007004000
    base_fileoff = 0
    
    print('Scanning for ROP gadgets...')
    gadgets = analyze_gadgets(data, base_vm, base_fileoff)
    
    print('')
    print('=== Gadget Summary ===')
    for name, glist in gadgets.items():
        print('  ' + name + ': ' + str(len(glist)) + ' found')
        if glist:
            g = glist[0]
            print('    First: VM 0x' + format(g['addr'], 'x') + ' (fileoff 0x' + format(g['fileoff'], 'x') + ')')
    
    print('')
    print('=== Top individual gadgets ===')
    for name in ['ldp_x0_x1_sp', 'ldp_x1_x2_sp', 'ldp_x2_x3_sp', 'ldr_x0_sp', 'ldr_x1_sp', 'ldr_x2_sp', 'ldr_x3_sp']:
        if gadgets[name]:
            print('')
            print(name + ' (top 5):')
            for g in gadgets[name][:5]:
                imm_str = str(g.get('imm', 'N/A')) if 'imm' in g else 'N/A'
                print('  VM 0x' + format(g['addr'], 'x') + ' (fileoff 0x' + format(g['fileoff'], 'x') + ') imm=' + imm_str)
    
    if gadgets['blr']:
        print('')
        print('blr gadgets (top 10):')
        for g in gadgets['blr'][:10]:
            print('  VM 0x' + format(g['addr'], 'x') + ' (fileoff 0x' + format(g['fileoff'], 'x') + ') reg=x' + str(g['reg']))
    
    output = {
        'gadgets': {k: v[:50] for k, v in gadgets.items()},
    }
    
    out_path = os.path.join(os.path.dirname(kernel_path), 'rop_gadgets.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print('')
    print('Results saved to: ' + out_path)

if __name__ == '__main__':
    main()
