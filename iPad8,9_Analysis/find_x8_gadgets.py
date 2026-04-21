import struct
import json
import os

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# Find ldr x8, [sp, #imm] gadgets
print('Searching for ldr x8, [sp, #imm] gadgets...')
ldr_x8 = []
for i in range(0, len(data) - 4, 4):
    instr = struct.unpack('<I', data[i:i+4])[0]
    # ldr x8, [sp, #imm] = 11111 00 1 imm12 11111 01000
    if (instr & 0xFFC003FF) == 0xF94003E8:
        imm = ((instr >> 10) & 0xFFF) * 8
        vm_addr = base_vm + i
        ldr_x8.append({'addr': vm_addr, 'fileoff': i, 'imm': imm})

print('Found %d ldr x8, [sp, #imm] gadgets' % len(ldr_x8))
for g in ldr_x8[:10]:
    print('  VM 0x%x (fileoff 0x%x) imm=%d' % (g['addr'], g['fileoff'], g['imm']))

# Find ldp x8, x9, [sp], #imm gadgets
print('')
print('Searching for ldp x8, x9, [sp], #imm gadgets...')
ldp_x8_x9 = []
for i in range(0, len(data) - 4, 4):
    instr = struct.unpack('<I', data[i:i+4])[0]
    # ldp x8, x9, [sp], #imm = 10101 000 imm7 11111 001000
    if (instr & 0xFFC003FF) == 0xA8C003E8:
        imm = ((instr >> 15) & 0x7F) * 8
        vm_addr = base_vm + i
        ldp_x8_x9.append({'addr': vm_addr, 'fileoff': i, 'imm': imm})

print('Found %d ldp x8, x9, [sp], #imm gadgets' % len(ldp_x8_x9))
for g in ldp_x8_x9[:10]:
    print('  VM 0x%x (fileoff 0x%x) imm=%d' % (g['addr'], g['fileoff'], g['imm']))

# Save results
output = {
    'ldr_x8_sp': ldr_x8[:50],
    'ldp_x8_x9_sp': ldp_x8_x9[:50],
}
out_path = os.path.join(os.path.dirname(kernel_path), 'rop_gadgets_x8.json')
with open(out_path, 'w') as f:
    json.dump(output, f, indent=2)
print('')
print('Results saved to: ' + out_path)
