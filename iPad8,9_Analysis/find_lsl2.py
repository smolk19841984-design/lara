import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# lsl xN, x0, #14 = ubfm xN, x0, #50, #63
# Encoding: 11010011 10 110010 000000 NNNNN
# = 0xD39E0000 | (Rn << 5) | Rt
# For Rn=0: 0xD39E0000 | Rt
# Mask: 0xFFFFFFE0, value: 0xD39E0000

print('=== Searching for lsl/ubfm xN, x0, #50, #63 (shift 14) ===')
found = 0
for i in range(0, len(data) - 4, 4):
    instr = struct.unpack('<I', data[i:i+4])[0]
    if (instr & 0xFFFFFFE0) == 0xD39E0000:
        rd = instr & 0x1F
        vm = base_vm + i
        print('  VM 0x%x (fileoff 0x%x) lsl x%d, x0, #14' % (vm, i, rd))
        found += 1
        if found >= 20:
            break

print('Total: %d' % found)

# Also try lsl xN, x0, #12 (for 4K pages)
print('')
print('=== Searching for lsl/ubfm xN, x0, #48, #63 (shift 12) ===')
found2 = 0
for i in range(0, len(data) - 4, 4):
    instr = struct.unpack('<I', data[i:i+4])[0]
    # lsl xN, x0, #12 = ubfm xN, x0, #52, #63
    # 0xD3A60000 | Rt
    if (instr & 0xFFFFFFE0) == 0xD3A60000:
        rd = instr & 0x1F
        vm = base_vm + i
        print('  VM 0x%x (fileoff 0x%x) lsl x%d, x0, #12' % (vm, i, rd))
        found2 += 1
        if found2 >= 10:
            break

print('Total: %d' % found2)
