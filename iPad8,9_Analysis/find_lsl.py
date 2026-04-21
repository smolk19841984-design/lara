import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# Search for lsl xN, x0, #14
# Encoding: 11010011 10001110 00000000 101XXXXX
# Actually: D3 8E 00 A0-D3 8E 00 BF
# Mask: 0xFFFFFC1F, value: 0xD38E0000 | (Rd << 0)
# Wait, lsl xN, xM, #imm = UBFM Xt, Xn, (64-imm), (63-imm)
# lsl xN, x0, #14 = ubfm xN, x0, #50, #49
# Actually: lsl xN, xM, #shift = UBFM Xt, Xn, (64-shift)&63, 63-shift
# For shift=14: (64-14)&63=50, 63-14=49
# UBFM encoding: 11010011 10 imm6 Rn Rt
# imm6 for lsb=50: 110010
# So: 0xD38E0000 | (Rn << 5) | Rt
# For Rn=0 (x0): 0xD38E0000 | Rt
# Mask: 0xFFFFFC1F, value: 0xD38E0000

print('=== Searching for lsl xN, x0, #14 ===')
found = 0
for i in range(0, len(data) - 4, 4):
    instr = struct.unpack('<I', data[i:i+4])[0]
    if (instr & 0xFFFFFC1F) == 0xD38E0000:
        rd = instr & 0x1F
        vm = base_vm + i
        print('  VM 0x%x (fileoff 0x%x) lsl x%d, x0, #14' % (vm, i, rd))
        found += 1
        if found >= 20:
            break

if found == 0:
    print('  None found')
print('Total found: %d' % found)
