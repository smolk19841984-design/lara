import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# Find all LDXR and check for ldxr -> stxr -> cbnz pattern
ldxr_list = []
for i in range(0, len(data) - 4, 4):
    instr = struct.unpack('<I', data[i:i+4])[0]
    if (instr & 0xFFC0FC00) == 0x08C0FC00:
        rt = instr & 0x1F
        rn = (instr >> 16) & 0x3F
        ldxr_list.append((i, rt, rn))

print('All LDXR instructions:')
for fo, rt, rn in ldxr_list:
    print('  fileoff 0x%x: ldxr x%d, [x%d]' % (fo, rt, rn))

# Check each for stxr + cbnz
print('')
print('=== Checking for ldxr -> stxr -> cbnz pattern ===')
found = 0
for fileoff, rt, rn in ldxr_list:
    has_stxr = False
    has_cb = False
    
    for j in range(1, 20):
        off = fileoff + j * 4
        if off + 4 > len(data):
            break
        instr = struct.unpack('<I', data[off:off+4])[0]
        
        # STXR Ws, Xt, [Xn]
        if (instr & 0xFFC0FC00) == 0x0800FC00:
            has_stxr = True
        
        # CBNZ Wt, #imm
        if (instr & 0x7F000000) == 0x35000000:
            has_cb = True
    
    if has_stxr and has_cb:
        vm = base_vm + fileoff
        print('  Found at VM 0x%x (fileoff 0x%x) ldxr x%d, [x%d]' % (vm, fileoff, rt, rn))
        
        # Disassemble
        for k in range(-2, 16):
            koff = fileoff + k * 4
            if koff < 0 or koff + 4 > len(data):
                continue
            inst = struct.unpack('<I', data[koff:koff+4])[0]
            marker = '>>>' if k == 0 else '   '
            print('    %s 0x%x: 0x%08x' % (marker, base_vm + koff, inst))
        
        found += 1
        if found >= 10:
            break

if found == 0:
    print('  None found')
