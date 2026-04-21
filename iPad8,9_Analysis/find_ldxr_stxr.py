import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# pmap_set_pte_xprr_perm uses ldxr/stxr loop to atomically update PTE
# Pattern:
#   ldxr xN, [x0]       - load PTE
#   bfi/bfxil xN, xM, #57, #3  - insert XPRR bits
#   stlxr wK, xN, [x0]  - store PTE
#   cbnz wK, retry      - retry if failed

# Search for ldxr xN, [x0]
# Encoding: 00001000 01 011111 00000 NNNNN
# = 0x085F7C00 | (Rn << 5) | Rt
# For [x0]: Rn=0, so 0x085F7C00 | Rt
# Mask: 0xFFFFFFE0, value: 0x085F7C00

print('=== Searching for ldxr xN, [x0] ===')
ldxr_addrs = []
for i in range(0, len(data) - 4, 4):
    instr = struct.unpack('<I', data[i:i+4])[0]
    if (instr & 0xFFFFFFE0) == 0x085F7C00:
        rt = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        if rn == 0:
            ldxr_addrs.append((i, rt))

print('Found %d ldxr xN, [x0] instructions' % len(ldxr_addrs))

# For each ldxr, check if followed by stlxr and cbnz within next 20 instructions
print('')
print('=== Checking for ldxr -> stlxr -> cbnz pattern ===')
found = 0
for fileoff, rt in ldxr_addrs:
    has_stlxr = False
    has_cb = False
    stlxr_off = 0
    cb_off = 0
    
    for j in range(1, 20):
        off = fileoff + j * 4
        if off + 4 > len(data):
            break
        instr = struct.unpack('<I', data[off:off+4])[0]
        
        # stlxr ws, wt, [xn]
        # 00001000 00 ws 11111 xn wt
        # Mask: 0xFFE0FC00, value: 0x0800FC00
        if (instr & 0xFFE0FC00) == 0x0800FC00:
            has_stlxr = True
            stlxr_off = j
        
        # cbnz wN, #imm
        if (instr & 0x7F000000) == 0x35000000:
            has_cb = True
            cb_off = j
    
    if has_stlxr and has_cb:
        vm = base_vm + fileoff
        print('  Found at VM 0x%x (fileoff 0x%x) stlxr@%d cbnz@%d' % (vm, fileoff, stlxr_off*4, cb_off*4))
        
        # Disassemble the function
        print('  Disassembly:')
        for k in range(-4, 20):
            koff = fileoff + k * 4
            if koff < 0 or koff + 4 > len(data):
                continue
            inst = struct.unpack('<I', data[koff:koff+4])[0]
            marker = '>>>' if k == 0 else '   '
            print('    %s 0x%x: 0x%08x' % (marker, base_vm + koff, inst))
        
        found += 1
        if found >= 5:
            break

if found == 0:
    print('  None found')
