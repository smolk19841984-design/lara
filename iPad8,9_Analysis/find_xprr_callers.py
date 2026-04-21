import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# pmap_set_xprr_perm calls pmap_set_pte_xprr_perm
# pmap_set_xprr_perm signature:
#   prologue: stp x29, x30, [sp, #-0x10]!
#   add x29, sp, #0
#   lsl xN, x0, #14  (pai << PAGE_SHIFT)
#   bl pmap_pte
#   bl pmap_set_pte_xprr_perm

# Search for prologue + lsl pattern
prologue = bytes([0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91])

print('=== Searching for pmap_set_xprr_perm (prologue + lsl x?, x0, #14) ===')
found = 0
for i in range(0, len(data) - 32, 4):
    if data[i:i+8] == prologue:
        # Check for lsl x?, x0, #14 in next 4 instructions
        for j in range(2, 6):
            off = i + j * 4
            if off + 4 > len(data):
                break
            instr = struct.unpack('<I', data[off:off+4])[0]
            # lsl xN, x0, #14 = D3 8E 00 A0-D3 8E 00 BF
            b0 = instr & 0xFF
            b1 = (instr >> 8) & 0xFF
            b2 = (instr >> 16) & 0xFF
            b3 = (instr >> 24) & 0xFF
            if b1 == 0x00 and b2 == 0x8E and b3 == 0xD3 and (b0 & 0xF0) == 0xA0:
                vm = base_vm + i
                print('Found at VM 0x%x (fileoff 0x%x)' % (vm, i))
                
                # Disassemble the function
                print('Disassembly:')
                for k in range(0, 40):
                    koff = i + k * 4
                    if koff + 4 > len(data):
                        break
                    inst = struct.unpack('<I', data[koff:koff+4])[0]
                    marker = '>>>' if k == j else '   '
                    print('  %s 0x%x: 0x%08x' % (marker, base_vm + koff, inst))
                
                # Find BL targets
                print('BL targets:')
                for k in range(6, 40):
                    koff = i + k * 4
                    if koff + 4 > len(data):
                        break
                    inst = struct.unpack('<I', data[koff:koff+4])[0]
                    if (inst & 0xFC000000) == 0x94000000:
                        offset = inst & 0x3FFFFFF
                        if offset & 0x2000000:
                            offset |= 0xFC000000
                        bl_target = base_vm + koff + offset * 4
                        print('  BL at 0x%x -> 0x%x' % (base_vm + koff, bl_target))
                    if inst == 0xD65F03C0:  # ret
                        break
                
                found += 1
                print('')
                if found >= 5:
                    break
    if found >= 5:
        break

if found == 0:
    print('None found')
