import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# Strategy: Find JOP gadgets - sequences that load registers and branch to another register
# We need: load x0, x1, x2 from stack, then blr to function

# Look for: ldp x0, x1, [sp, #imm]; ...; br/blr xN
print('=== JOP: ldp x0, x1, [sp, #imm] followed by br/blr within 8 instructions ===')
found = 0
for i in range(0, len(data) - 40, 4):
    instr0 = struct.unpack('<I', data[i:i+4])[0]
    if (instr0 & 0xFFC003FF) == 0xA9C003E0:  # ldp x0, x1, [sp, #imm] (no writeback)
        imm = ((instr0 >> 15) & 0x7F) * 8
        for j in range(1, 9):
            off = i + j * 4
            instr = struct.unpack('<I', data[off:off+4])[0]
            # br xN or blr xN
            if (instr & 0xFFFFFC1F) in [0xD61F0000, 0xD63F0000]:
                reg = (instr >> 5) & 0x1F
                vm = base_vm + i
                print('  VM 0x%x ldp x0,x1,[sp,#%d] -> br/blr x%d (offset %d)' % (vm, imm, reg, j*4))
                found += 1
                if found >= 15:
                    break
        if found >= 15:
            break

if found == 0:
    print('  None found')

# Also check: ldr x0, [sp, #imm]; ...; br/blr xN
print('')
print('=== JOP: ldr x0, [sp, #imm] followed by br/blr within 8 instructions ===')
found = 0
for i in range(0, len(data) - 40, 4):
    instr0 = struct.unpack('<I', data[i:i+4])[0]
    if (instr0 & 0xFFC003FF) == 0xF94003E0:
        imm = ((instr0 >> 10) & 0xFFF) * 8
        for j in range(1, 9):
            off = i + j * 4
            instr = struct.unpack('<I', data[off:off+4])[0]
            if (instr & 0xFFFFFC1F) in [0xD61F0000, 0xD63F0000]:
                reg = (instr >> 5) & 0x1F
                vm = base_vm + i
                print('  VM 0x%x ldr x0,[sp,#%d] -> br/blr x%d (offset %d)' % (vm, imm, reg, j*4))
                found += 1
                if found >= 15:
                    break
        if found >= 15:
            break

if found == 0:
    print('  None found')

# Check: ldp x0, x1, [sp], #imm; ...; ldp x2, x3, [sp], #imm; ...; br/blr xN
print('')
print('=== JOP: Combined ldp x0,x1 + ldp x2,x3 + br/blr ===')
found = 0
for i in range(0, len(data) - 60, 4):
    instr0 = struct.unpack('<I', data[i:i+4])[0]
    if (instr0 & 0xFFC003FF) == 0xA8C003E0:  # ldp x0, x1, [sp], #imm
        imm1 = ((instr0 >> 15) & 0x7F) * 8
        # Look for ldp x2, x3 within next 8 instructions
        for j in range(1, 8):
            off1 = i + j * 4
            instr1 = struct.unpack('<I', data[off1:off1+4])[0]
            if (instr1 & 0xFFC003FF) == 0xA8C003E2:  # ldp x2, x3, [sp], #imm
                imm2 = ((instr1 >> 15) & 0x7F) * 8
                # Look for br/blr within next 8 instructions
                for k in range(j+1, j+9):
                    off2 = i + k * 4
                    instr2 = struct.unpack('<I', data[off2:off2+4])[0]
                    if (instr2 & 0xFFFFFC1F) in [0xD61F0000, 0xD63F0000]:
                        reg = (instr2 >> 5) & 0x1F
                        vm = base_vm + i
                        print('  VM 0x%x ldp x0,x1 -> ldp x2,x3 -> br/blr x%d' % (vm, reg))
                        found += 1
                        if found >= 10:
                            break
                if found >= 10:
                    break
        if found >= 10:
            break

if found == 0:
    print('  None found')
