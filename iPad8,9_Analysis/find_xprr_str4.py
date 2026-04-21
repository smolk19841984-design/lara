import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# The string is at fileoff 0x4cdda
# Find functions that reference this string via ADRP
# ADRP uses VM addresses, so we need to convert fileoff to VM

# __LINKEDIT in decompressed kernel:
# fileoff=0x0, vmaddr=0x7c000
# So string VM = 0x7c000 + 0x4cdda = 0xc8dda

str_vm = 0x7c000 + 0x4cdda
str_page = str_vm & ~0xFFF
str_off = str_vm & 0xFFF

print('String VM: 0x%x, page: 0x%x, offset: 0x%x' % (str_vm, str_page, str_off))

# Now search for ADRP+ADD that references this VM
print('')
print('=== Searching for ADRP+ADD referencing string VM ===')
found = 0
for i in range(0, len(data) - 8, 4):
    instr1 = struct.unpack('<I', data[i:i+4])[0]
    instr2 = struct.unpack('<I', data[i+4:i+8])[0]
    
    if (instr1 & 0x9F000000) == 0x90000000:  # ADRP
        rd = instr1 & 0x1F
        immlo = (instr1 >> 29) & 0x3
        immhi = (instr1 >> 5) & 0x7FFFF
        adr_page = ((immhi << 2) | immlo) << 12
        
        if (instr2 & 0xFFC003FF) == (0x91000000 | rd):  # ADD
            add_imm = (instr2 >> 10) & 0xFFF
            target = adr_page + add_imm
            if target == str_vm:
                vm = base_vm + i
                print('  MATCH: ADRP+ADD at VM 0x%x (fileoff 0x%x)' % (vm, i))
                found += 1
                if found >= 10:
                    break

if found == 0:
    print('  No matches found')
    # Try ADRP+LDR
    print('')
    print('=== Searching for ADRP+LDR ===')
    for i in range(0, len(data) - 8, 4):
        instr1 = struct.unpack('<I', data[i:i+4])[0]
        instr2 = struct.unpack('<I', data[i+4:i+8])[0]
        
        if (instr1 & 0x9F000000) == 0x90000000:
            rd = instr1 & 0x1F
            immlo = (instr1 >> 29) & 0x3
            immhi = (instr1 >> 5) & 0x7FFFF
            adr_page = ((immhi << 2) | immlo) << 12
            
            if (instr2 & 0xFFC003FF) == (0xF9400000 | rd):  # LDR
                ldr_off = ((instr2 >> 10) & 0xFFF) * 8
                target = adr_page + ldr_off
                if target == str_vm:
                    vm = base_vm + i
                    print('  MATCH: ADRP+LDR at VM 0x%x (fileoff 0x%x)' % (vm, i))
                    found += 1
                    if found >= 10:
                        break

if found == 0:
    print('  Still no matches')
