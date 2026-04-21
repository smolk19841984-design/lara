import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# The string \"invalid XPRR index\" is at fileoff 0x4cd9f
# Let's find the function that uses this string by searching for ADRP+LDR or ADRP+ADD
# that references this string page

str_fileoff = 0x4cd9f

# Search for ADRP Xd, #page where page is close to str_fileoff
# ADRP encodes a 33-bit immediate: immhi (19 bits) : immlo (2 bits), shifted by 12
# The page in the instruction - это VM page, но мы ищем file offset

# Let's try a different approach: search for the function prologue near the string
# The string is in __LINKEDIT at fileoff 0x4cd9f
# Functions that reference this string will have ADRP+LDR or ADRP+ADD

# Search for ADRP with page close to 0x4c000
print('=== Searching for ADRP referencing string page 0x4c000 ===')
target_page = 0x4c000
target_off = 0xd9f

found = 0
for i in range(0, len(data) - 8, 4):
    instr1 = struct.unpack('<I', data[i:i+4])[0]
    instr2 = struct.unpack('<I', data[i+4:i+8])[0]
    
    if (instr1 & 0x9F000000) == 0x90000000:  # ADRP
        rd = instr1 & 0x1F
        immlo = (instr1 >> 29) & 0x3
        immhi = (instr1 >> 5) & 0x7FFFF
        adr_page = ((immhi << 2) | immlo) << 12
        
        # Check if this ADRP page matches our target
        if adr_page == target_page:
            if (instr2 & 0xFFC003FF) == (0x91000000 | rd):  # ADD
                add_imm = (instr2 >> 10) & 0xFFF
                if add_imm == target_off:
                    vm = base_vm + i
                    print('  MATCH: ADRP+ADD at VM 0x%x (fileoff 0x%x)' % (vm, i))
                    found += 1
                    if found >= 5:
                        break
            elif (instr2 & 0xFFC003FF) == (0xF9400000 | rd):  # LDR
                ldr_off = ((instr2 >> 10) & 0xFFF) * 8
                if adr_page + ldr_off == target_page + target_off:
                    vm = base_vm + i
                    print('  MATCH: ADRP+LDR at VM 0x%x (fileoff 0x%x)' % (vm, i))
                    found += 1
                    if found >= 5:
                        break

if found == 0:
    print('  No matches found')
    
    # Try broader: any ADRP+ADD/ADR+LDR within 0x1000 of string
    print('')
    print('=== Broader search: ADRP+ADD within 0x1000 of string ===')
    found = 0
    for i in range(0, len(data) - 8, 4):
        instr1 = struct.unpack('<I', data[i:i+4])[0]
        instr2 = struct.unpack('<I', data[i+4:i+8])[0]
        
        if (instr1 & 0x9F000000) == 0x90000000:
            rd = instr1 & 0x1F
            immlo = (instr1 >> 29) & 0x3
            immhi = (instr1 >> 5) & 0x7FFFF
            adr_page = ((immhi << 2) | immlo) << 12
            
            if (instr2 & 0xFFC003FF) == (0x91000000 | rd):
                add_imm = (instr2 >> 10) & 0xFFF
                target = adr_page + add_imm
                if abs(target - str_fileoff) < 0x1000:
                    vm = base_vm + i
                    print('  VM 0x%x (fileoff 0x%x) page=0x%x off=0x%x target=0x%x' % (vm, i, adr_page, add_imm, target))
                    found += 1
                    if found >= 10:
                        break
    
    if found == 0:
        print('  Still no matches')
