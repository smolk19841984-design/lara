import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# Find the string location
target = b'pmap_set_pte_xprr_perm'
idx = data.find(target)
print('String \"pmap_set_pte_xprr_perm\" at fileoff 0x%x' % idx)

# The string is in __LINKEDIT. Find ADRP+ADD reference to it
# ADRP Xd, page; ADD Xd, Xd, #offset
# The page is at fileoff aligned to 0x1000
str_page = idx & ~0xFFF
str_off = idx & 0xFFF

print('String page: 0x%x, offset: 0x%x' % (str_page, str_off))

# Search for ADRP referencing this page
print('')
print('=== Searching for ADRP references to string page ===')
for i in range(0, len(data) - 8, 4):
    instr1 = struct.unpack('<I', data[i:i+4])[0]
    instr2 = struct.unpack('<I', data[i+4:i+8])[0]
    
    # ADRP Xd, #page
    if (instr1 & 0x9F000000) == 0x90000000:
        rd = instr1 & 0x1F
        immlo = (instr1 >> 29) & 0x3
        immhi = (instr1 >> 5) & 0x7FFFF
        imm = (immhi << 2 | immlo) << 12
        
        # Check if ADD follows with same rd
        if (instr2 & 0xFF8003FF) == (0x91000000 | rd):
            add_imm = (instr2 >> 10) & 0xFFF
            
            # The target address = page_base + add_imm
            # We need to check if this points to our string
            # In file terms: ADRP page + ADD offset should equal str_page + str_off
            # But ADRP uses VM addresses, not file offsets
            # Let's just check if the combined offset matches
            target_off = (i & ~0xFFF) + (imm & 0xFFFFFFFFFFFFF000) + add_imm
            # This is approximate - let's just print candidates near our string
            if abs(imm - str_page) < 0x10000 or abs(add_imm - str_off) < 0x100:
                vm = base_vm + i
                print('  ADRP+ADD at VM 0x%x (fileoff 0x%x): page=0x%x add_imm=0x%x' % (vm, i, imm, add_imm))

# Simpler approach: search for any ADRP near the string
print('')
print('=== Direct search: functions referencing the string ===')
# Read 256 bytes around each ADRP candidate and look for the pattern
found_refs = []
for i in range(0, len(data) - 4, 4):
    instr = struct.unpack('<I', data[i:i+4])[0]
    if (instr & 0x9F000000) == 0x90000000:
        rd = instr & 0x1F
        immlo = (instr >> 29) & 0x3
        immhi = (instr >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        
        # Check if this ADRP page is close to our string page
        if abs(imm - str_page) < 0x2000:
            # Check next instruction for ADD
            if i + 4 < len(data):
                instr2 = struct.unpack('<I', data[i+4:i+8])[0]
                if (instr2 & 0xFF8003FF) == (0x91000000 | rd):
                    add_imm = (instr2 >> 10) & 0xFFF
                    total = imm + add_imm
                    if abs(total - (str_page + str_off)) < 0x100:
                        vm = base_vm + i
                        found_refs.append((vm, i, imm, add_imm))

print('Found %d ADRP+ADD references to string' % len(found_refs))
for vm, fo, page, add in found_refs[:10]:
    print('  VM 0x%x (fileoff 0x%x) page=0x%x add=0x%x' % (vm, fo, page, add))
    
    # Disassemble 20 instructions before and after
    print('  Disassembly:')
    start = max(0, fo - 80)
    end = min(len(data), fo + 80)
    for j in range(start, end, 4):
        inst = struct.unpack('<I', data[j:j+4])[0]
        marker = '>>>' if j == fo else '   '
        print('    %s 0x%x: 0x%08x' % (marker, base_vm + j, inst))
    print('')
