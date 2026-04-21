import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# Find the string
target = b'pmap_set_pte_xprr_perm'
str_idx = data.find(target)
print('String at fileoff 0x%x' % str_idx)

# Now search for ADRP that points to this string
# ADRP encodes: imm = immhi:immlo, target = PC & ~0xFFF + imm << 12
# We need to find ADRP where the page matches str_idx's page

str_page = str_idx & ~0xFFF
str_off = str_idx & 0xFFF

print('String page: 0x%x, offset: 0x%x' % (str_page, str_off))

# Search for ADRP Xd, #page where page is close to str_page
# But ADRP uses VM addresses, not file offsets
# The __LINKEDIT segment has a VM address. Let's find it.

# Search for ADRP in __TEXT_EXEC that references __LINKEDIT
# ADRP Xd, page; ADD Xd, Xd, #offset
# The page in VM terms: __LINKEDIT vmaddr + (str_page - __LINKEDIT fileoff)

# Let's find __LINKEDIT segment info
# Search for LC_SEGMENT_64 with segname __LINKEDIT
linkedit_vmaddr = 0
linkedit_fileoff = 0
linkedit_vmsize = 0

for i in range(0, len(data) - 0x48, 4):
    cmd = struct.unpack('<I', data[i:i+4])[0]
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = data[i+8:i+24]
        if b'__LINKEDIT' in segname:
            vmaddr = struct.unpack('<Q', data[i+48:i+56])[0]
            vmsize = struct.unpack('<Q', data[i+56:i+64])[0]
            fileoff = struct.unpack('<Q', data[i+64:i+72])[0]
            linkedit_vmaddr = vmaddr
            linkedit_fileoff = fileoff
            linkedit_vmsize = vmsize
            print('Found __LINKEDIT: vmaddr=0x%x fileoff=0x%x vmsize=0x%x' % (vmaddr, fileoff, vmsize))
            break

if linkedit_vmaddr:
    # String VM = linkedit_vmaddr + (str_idx - linkedit_fileoff)
    str_vm = linkedit_vmaddr + (str_idx - linkedit_fileoff)
    print('String VM: 0x%x' % str_vm)
    
    # Now search for ADRP+ADD that references this VM
    # ADRP Xd, page; ADD Xd, Xd, #offset
    # page = str_vm & ~0xFFF
    # offset = str_vm & 0xFFF
    target_page = str_vm & ~0xFFF
    target_off = str_vm & 0xFFF
    
    print('Target ADRP page: 0x%x, ADD offset: 0x%x' % (target_page, target_off))
    
    # Search for matching ADRP+ADD
    found = 0
    for i in range(0, len(data) - 8, 4):
        instr1 = struct.unpack('<I', data[i:i+4])[0]
        instr2 = struct.unpack('<I', data[i+4:i+8])[0]
        
        if (instr1 & 0x9F000000) == 0x90000000:  # ADRP
            rd = instr1 & 0x1F
            immlo = (instr1 >> 29) & 0x3
            immhi = (instr1 >> 5) & 0x7FFFF
            adr_page = ((immhi << 2) | immlo) << 12
            
            if (instr2 & 0xFF8003FF) == (0x91000000 | rd):  # ADD
                add_imm = (instr2 >> 10) & 0xFFF
                
                # Check if this matches our target
                if adr_page == target_page and add_imm == target_off:
                    vm = base_vm + i
                    print('  MATCH: ADRP+ADD at VM 0x%x (fileoff 0x%x)' % (vm, i))
                    found += 1
                    if found >= 5:
                        break
    
    if found == 0:
        print('No direct ADRP+ADD match found')
        # Try broader search - any ADRP+ADD near the string VM
        print('')
        print('=== Broader search: ADRP+ADD within 0x100 of string VM ===')
        for i in range(0, len(data) - 8, 4):
            instr1 = struct.unpack('<I', data[i:i+4])[0]
            instr2 = struct.unpack('<I', data[i+4:i+8])[0]
            
            if (instr1 & 0x9F000000) == 0x90000000:
                rd = instr1 & 0x1F
                immlo = (instr1 >> 29) & 0x3
                immhi = (instr1 >> 5) & 0x7FFFF
                adr_page = ((immhi << 2) | immlo) << 12
                
                if (instr2 & 0xFF8003FF) == (0x91000000 | rd):
                    add_imm = (instr2 >> 10) & 0xFFF
                    target = adr_page + add_imm
                    if abs(target - str_vm) < 0x100:
                        vm = base_vm + i
                        print('  VM 0x%x (fileoff 0x%x) page=0x%x off=0x%x target=0x%x' % (vm, i, adr_page, add_imm, target))
                        found += 1
                        if found >= 5:
                            break
        
        if found == 0:
            print('  Still no matches')
