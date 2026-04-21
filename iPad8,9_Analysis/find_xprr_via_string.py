import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# Find pmap_set_xprr_perm by searching for the function that:
# 1. Has prologue
# 2. Calls pmap_pte (BL)
# 3. Calls pmap_set_pte_xprr_perm (BL)
# 4. Has lsl x?, x0, #14 or similar

# First, let's find pmap_pte function
# Search for string reference
target = b'pmap_pte'
idx = data.find(target)
if idx >= 0:
    print('Found \"pmap_pte\" string at fileoff 0x%x' % idx)
else:
    print('pmap_pte string not found')

# Let's try a different approach: find the function by searching for the string
# \"invalid XPRR index\" which is used in pmap_set_pte_xprr_perm
target2 = b'invalid XPRR index'
idx2 = data.find(target2)
if idx2 >= 0:
    print('Found \"invalid XPRR index\" at fileoff 0x%x' % idx2)
    
    # This string is used in pmap_set_pte_xprr_perm
    # Find ADRP+ADD that references this string
    str_page = idx2 & ~0xFFF
    str_off = idx2 & 0xFFF
    
    # Search for ADRP+ADD near this string
    print('Searching for ADRP+ADD references...')
    for i in range(0, len(data) - 8, 4):
        instr1 = struct.unpack('<I', data[i:i+4])[0]
        # ADRP detection
        if (instr1 & 0x9F000000) == 0x90000000:
            rd = instr1 & 0x1F
            immlo = (instr1 >> 29) & 0x3
            immhi = (instr1 >> 5) & 0x7FFFF
            adr_page = ((immhi << 2) | immlo) << 12

            # check following instructions for ADD (imm) that uses same rd
            for j in range(1, 12):
                off = i + j * 4
                if off + 4 > len(data):
                    break
                instr2 = struct.unpack('<I', data[off:off+4])[0]
                # ADD (immediate) opcode has top byte 0x91
                if (instr2 & 0xFF000000) == 0x91000000:
                    rd2 = instr2 & 0x1F
                    rn2 = (instr2 >> 5) & 0x1F
                    add_imm = (instr2 >> 10) & 0xFFF
                    if rd2 == rd:
                        target = adr_page + add_imm
                        if target == idx2:
                            vm = base_vm + i
                            print('  ADRP+ADD at VM 0x%x (fileoff 0x%x) -> 0x%x' % (vm, i, target))
                            print('  Disassembly:')
                            start = max(0, i - 120)
                            end = min(len(data), i + 120)
                            for k in range(start, end, 4):
                                inst = struct.unpack('<I', data[k:k+4])[0]
                                marker = '>>>' if k == i else '   '
                                print('    %s 0x%x: 0x%08x' % (marker, base_vm + k, inst))
                            raise SystemExit
else:
    print('\"invalid XPRR index\" string not found')
