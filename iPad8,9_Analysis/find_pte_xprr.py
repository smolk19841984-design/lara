import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# Check if ds_kvtopte returns PTE address that we can write to
# The PTE is in the page table, which may or may not be PPL-protected

# Let's also search for pmap_set_pte_xprr_perm which is called by pmap_set_xprr_perm
# This function directly modifies the PTE XPRR bits
print('=== Searching for pmap_set_pte_xprr_perm ===')
# Pattern: stxr or stlxr to modify PTE, or str to write XPRR bits
# Look for: function that writes to bits [59:57] of a 64-bit value

# Search for the string reference first
target_str = b'_pmap_set_pte_xprr_perm'
idx = data.find(target_str)
if idx >= 0:
    print('Found string at fileoff 0x%x' % idx)
else:
    print('String not found in binary')

# Also search for pmap_set_pte_xprr_perm variations
for variant in [b'pmap_set_pte_xprr', b'pmap_set_xprr', b'xprr_perm']:
    idx = data.find(variant)
    if idx >= 0:
        print('Found \"%s\" at fileoff 0x%x' % (variant.decode(), idx))

# Search for the actual function code pattern
# pmap_set_pte_xprr_perm(ptep, expected_perm, new_perm):
#   - loads PTE value
#   - extracts XPRR bits
#   - compares with expected
#   - stores new value
# Pattern: ldr xN, [x0]; ubfx/ubfiz for XPRR bits; cmp; stxr/stlxr
print('')
print('=== Searching for PTE XPRR modification pattern ===')
# Look for: ubfx xN, xM, #57, #3 (extract XPRR bits from PTE)
# ubfx xN, xM, #57, #3 = 10011011 011 M 000000 N
# Actually: 11011 01 110 imm3 100000 Rn Rd
# ubfx xN, xM, #57, #3: 0xD37B0000 | (M << 5) | N
# Mask: 0xFFE0FC00, value: 0x93400000
found = 0
for i in range(0, len(data) - 4, 4):
    instr = struct.unpack('<I', data[i:i+4])[0]
    # ubfx xN, xM, #57, #3
    if (instr & 0xFFE0FC00) == 0x93400000:
        ls = (instr >> 16) & 0x3F  # lsb
        width = (instr >> 10) & 0x3F  # width
        if ls == 57 and width == 3:
            vm = base_vm + i
            print('  Found ubfx x?, x?, #57, #3 at VM 0x%x (fileoff 0x%x)' % (vm, i))
            found += 1
            if found >= 10:
                break

if found == 0:
    print('  No ubfx #57,#3 found')

# Also search for bfi/bfiz to insert XPRR bits
print('')
print('=== Searching for BFI to insert XPRR bits ===')
found = 0
for i in range(0, len(data) - 4, 4):
    instr = struct.unpack('<I', data[i:i+4])[0]
    # bfi xN, xM, #57, #3
    # BFI (shifted register): 00111010 00 lsb 100000 Rn Rd
    # Actually BFI is: 0x3A000000 | (lsb << 16) | (Rn << 5) | Rd
    # But we need to check the actual encoding
    # bfi xN, xM, #57, #3: mask 0xFFE0FC00, check lsb=57, width=3
    if (instr & 0xFFE0FC00) == 0x3A000000:
        ls = (instr >> 16) & 0x3F
        if ls == 57:
            vm = base_vm + i
            print('  Found bfi at VM 0x%x (fileoff 0x%x)' % (vm, i))
            found += 1
            if found >= 10:
                break

if found == 0:
    print('  No bfi #57 found')
