import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# Find pmap_pte function - it computes PTE address from pmap + VA
# Search for the string reference
target = b'pmap_pte'
idx = data.find(target)
if idx >= 0:
    print('Found \"pmap_pte\" at fileoff 0x%x' % idx)
    # Show surrounding strings
    start = max(0, idx - 50)
    end = min(len(data), idx + 50)
    chunk = data[start:end]
    print('Context: %s' % repr(chunk))
else:
    print('pmap_pte string not found')

# Also search for pmap_tte or pmap_enter
print('')
print('=== Searching for pmap-related strings ===')
for s in [b'pmap_tte', b'pmap_enter', b'pmap_remove', b'pmap_protect', b'pmap_nest', b'pmap_expand']:
    idx = data.find(s)
    if idx >= 0:
        print('Found \"%s\" at fileoff 0x%x' % (s.decode(), idx))

# Search for the actual pmap_pte function by pattern
# pmap_pte(pmap, va) returns PTE pointer
# Pattern: lsr xN, x1, #14; ...; ldr xM, [x0, #offset]
print('')
print('=== Searching for pmap_pte pattern ===')
# Look for: ldr xN, [x0, #pmap_tte] ; lsr xM, x1, #14
# Or: lsr xN, x1, #14 ; lsl xN, xN, #3
found = 0
for i in range(0, len(data) - 12, 4):
    instr1 = struct.unpack('<I', data[i:i+4])[0]
    instr2 = struct.unpack('<I', data[i+4:i+8])[0]
    
    # lsr xN, x1, #14 = ubfm xN, x1, #14, #63
    # = 0xD39E0000 | (1 << 5) | N = 0xD39E0020 | N
    if (instr1 & 0xFFFFFFE0) == 0xD39E0020:
        # Check for lsl xN, xN, #3 in next 4 instructions
        for j in range(1, 5):
            off = i + j * 4
            if off + 4 > len(data):
                break
            instr = struct.unpack('<I', data[off:off+4])[0]
            # lsl xN, xN, #3 = ubfm xN, xN, #61, #60
            # = 0xD3F60000 | (N << 5) | N
            rt = instr1 & 0x1F
            if (instr & 0xFFFFFFE0) == (0xD3F60000 | rt):
                vm = base_vm + i
                print('  Found at VM 0x%x (fileoff 0x%x)' % (vm, i))
                found += 1
                if found >= 5:
                    break
    if found >= 5:
        break

if found == 0:
    print('  None found')
