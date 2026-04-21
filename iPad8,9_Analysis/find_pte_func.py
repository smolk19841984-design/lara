import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# pmap_set_pte_xprr_perm has:
# 1. ldxr xN, [x0]  - load exclusive
# 2. ubfx/bfi for XPRR bits
# 3. stxr/stlxr - store exclusive
# 4. cbnz/tbnz for retry loop

# Search for ldxr xN, [x0] pattern
print('=== Searching for ldxr/stxr patterns (pmap_set_pte_xprr_perm) ===')
found = 0
for i in range(0, len(data) - 24, 4):
    instr0 = struct.unpack('<I', data[i:i+4])[0]
    # ldxr xN, [x0] = 0x085F7C00 | (N << 16) | N
    # Actually: ldxr Xt, [Xn] = 000010 0 00 1 11111 Xn Rt
    # Mask: 0xFFE0FC00, value: 0x085F7C00
    if (instr0 & 0xFFE0FC00) == 0x085F7C00:
        rt = instr0 & 0x1F
        rn = (instr0 >> 5) & 0x1F
        if rn == 0:  # [x0]
            # Check next 16 instructions for stxr
            has_stxr = False
            has_cb = False
            for j in range(1, 16):
                off = i + j * 4
                if off + 4 > len(data):
                    break
                instr = struct.unpack('<I', data[off:off+4])[0]
                # stxr ws, wt, [xn]
                if (instr & 0xFFE0FC00) == 0x0800FC00:
                    has_stxr = True
                # cbnz/cbnz
                if (instr & 0x7F000000) in [0x35000000, 0x34000000]:
                    has_cb = True
            
            if has_stxr and has_cb:
                vm = base_vm + i
                print('  Found at VM 0x%x (fileoff 0x%x)' % (vm, i))
                found += 1
                if found >= 10:
                    break

if found == 0:
    print('  None found')

# Also search for the string reference more precisely
print('')
print('=== Finding exact string location ===')
target = b'_pmap_set_pte_xprr_perm\x00'
idx = data.find(target)
if idx >= 0:
    print('Found at fileoff 0x%x' % idx)
    # Show surrounding strings
    start = max(0, idx - 50)
    end = min(len(data), idx + 50)
    chunk = data[start:end]
    print('Context:')
    print(chunk)
else:
    # Try without leading underscore
    target = b'pmap_set_pte_xprr_perm\x00'
    idx = data.find(target)
    if idx >= 0:
        print('Found (no underscore) at fileoff 0x%x' % idx)
    else:
        print('String not found')
