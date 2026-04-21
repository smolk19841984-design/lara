import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# Find pmap_pte string
target = b'pmap_pte'
idx = data.find(target)
if idx >= 0:
    print('Found \"%s\" at fileoff 0x%x' % (target.decode(), idx))
else:
    print('String not found')

# Find pmap_set_xprr_perm string
target2 = b'pmap_set_xprr_perm'
idx2 = data.find(target2)
if idx2 >= 0:
    print('Found \"%s\" at fileoff 0x%x' % (target2.decode(), idx2))
else:
    print('String not found')

# Find pmap_in_ppl string
target3 = b'pmap_in_ppl'
idx3 = data.find(target3)
if idx3 >= 0:
    print('Found \"%s\" at fileoff 0x%x' % (target3.decode(), idx3))
else:
    print('String not found')

# Find all pmap-related strings
print('')
print('=== All pmap_xprr strings ===')
for target in [b'pmap_set_xprr', b'pmap_in_ppl', b'pmap_claim_reserved', b'pmap_free_reserved', b'xprr', b'XPRR']:
    idx = data.find(target)
    if idx >= 0:
        # Show context
        start = max(0, idx - 20)
        end = min(len(data), idx + 100)
        chunk = data[start:end]
        print('Found \"%s\" at 0x%x: %s' % (target.decode(), idx, repr(chunk)))
