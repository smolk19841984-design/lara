import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# Search for strings related to pmap_set_xprr_perm
strings_to_find = [
    b'sync_tlb_flush',
    b'flush_tlb_region',
    b'pmap_set_xprr',
    b'pmap_set_pte',
    b'physical aperture',
    b'static region PTE',
]

for s in strings_to_find:
    idx = data.find(s)
    if idx >= 0:
        print('Found \"%s\" at fileoff 0x%x' % (s.decode(), idx))
        # Show context
        start = max(0, idx - 30)
        end = min(len(data), idx + 80)
        chunk = data[start:end]
        print('  Context: %s' % repr(chunk))
        print('')
    else:
        print('Not found: \"%s\"' % s.decode())
        print('')
