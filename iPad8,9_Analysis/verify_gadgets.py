import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

# Verify the gadgets I found by disassembling surrounding instructions
gadgets_to_verify = [
    ('ldp x0, x1, [sp], #16', 0xd4d6dc),
    ('ldp x2, x3, [sp], #16', 0xd4f08c),
    ('ldr x8, [sp]', 0xd6242c),
    ('blr x8', 0x333cb64),
]

for name, fileoff in gadgets_to_verify:
    print('=== ' + name + ' at fileoff 0x%x ===' % fileoff)
    # Read 64 bytes around the gadget (16 instructions)
    for i in range(-4, 12):
        off = fileoff + i * 4
        if off < 0 or off + 4 > len(data):
            continue
        instr = struct.unpack('<I', data[off:off+4])[0]
        marker = '>>>' if i == 0 else '   '
        print('  %s 0x%x: 0x%08x' % (marker, off, instr))
    print('')
