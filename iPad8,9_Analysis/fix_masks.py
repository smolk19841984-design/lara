filepath = r'C:\Users\smolk\Documents\2\lara-main\jbdc\kexploit\darksword.m'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

old_l2 = (
    "// L2 block: 512 MB (bits[47:25] = PA, bits[24:0] = offset)\n"
    "#define L2_BLOCK_PA_MASK      0x0000FFFFFFFE0000ULL\n"
    "#define L2_BLOCK_OFFSET_MASK  0x00000000001FFFFFULL"
)

new_l2 = (
    "// L2 block: 512 MB (bits[47:25] = PA, bits[24:0] = offset)\n"
    "#define L2_BLOCK_PA_MASK      0x0000FFFFFFE00000ULL\n"
    "#define L2_BLOCK_OFFSET_MASK  0x0000000001FFFFFULL"
)

if old_l2 in content:
    result = content.replace(old_l2, new_l2)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(result)
    print('L2 block masks fixed')
else:
    print('ERROR: Pattern not found')
    idx = content.find('L2_BLOCK_PA_MASK')
    if idx >= 0:
        print('Found at index', idx)
        print(repr(content[idx:idx+100]))
