filepath = r'C:\Users\smolk\Documents\2\lara-main\jbdc\kexploit\darksword.m'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# Fix L1 masks
old_l1 = (
    "// L1 block: 1 TB (bits[47:36] = PA, bits[35:0] = offset)\n"
    "#define L1_BLOCK_PA_MASK      0x0000FFFF80000000ULL\n"
    "#define L1_BLOCK_OFFSET_MASK  0x000000007FFFFFFFULL"
)
new_l1 = (
    "// L1 block: 1 TB (bits[47:36] = PA, bits[35:0] = offset)\n"
    "#define L1_BLOCK_PA_MASK      0x0000FFF000000000ULL\n"
    "#define L1_BLOCK_OFFSET_MASK  0x0000000FFFFFFFFFULL"
)

# Fix L2 masks
old_l2 = (
    "// L2 block: 512 MB (bits[47:25] = PA, bits[24:0] = offset)\n"
    "#define L2_BLOCK_PA_MASK      0x0000FFFFFFE00000ULL\n"
    "#define L2_BLOCK_OFFSET_MASK  0x0000000001FFFFFULL"
)
new_l2 = (
    "// L2 block: 512 MB (bits[47:29] = PA, bits[28:0] = offset)\n"
    "#define L2_BLOCK_PA_MASK      0x0000FFFFE0000000ULL\n"
    "#define L2_BLOCK_OFFSET_MASK  0x000000001FFFFFFFULL"
)

content = content.replace(old_l1, new_l1)
content = content.replace(old_l2, new_l2)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)
print('Both L1 and L2 block masks fixed')
