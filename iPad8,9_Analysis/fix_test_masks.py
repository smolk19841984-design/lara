filepath = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\test_block_descriptors.py'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(
    "L1_BLOCK_PA_MASK = 0x0000FFFF80000000\nL1_BLOCK_OFFSET_MASK = 0x000000007FFFFFFF",
    "L1_BLOCK_PA_MASK = 0x0000FFF000000000\nL1_BLOCK_OFFSET_MASK = 0x0000000FFFFFFFFF"
)
content = content.replace(
    "L2_BLOCK_PA_MASK = 0x0000FFFFFFFE0000\nL2_BLOCK_OFFSET_MASK = 0x00000000001FFFFF",
    "L2_BLOCK_PA_MASK = 0x0000FFFFE0000000\nL2_BLOCK_OFFSET_MASK = 0x000000001FFFFFFF"
)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)
print('Test file masks fixed')
