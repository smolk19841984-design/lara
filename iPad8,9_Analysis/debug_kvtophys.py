filepath = r'C:\Users\smolk\Documents\2\lara-main\jbdc\kexploit\darksword.m'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# Find the ds_kvtophys L1 lookup section and add debug logging
old_l1_lookup = (
    "    // L1 entry\n"
    "    uint64_t l1_tte = ds_kread64(l1_table_va + ARM64_L1_IDX(kva) * 8);\n"
    "\n"
    "    // Check if L1 is a block descriptor (1 TB block)"
)

new_l1_lookup = (
    "    // L1 entry\n"
    "    uint64_t l1_entry_addr = l1_table_va + ARM64_L1_IDX(kva) * 8;\n"
    "    uint64_t l1_tte = ds_kread64(l1_entry_addr);\n"
    "    pe_log(\"ds_kvtophys: L1 lookup: table_va=0x%llx idx=%d entry_addr=0x%llx l1_tte=0x%llx\",\n"
    "           l1_table_va, ARM64_L1_IDX(kva), l1_entry_addr, l1_tte);\n"
    "\n"
    "    // Check if L1 is a block descriptor (1 TB block)"
)

if old_l1_lookup in content:
    result = content.replace(old_l1_lookup, new_l1_lookup)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(result)
    print('Added L1 debug logging to ds_kvtophys')
else:
    print('ERROR: Pattern not found')
    idx = content.find('// L1 entry')
    if idx >= 0:
        print('Found at index', idx)
        print(repr(content[idx:idx+100]))
