filepath = r'C:\Users\smolk\Documents\2\lara-main\jbdc\kexploit\darksword.m'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# After getting l1_table_va, add diagnostic reads of first few entries
old_l1_read = (
    "    // Retrieve the L1 table VA from pmap->tte (valid for kernel VA space).\n"
    "    uint64_t l1_table_va = ds_kread64(g_kernel_pmap + 0x00);\n"
    "\n"
    "    // L1 entry"
)

new_l1_read = (
    "    // Retrieve the L1 table VA from pmap->tte (valid for kernel VA space).\n"
    "    uint64_t l1_table_va = ds_kread64(g_kernel_pmap + 0x00);\n"
    "\n"
    "    // Diagnostic: read first 4 L1 entries to verify table is accessible\n"
    "    for (int di = 0; di < 4; di++) {\n"
    "        uint64_t diag_entry = ds_kread64(l1_table_va + di * 8);\n"
    "        pe_log(\"ds_kvtophys: L1[%d] @ 0x%llx = 0x%llx\", di, l1_table_va + di * 8, diag_entry);\n"
    "    }\n"
    "\n"
    "    // L1 entry"
)

if old_l1_read in content:
    result = content.replace(old_l1_read, new_l1_read)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(result)
    print('Added L1 table diagnostic logging')
else:
    print('ERROR: Pattern not found')
    idx = content.find('// Retrieve the L1 table VA')
    if idx >= 0:
        print('Found at index', idx)
        print(repr(content[idx:idx+100]))
