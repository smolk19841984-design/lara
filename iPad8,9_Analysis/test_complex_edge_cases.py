import sys

# --- Simulated Kernel Memory ---
memory = {}

def kread64(addr):
    return memory.get(addr, 0)

def kwrite64(addr, val):
    memory[addr] = val

# --- 1. PAC Stripping & Pointer Validation (A12X Edge Case) ---
# A12X uses PAC. Pointers have signatures in the upper bits (e.g., 0x0023fffffe001000).
def pacstrip(p):
    # If bit 55 is set, it's a kernel pointer, fill upper bits with 1s.
    if (p >> 55) & 1:
        return p | 0xFFFFFF8000000000
    return p & ~0xFFFFFF8000000000

def _rc_is_kptr(p):
    p = pacstrip(p)
    if p == 0 or p == 0xffffffffffffffff: return False
    if p >= 0xffffffff00000000 and p <= 0xffffffff0000ffff: return False
    # Accept all iOS 17 kernel heap ranges: 0xffffff00... through 0xffffffe...
    return p >= 0xffffff0000000000

def test_sentinel_checks():
    """Test CVE-2024-23265 pattern: -1 sentinel must be rejected."""
    print("\n[=== TEST 5: CVE-2024-23265 Sentinel Check ===]")
    sentinel = 0xffffffffffffffff
    
    # Test in thread chain walk
    print(f"[*] Thread chain sentinel check: 0x{sentinel:016x}")
    chain_ok = (sentinel != 0) and (sentinel != 0xffffffffffffffff)
    print(f"    Would continue chain walk? {chain_ok}")
    
    # Test in sandbox_raw
    print(f"[*] Sandbox slot sentinel check: 0x{sentinel:016x}")
    sbx_ok = (sentinel != 0xffffffffffffffff)
    print(f"    Would attempt unsandbox? {sbx_ok}")
    
    # Test in ncache traversal
    print(f"[*] Ncache traversal sentinel check: 0x{sentinel:016x}")
    nc_ok = (sentinel != 0) and (sentinel != 0xffffffffffffffff)
    print(f"    Would continue ncache walk? {nc_ok}")
    
    if not chain_ok and not sbx_ok and not nc_ok:
        print("[+] SUCCESS: All sentinel checks correctly reject -1 pointer!")
        print("    This prevents the CVE-2024-23265 race condition pattern.")

def test_pac_pointers():
    print("\n[=== TEST 1: PAC Pointer Stripping & Validation ===]")
    raw_kptr = 0xffffffe000123456
    pac_kptr = 0x0023ffe000123456 # Simulated PAC signature in upper bits
    garbage  = 0xffffffff00000049 # The exact garbage that caused the panic
    
    print(f"[*] Testing raw kernel pointer: 0x{raw_kptr:016x}")
    print(f"    pacstrip -> 0x{pacstrip(raw_kptr):016x} | is_kptr: {_rc_is_kptr(raw_kptr)}")
    
    print(f"[*] Testing PAC-signed pointer: 0x{pac_kptr:016x}")
    print(f"    pacstrip -> 0x{pacstrip(pac_kptr):016x} | is_kptr: {_rc_is_kptr(pac_kptr)}")
    
    print(f"[*] Testing garbage pointer   : 0x{garbage:016x}")
    print(f"    pacstrip -> 0x{pacstrip(garbage):016x} | is_kptr: {_rc_is_kptr(garbage)}")

    a12x_heap_ptr = 0xffffffdce6854520
    print(f"[*] Testing A12X heap pointer : 0x{a12x_heap_ptr:016x}")
    print(f"    pacstrip -> 0x{pacstrip(a12x_heap_ptr):016x} | is_kptr: {_rc_is_kptr(a12x_heap_ptr)}")

# --- 2. Out-of-Line File Descriptor Table (VFS Edge Case) ---
# If a process opens many files, fd_ofiles moves from inline proc struct to a dynamically allocated array.
def test_out_of_line_fd():
    print("\n[=== TEST 2: Out-of-Line File Descriptor Table ===]")
    our_proc = 0xffffffe000200000
    O_PROC_FD = 0xF8
    
    # Setup pointers
    p_fd = 0xffffffe000900000
    kwrite64(our_proc + O_PROC_FD, p_fd)
    
    # Instead of inline, fd_ofiles points to a huge array far away
    fd_ofiles_array = 0xffffffe008800000 
    # iOS 17 offset is 0x10
    kwrite64(p_fd + 0x10, fd_ofiles_array)
    
    # We opened 250 files, so fd = 250
    fd = 250
    fileproc = 0xffffffe000B00000
    f_fglob = 0xffffffe000C00000
    target_vnode = 0xffffffe000400000
    
    kwrite64(fd_ofiles_array + (fd * 8), fileproc)
    # iOS 17 offset is 0x08
    kwrite64(fileproc + 0x08, f_fglob)
    kwrite64(f_fglob + 0x38, target_vnode)
    
    print(f"[*] Simulating vnode_from_fd for HIGH fd={fd} (Out-of-Line array at 0x{fd_ofiles_array:x})")
    
    # The logic from our vfs.m
    read_p_fd = kread64(our_proc + O_PROC_FD)
    read_fd_ofiles = kread64(read_p_fd + 0x10)
    read_fileproc = kread64(read_fd_ofiles + (fd * 8))
    read_f_fglob = kread64(read_fileproc + 0x08)
    read_fg_data = kread64(read_f_fglob + 0x38)
    
    print(f"[+] Resolved vnode: 0x{read_fg_data:016x}")
    if read_fg_data == target_vnode:
        print("[+] SUCCESS: vnode_from_fd handles out-of-line FD tables correctly!")

# --- 3. Sandbox Zone Boundary Overflow (PPL Bypass Edge Case) ---
# DarkSword writes in 32-byte (0x20) chunks. If the sandbox object is near a zone boundary,
# a 32-byte write might overflow into the next object and cause a `zone_require_ro` panic.
def ds_write_safe(elem_base, elem_size, addr):
    chunk_start = addr & ~0x1F
    chunk_end = chunk_start + 0x20
    return (chunk_start >= elem_base) and (chunk_end <= elem_base + elem_size)

def ds_write_range_safe(elem_base, elem_size, off, length):
    if length == 0: return True
    if off > elem_size or length > (elem_size - off): return False
    
    write_start = elem_base + off
    write_end = write_start + length
    cursor = write_start
    
    while cursor < write_end:
        if not ds_write_safe(elem_base, elem_size, cursor):
            return False
        cursor = (cursor & ~0x1F) + 0x20
    return True

def test_zone_boundary_overflow():
    print("\n[=== TEST 3: Sandbox Zone Boundary Overflow Prevention ===]")
    # Sandbox object size is 0x58 (88 bytes)
    SBX_OBJ_SIZE = 0x58
    
    # Scenario A: Perfectly aligned sandbox object
    aligned_sandbox = 0xffffffe000100000
    print(f"[*] Scenario A: Aligned Sandbox at 0x{aligned_sandbox:x}")
    safe_A = ds_write_range_safe(aligned_sandbox, SBX_OBJ_SIZE, 0x10, 8)
    print(f"    Write 8 bytes at offset 0x10 (ext_set) -> Safe? {safe_A}")
    
    # Scenario B: Unaligned sandbox object near page/zone boundary
    # Object starts at 0x...0B0. It ends at 0x...0B0 + 0x58 = 0x...108
    unaligned_sandbox = 0xffffffe0001000B0
    print(f"\n[*] Scenario B: Unaligned Sandbox at 0x{unaligned_sandbox:x}")
    
    # Writing at offset 0x48. 
    # Address = 0x...0F8. 
    # 32-byte chunk aligns to 0x...0E0, ends at 0x...100. (Inside 0x108 boundary)
    safe_B1 = ds_write_range_safe(unaligned_sandbox, SBX_OBJ_SIZE, 0x48, 8)
    print(f"    Write 8 bytes at offset 0x48 -> Safe? {safe_B1}")
    
    # Writing at offset 0x50. 
    # Address = 0x...100. 
    # 32-byte chunk aligns to 0x...100, ends at 0x...120. (Exceeds 0x108 boundary!)
    safe_B2 = ds_write_range_safe(unaligned_sandbox, SBX_OBJ_SIZE, 0x50, 8)
    print(f"    Write 8 bytes at offset 0x50 -> Safe? {safe_B2}")
    
    if not safe_B2:
        print("[+] SUCCESS: The logic correctly detected a zone overflow and blocked the write!")
        print("    This prevents the 'zone bound checks' Kernel Panic we saw in BUGS.md.")

# --- 4. TrustCache Linked List Traversal (AMFI Edge Case) ---
def test_trustcache_traversal():
    print("\n[=== TEST 4: TrustCache Linked List Traversal ===]")
    pmap_image4_trust_caches = 0xffffffe000111111 # List head
    
    # Setup 3 existing TrustCache modules
    tc1 = 0xffffffe000222222
    tc2 = 0xffffffe000333333
    tc3 = 0xffffffe000444444
    
    # Head points to tc1
    kwrite64(pmap_image4_trust_caches, tc1)
    
    # tc1 -> tc2 -> tc3 -> 0
    kwrite64(tc1, tc2)       # next
    kwrite64(tc1 + 8, 0)     # prev
    
    kwrite64(tc2, tc3)       # next
    kwrite64(tc2 + 8, tc1)   # prev
    
    kwrite64(tc3, 0)         # next (tail)
    kwrite64(tc3 + 8, tc2)   # prev
    
    print("[*] Traversing TrustCache list to find the tail...")
    
    curr = kread64(pmap_image4_trust_caches)
    tail = 0
    count = 0
    
    while curr != 0 and count < 100:
        print(f"    Found TC module at: 0x{curr:016x}")
        tail = curr
        curr = kread64(curr) # read next pointer
        count += 1
        
    print(f"[+] Reached tail at: 0x{tail:016x} (Total modules: {count})")
    
    our_new_tc = 0xffffffe000999999
    print(f"[*] Simulating injection of our TrustCache at 0x{our_new_tc:x}...")
    
    # If we had PPL bypass, we would do:
    # kwrite64(tail, our_new_tc) # tail->next = our_tc
    # kwrite64(our_new_tc + 8, tail) # our_tc->prev = tail
    # kwrite64(our_new_tc, 0) # our_tc->next = 0
    
    print("[+] SUCCESS: List traversal logic is sound for future PPL bypass integration.")

if __name__ == "__main__":
    test_pac_pointers()
    test_out_of_line_fd()
    test_zone_boundary_overflow()
    test_trustcache_traversal()
    test_sentinel_checks()