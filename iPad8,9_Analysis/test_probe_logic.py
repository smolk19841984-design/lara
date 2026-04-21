import sys

def _rc_is_kptr(p):
    if p == 0 or p == 0xffffffffffffffff: return False
    if p >= 0xffffffff00000000 and p <= 0xffffffff0000ffff: return False
    return p >= 0xffffff0000000000

# Simulated memory
memory = {}

def kread64(addr):
    return memory.get(addr, 0)

def kwrite64(addr, val):
    memory[addr] = val

def setup_simulated_memory():
    thread_addr = 0xffffffe000100000
    task_addr   = 0xffffffe000200000
    proc_addr   = 0xffffffe000300000
    
    # True offsets for iOS 17.3.1 A12X
    true_tro = 0x368
    true_task_threads_next = 0x58
    true_thread_task_threads_next = true_tro - 0x10 # 0x358
    
    # Setup thread
    kwrite64(thread_addr + true_tro, 0xffffffe000400000) # thread_ro
    kwrite64(thread_addr + true_thread_task_threads_next, thread_addr + true_thread_task_threads_next) # points to itself (1 thread)
    
    # Setup thread_ro
    thread_ro = 0xffffffe000400000
    kwrite64(thread_ro + 0x10, proc_addr)
    kwrite64(thread_ro + 0x18, task_addr)
    
    # Setup task
    kwrite64(task_addr + true_task_threads_next, thread_addr + true_thread_task_threads_next)
    
    return thread_addr

def rc_probe_tro_offset(thread_addr):
    print(f"[*] Starting probe on thread 0x{thread_addr:x}")
    
    for off in range(0x338, 0x3F8 + 8, 8):
        val = kread64(thread_addr + off)
        if not _rc_is_kptr(val): continue
        
        ro_offsets = [
            (0x10, 0x18),
            (0x8, 0x10),
            (0x18, 0x20),
            (0x0, 0x8)
        ]
        
        found_valid = False
        
        for proc_off, task_off in ro_offsets:
            maybe_proc = kread64(val + proc_off)
            maybe_task = kread64(val + task_off)
            
            if _rc_is_kptr(maybe_proc) and _rc_is_kptr(maybe_task):
                thread_found = False
                best_task_threads_next = 0
                best_thread_task_threads_next = 0
                
                for ttn_off in range(0x40, 0x70 + 8, 8):
                    task_threads_next = kread64(maybe_task + ttn_off)
                    if not _rc_is_kptr(task_threads_next): continue
                    
                    chain = task_threads_next
                    found_in_chain = False
                    found_thread_ttn_off = 0
                    
                    for walk in range(16):
                        if not _rc_is_kptr(chain): break
                        if chain >= thread_addr and chain < thread_addr + 0x500:
                            found_in_chain = True
                            found_thread_ttn_off = chain - thread_addr
                            break
                        chain = kread64(chain)
                        
                    if found_in_chain:
                        thread_found = True
                        best_task_threads_next = ttn_off
                        best_thread_task_threads_next = found_thread_ttn_off
                        break
                        
                if thread_found:
                    print(f"[+] SUCCESS! Found valid offsets:")
                    print(f"    t_tro: 0x{off:x}")
                    print(f"    thread_ro->proc: 0x{proc_off:x}")
                    print(f"    thread_ro->task: 0x{task_off:x}")
                    print(f"    task->threads: 0x{best_task_threads_next:x}")
                    print(f"    thread->task_threads: 0x{best_thread_task_threads_next:x}")
                    return True
                    
    print("[-] Probe failed to find offsets")
    return False

if __name__ == "__main__":
    thread_addr = setup_simulated_memory()
    rc_probe_tro_offset(thread_addr)