//
//  KernelPrimitiveGuard.h
//  lara
//
//  Created to protect kernel read/write primitives from premature socket closure
//

#ifndef KernelPrimitiveGuard_h
#define KernelPrimitiveGuard_h

#include <stdint.h>
#include <stdbool.h>

// Initialize the guard with socket file descriptors
void kpg_init(int control_fd, int rw_fd, uint64_t control_pcb, uint64_t rw_pcb);

// Check if sockets are still valid before each kernel access
bool kpg_verify_sockets(void);

// Protect sockets from being closed by incrementing so_count
void kpg_protect_sockets(uint64_t kernel_base, uint64_t so_count_offset);

// Restore original so_count values (for cleanup)
void kpg_restore_sockets(uint64_t kernel_base, uint64_t so_count_offset);

// Get protected control socket fd (reopens if needed)
int kpg_get_control_socket(void);

// Get protected rw socket fd (reopens if needed)
int kpg_get_rw_socket(void);

// Log current socket state
void kpg_log_state(void);

// Mark primitives as ready/unready
void kpg_set_ready(bool ready);
bool kpg_is_ready(void);

#endif /* KernelPrimitiveGuard_h */
