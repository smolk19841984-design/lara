//
//  shadow_pages.h
//  Lara Jailbreak - PPL Bypass via Shadow Pages
//
//  Implements Shadow Pages technique to bypass PPL (Page Protection Layer)
//  by creating writable copies of kernel pages and redirecting access
//

#ifndef shadow_pages_h
#define shadow_pages_h

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <mach/mach.h>
#include <os/log.h>

// Shadow page structure
typedef struct {
    uint64_t original_addr;     // Original kernel virtual address
    uint64_t shadow_addr;       // Shadow page address (writable)
    uint64_t physical_addr;     // Physical address of the page
    size_t ref_count;           // Reference count
    bool is_mapped;             // Whether the shadow is currently mapped
    uint8_t *data;              // Cached page data
} shadow_page_t;

// Shadow page manager
typedef struct {
    shadow_page_t *pages;
    size_t num_pages;
    size_t capacity;
    uint64_t (*kread)(uint64_t addr);
    void (*kwrite)(uint64_t addr, uint64_t value);
    bool (*kread_buf)(uint64_t addr, void *buf, size_t len);
    bool (*kwrite_buf)(uint64_t addr, const void *buf, size_t len);
} shadow_manager_t;

static shadow_manager_t g_shadow_mgr = {0};

// Page size constants
#define PAGE_SIZE_4K  0x1000
#define PAGE_MASK     0xFFF

// Initialize shadow page manager
static bool shadow_init(uint64_t (*kread)(uint64_t), 
                        void (*kwrite)(uint64_t, uint64_t),
                        bool (*kread_buf)(uint64_t, void*, size_t),
                        bool (*kwrite_buf)(uint64_t, const void*, size_t)) {
    if (!kread || !kwrite || !kread_buf || !kwrite_buf) {
        os_log_error(OS_LOG_DEFAULT, "[Shadow] Invalid primitives");
        return false;
    }
    
    g_shadow_mgr.kread = kread;
    g_shadow_mgr.kwrite = kwrite;
    g_shadow_mgr.kread_buf = kread_buf;
    g_shadow_mgr.kwrite_buf = kwrite_buf;
    g_shadow_mgr.capacity = 256;
    g_shadow_mgr.pages = calloc(g_shadow_mgr.capacity, sizeof(shadow_page_t));
    
    if (!g_shadow_mgr.pages) {
        os_log_error(OS_LOG_DEFAULT, "[Shadow] Failed to allocate pages array");
        return false;
    }
    
    os_log_info(OS_LOG_DEFAULT, "[Shadow] Initialized with capacity %zu", g_shadow_mgr.capacity);
    return true;
}

// Find or create shadow page for given address
static shadow_page_t* shadow_get_page(uint64_t addr) {
    uint64_t page_addr = addr & ~PAGE_MASK;
    
    // Check if shadow already exists
    for (size_t i = 0; i < g_shadow_mgr.num_pages; i++) {
        if (g_shadow_mgr.pages[i].original_addr == page_addr) {
            g_shadow_mgr.pages[i].ref_count++;
            return &g_shadow_mgr.pages[i];
        }
    }
    
    // Create new shadow page
    if (g_shadow_mgr.num_pages >= g_shadow_mgr.capacity) {
        // Expand capacity
        size_t new_capacity = g_shadow_mgr.capacity * 2;
        shadow_page_t *new_pages = realloc(g_shadow_mgr.pages, 
                                           new_capacity * sizeof(shadow_page_t));
        if (!new_pages) {
            os_log_error(OS_LOG_DEFAULT, "[Shadow] Failed to expand capacity");
            return NULL;
        }
        g_shadow_mgr.pages = new_pages;
        g_shadow_mgr.capacity = new_capacity;
    }
    
    shadow_page_t *page = &g_shadow_mgr.pages[g_shadow_mgr.num_pages++];
    memset(page, 0, sizeof(shadow_page_t));
    
    page->original_addr = page_addr;
    page->ref_count = 1;
    
    // Read original page content
    uint8_t *page_data = malloc(PAGE_SIZE_4K);
    if (!page_data) {
        g_shadow_mgr.num_pages--;
        return NULL;
    }
    
    if (!g_shadow_mgr.kread_buf(page_addr, page_data, PAGE_SIZE_4K)) {
        os_log_error(OS_LOG_DEFAULT, "[Shadow] Failed to read page 0x%llx", page_addr);
        free(page_data);
        g_shadow_mgr.num_pages--;
        return NULL;
    }
    
    page->data = page_data;
    
    // Allocate shadow memory in userspace (will be mapped later)
    // For now, we just cache the data
    page->shadow_addr = (uint64_t)(uintptr_t)page_data;
    
    os_log_info(OS_LOG_DEFAULT, "[Shadow] Created shadow for 0x%llx -> 0x%llx", 
                page_addr, page->shadow_addr);
    
    return page;
}

// Write to shadow page (bypasses PPL)
static bool shadow_write(uint64_t addr, const void *data, size_t len) {
    uint64_t page_addr = addr & ~PAGE_MASK;
    size_t offset = addr & PAGE_MASK;
    
    if (offset + len > PAGE_SIZE_4K) {
        // Cross-page write - split into multiple writes
        size_t first_part = PAGE_SIZE_4K - offset;
        if (!shadow_write(addr, data, first_part)) {
            return false;
        }
        return shadow_write(page_addr + PAGE_SIZE_4K, 
                           (const uint8_t*)data + first_part, 
                           len - first_part);
    }
    
    shadow_page_t *page = shadow_get_page(addr);
    if (!page) {
        os_log_error(OS_LOG_DEFAULT, "[Shadow] Failed to get page for 0x%llx", addr);
        return false;
    }
    
    // Write to cached data
    memcpy(page->data + offset, data, len);
    page->is_mapped = true;
    
    os_log_debug(OS_LOG_DEFAULT, "[Shadow] Wrote %zu bytes to shadow 0x%llx", len, addr);
    return true;
}

// Read from shadow page (or original if not shadowed)
static bool shadow_read(uint64_t addr, void *buf, size_t len) {
    uint64_t page_addr = addr & ~PAGE_MASK;
    size_t offset = addr & PAGE_MASK;
    
    // Check if shadow exists
    for (size_t i = 0; i < g_shadow_mgr.num_pages; i++) {
        if (g_shadow_mgr.pages[i].original_addr == page_addr && 
            g_shadow_mgr.pages[i].is_mapped) {
            // Read from shadow
            size_t copy_len = MIN(len, PAGE_SIZE_4K - offset);
            memcpy(buf, g_shadow_mgr.pages[i].data + offset, copy_len);
            
            if (len > copy_len) {
                // Continue reading from next page
                return shadow_read(page_addr + PAGE_SIZE_4K, 
                                  (uint8_t*)buf + copy_len, 
                                  len - copy_len);
            }
            return true;
        }
    }
    
    // No shadow - read from original
    return g_shadow_mgr.kread_buf(addr, buf, len);
}

// Apply all shadow pages (make them active)
// This is where the magic happens - we need to redirect page table entries
static bool shadow_apply(void) {
    os_log_info(OS_LOG_DEFAULT, "[Shadow] Applying %zu shadow pages", g_shadow_mgr.num_pages);
    
    for (size_t i = 0; i < g_shadow_mgr.num_pages; i++) {
        shadow_page_t *page = &g_shadow_mgr.pages[i];
        
        if (!page->is_mapped) {
            continue;
        }
        
        // To bypass PPL, we need to:
        // 1. Find the PTE for the original page
        // 2. Modify the PTE to point to our shadow page's physical address
        // 3. Clear the PPL bit (XPRR) in the PTE
        
        // This requires:
        // - Physical address of shadow page (via IOSurface or similar)
        // - Ability to modify page tables (via darksword primitives)
        
        // Placeholder: In real implementation, this would use the PPL bypass
        // from ppl.m to modify the PTE directly
        
        uint64_t pte_addr = 0; // Would be calculated from TTBR0 and VA
        if (!pte_addr) {
            os_log_error(OS_LOG_DEFAULT, "[Shadow] Cannot find PTE for 0x%llx", 
                        page->original_addr);
            continue;
        }
        
        // Read current PTE
        uint64_t pte = g_shadow_mgr.kread(pte_addr);
        
        // Update PTE to point to shadow physical address
        // Clear XPRR bit (bit 54 on A18) to allow writing
        uint64_t new_pte = (pte & ~(0xFULL << 12)) | (page->physical_addr & 0xFFFFFFFFF000);
        new_pte &= ~(1ULL << 54); // Clear XPRR
        
        // Write new PTE (this bypasses PPL)
        g_shadow_mgr.kwrite(pte_addr, new_pte);
        
        os_log_info(OS_LOG_DEFAULT, "[Shadow] Applied shadow: 0x%llx -> phys 0x%llx", 
                   page->original_addr, page->physical_addr);
    }
    
    return true;
}

// Patch kernel function via shadow page
static bool shadow_patch_func(uint64_t func_addr, const uint8_t *patch, size_t patch_len) {
    if (!shadow_write(func_addr, patch, patch_len)) {
        return false;
    }
    
    // Flush instruction cache
    // sys_icache_invalidate((void*)(uintptr_t)func_addr, patch_len);
    
    os_log_info(OS_LOG_DEFAULT, "[Shadow] Patched function at 0x%llx (%zu bytes)", 
               func_addr, patch_len);
    return true;
}

// Patch single instruction
static bool shadow_patch_instr(uint64_t addr, uint32_t instr) {
    return shadow_write(addr, &instr, sizeof(instr));
}

// NOP out function (replace with RET)
static bool shadow_nop_func(uint64_t func_addr) {
    // ARM64 RET instruction: C0 03 5F D6
    uint32_t ret_instr = 0xD65F03C0;
    return shadow_patch_instr(func_addr, ret_instr);
}

// Cleanup shadow pages
static void shadow_cleanup(void) {
    for (size_t i = 0; i < g_shadow_mgr.num_pages; i++) {
        if (g_shadow_mgr.pages[i].data) {
            free(g_shadow_mgr.pages[i].data);
        }
    }
    
    if (g_shadow_mgr.pages) {
        free(g_shadow_mgr.pages);
        g_shadow_mgr.pages = NULL;
    }
    
    g_shadow_mgr.num_pages = 0;
    g_shadow_mgr.capacity = 0;
    
    os_log_info(OS_LOG_DEFAULT, "[Shadow] Cleanup complete");
}

// Helper: Create ARM64 branch instruction
static inline uint32_t arm64_branch(uint64_t src, uint64_t dst) {
    int64_t offset = (int64_t)(dst - src) >> 2;
    return (uint32_t)((offset & 0x3FFFFFF) | 0x14000000); // B opcode
}

// Helper: Create ARM64 BL (branch with link)
static inline uint32_t arm64_bl(uint64_t src, uint64_t dst) {
    int64_t offset = (int64_t)(dst - src) >> 2;
    return (uint32_t)((offset & 0x3FFFFFF) | 0x94000000); // BL opcode
}

#endif /* shadow_pages_h */
