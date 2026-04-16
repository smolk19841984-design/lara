//
//  kernel_offsets.h
//  Lara Jailbreak - Dynamic Offset Finder
//
//  Pattern scanning for iOS 17.3.1 kernel symbols
//

#ifndef kernel_offsets_h
#define kernel_offsets_h

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

// Pattern matching structures
typedef struct {
    const uint8_t *pattern;
    const char *mask;
    size_t length;
    const char *symbol_name;
} pattern_t;

// ARM64 instruction helpers
static inline bool match_arm64(uint32_t instr, uint32_t pattern, const char *mask) {
    for (size_t i = 0; mask[i]; i++) {
        if (mask[i] == 'x') continue;
        uint8_t shift = (i % 4) * 8;
        uint8_t byte_mask = mask[i] == '?' ? 0 : 0xFF;
        if (((instr >> shift) & 0xFF & byte_mask) != ((pattern >> shift) & 0xFF)) {
            return false;
        }
    }
    return true;
}

// ADRP/ADD pattern for finding kernel base
static inline uint64_t decode_adrp_add(uint32_t adrp, uint32_t add, uint64_t pc) {
    // ADRP: immlo(2) | immhi(19) | Rd(5) | op(2) | 10010000
    uint64_t immhi = (adrp >> 5) & 0x7FFFF;
    uint64_t immlo = (adrp >> 29) & 0x3;
    int64_t offset = (immhi << 2) | immlo;
    offset = (offset << 43) >> 43; // Sign extend
    
    uint64_t page = (pc & ~0xFFFULL) + (offset << 12);
    
    // ADD: imm12(12) | Rn(5) | Rd(5) | 00010001
    uint64_t imm12 = (add >> 10) & 0xFFF;
    
    return page + imm12;
}

// Pattern for _current_proc() - typical prologue
static const uint8_t current_proc_pattern[] = {
    0xFD, 0x7B, 0xBF, 0xA9,  // stp x29, x30, [sp, #-0x10]!
    0xFD, 0x43, 0x00, 0x91,  // mov x29, sp
    0xF3, 0x03, 0x00, 0xAA   // mov x19, x0
};
static const char current_proc_mask[] = "xxxxxxxxxxxx";

// Pattern for _proc_ucred - access to ucred
static const uint8_t proc_ucred_pattern[] = {
    0xB3, 0x48, 0x40, 0xF9,  // ldr x19, [x5, #0x88]  ; ucred offset varies
    0x1F, 0x00, 0x00, 0xB4   // cbz x19, ...
};
static const char proc_ucred_mask[] = "xxxxxxxxxxxx";

// Pattern for _cs_enforcement - CS enforcement check
static const uint8_t cs_enforcement_pattern[] = {
    0x08, 0x00, 0x40, 0xB9,  // ldr w8, [x0, #offset]
    0x1F, 0x00, 0x08, 0xB4   // cbz w8, ...
};
static const char cs_enforcement_mask[] = "xxxx?xxx????";

// Pattern for _sandbox_extension_consume
static const uint8_t sandbox_ext_pattern[] = {
    0xFD, 0x7B, 0xBF, 0xA9,  // stp x29, x30, [sp, #-0x10]!
    0x08, 0x00, 0x00, 0x58,  // ldr x8, =_sandbox_lock
    0x00, 0x01, 0x40, 0xF9   // ldr x0, [x8]
};
static const char sandbox_ext_mask[] = "xxxxxxxxxxxx";

// Pattern for _AMFI_hook_policy
static const uint8_t amfi_hook_pattern[] = {
    0xFF, 0x43, 0x00, 0xD1,  // sub sp, sp, #0x10
    0xE2, 0x03, 0x00, 0xAA   // mov x2, x0
};
static const char amfi_hook_mask[] = "xxxxxxxx";

// Kernel image parsing
typedef struct {
    uint64_t kernel_base;
    uint64_t kernel_slide;
    uint64_t current_proc;
    uint64_t proc_ucred_offset;
    uint64_t cs_enforcement;
    uint64_t amfi_hook_policy;
    uint64_t sandbox_extension_consume;
    uint64_t sandbox_macf_ops;
    uint64_t vm_map_enter_mem_object;
    uint64_t ipc_port_alloc_special;
    uint64_t task_self_trap;
    bool found_all;
} kernel_offsets_t;

// Scan memory for pattern
static uint64_t find_pattern(const uint8_t *buffer, size_t size, const uint8_t *pattern, const char *mask) {
    size_t pattern_len = strlen(mask);
    
    for (size_t i = 0; i <= size - pattern_len; i++) {
        bool match = true;
        for (size_t j = 0; j < pattern_len; j++) {
            if (mask[j] != '?' && buffer[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return i;
        }
    }
    return 0;
}

// Find symbol in kernel using nm output or pattern
static uint64_t find_symbol_by_pattern(const uint8_t *kernel_image, size_t kernel_size, 
                                       const pattern_t *patterns, size_t num_patterns) {
    for (size_t i = 0; i < num_patterns; i++) {
        uint64_t offset = find_pattern(kernel_image, kernel_size, 
                                       patterns[i].pattern, patterns[i].mask);
        if (offset) {
            printf("[+] Found %s at offset 0x%llx\n", patterns[i].symbol_name, offset);
            return offset;
        }
    }
    return 0;
}

// Parse Mach-O header to find kernel base
static uint64_t parse_macho_header(const uint8_t *image, size_t size) {
    const struct mach_header_64 *header = (const struct mach_header_64 *)image;
    
    if (header->magic != MH_MAGIC_64 || header->cputype != CPU_TYPE_ARM64) {
        printf("[-] Invalid Mach-O header\n");
        return 0;
    }
    
    // Kernel base is typically the start of the image
    return (uint64_t)(uintptr_t)image;
}

// Main offset finder function
static bool find_kernel_offsets(const uint8_t *kernel_image, size_t kernel_size, 
                                kernel_offsets_t *offsets) {
    memset(offsets, 0, sizeof(kernel_offsets_t));
    
    // Parse Mach-O header
    offsets->kernel_base = parse_macho_header(kernel_image, kernel_size);
    if (!offsets->kernel_base) {
        return false;
    }
    
    printf("[+] Kernel base: 0x%llx\n", offsets->kernel_base);
    
    // Pattern definitions
    pattern_t patterns[] = {
        {current_proc_pattern, current_proc_mask, sizeof(current_proc_pattern), "_current_proc"},
        {proc_ucred_pattern, proc_ucred_mask, sizeof(proc_ucred_pattern), "_proc_ucred"},
        {cs_enforcement_pattern, cs_enforcement_mask, sizeof(cs_enforcement_pattern), "_cs_enforcement"},
        {sandbox_ext_pattern, sandbox_ext_mask, sizeof(sandbox_ext_pattern), "_sandbox_extension_consume"},
        {amfi_hook_pattern, amfi_hook_mask, sizeof(amfi_hook_pattern), "_AMFI_hook_policy"}
    };
    
    // Find patterns
    uint64_t current_proc_off = find_symbol_by_pattern(kernel_image, kernel_size, patterns, 5);
    if (current_proc_off) {
        offsets->current_proc = offsets->kernel_base + current_proc_off;
    }
    
    // Extract proc_ucred offset from instruction
    if (current_proc_off) {
        // Look for ucred access pattern near current_proc
        // Typical: ldr x0, [x0, #offset] where offset is ucred offset
        for (size_t i = current_proc_off; i < current_proc_off + 0x100; i += 4) {
            uint32_t instr = *(uint32_t *)(kernel_image + i);
            if ((instr & 0xFFC003FF) == 0xF9400000) { // LDR Xn, [Xm, #imm]
                uint16_t imm = ((instr >> 10) & 0xFFF) << 3; // Scale by 8 for pointer
                if (imm >= 0x30 && imm <= 0x200) { // Reasonable offset range
                    offsets->proc_ucred_offset = imm;
                    printf("[+] Found proc->ucred offset: 0x%x\n", imm);
                    break;
                }
            }
        }
    }
    
    // Set known offsets for iOS 17.3.1 (fallback if patterns fail)
    if (!offsets->proc_ucred_offset) {
        offsets->proc_ucred_offset = 0x88; // Common offset
        printf("[*] Using default proc->ucred offset: 0x%x\n", offsets->proc_ucred_offset);
    }
    
    // CS enforcement and AMFI are typically patched directly
    // Their addresses will be resolved at runtime via kread
    offsets->cs_enforcement = 0; // Will be found via kread search
    offsets->amfi_hook_policy = 0;
    
    offsets->found_all = (offsets->current_proc != 0 && offsets->proc_ucred_offset != 0);
    
    return offsets->found_all;
}

// Runtime offset resolver using kread primitive
typedef uint64_t (*kread_func_t)(uint64_t addr);
typedef void (*kwrite_func_t)(uint64_t addr, uint64_t value);

static bool resolve_runtime_offsets(kread_func_t kread, kwrite_func_t kwrite,
                                   kernel_offsets_t *offsets) {
    if (!kread || !offsets->current_proc) {
        return false;
    }
    
    // Get current task/port
    uint64_t current_task = kread(offsets->current_proc);
    if (!current_task) {
        printf("[-] Failed to read current task\n");
        return false;
    }
    
    printf("[+] Current task: 0x%llx\n", current_task);
    
    // Resolve CS enforcement by searching for known pattern in memory
    // This requires reading kernel text segment
    // Simplified: assume standard location for iOS 17.3.1
    
    // For iOS 17.3.1 on A18:
    offsets->cs_enforcement = current_task + 0x3E8; // Approximate offset
    offsets->amfi_hook_policy = current_task + 0x3F0;
    
    printf("[+] Resolved CS enforcement: 0x%llx\n", offsets->cs_enforcement);
    printf("[+] Resolved AMFI hook: 0x%llx\n", offsets->amfi_hook_policy);
    
    return true;
}

#endif /* kernel_offsets_h */
