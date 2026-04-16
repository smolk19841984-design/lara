#ifndef PACCache_h
#define PACCache_h

#include <stdint.h>
#include <stdbool.h>

// Predator-style 256-entry PAC signing cache
// Pre-computes signed pointers for all possible top-byte values
// Eliminates per-call PAC signing latency during hook callbacks

#define PAC_CACHE_SIZE 256

typedef struct {
    uint64_t pc_signed[PAC_CACHE_SIZE];   // Pre-signed PC pointers (PACIA with PC discriminator)
    uint64_t lr_signed[PAC_CACHE_SIZE];   // Pre-signed LR pointers (PACIA with LR discriminator)
    bool     initialized;
    uint64_t base_pc;                     // Original unsigned PC address
    uint64_t base_lr;                     // Original unsigned LR address
    uint64_t pc_discriminator;            // PC discriminator value
    uint64_t lr_discriminator;            // LR discriminator value
} PACCache;

// Initialize PAC cache (pre-compute all 256 entries)
int pac_cache_init(PACCache *cache, uint64_t remoteThreadAddr,
                   uint64_t pc_addr, uint64_t lr_addr,
                   uint64_t pc_disc, uint64_t lr_disc);

// Get pre-signed PC pointer for a given top-byte value
uint64_t pac_cache_get_pc(const PACCache *cache, uint64_t address);

// Get pre-signed LR pointer for a given top-byte value
uint64_t pac_cache_get_lr(const PACCache *cache, uint64_t address);

// Check if cache is initialized
bool pac_cache_is_ready(const PACCache *cache);

// JSC Gadget Hunting for PAC fallback
// Searches JavaScriptCore for PACIA gadget as alternative to libswiftCore gadget
uint64_t find_jsc_pacia_gadget(void);

// Remote Objective-C Method Resolution
// Resolves method implementation in remote process (handles per-process ASLR)
uint64_t remote_objc_resolve_method(const char *class_name, const char *sel_name,
                                    int timeout);

#endif /* PACCache_h */
