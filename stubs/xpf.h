// Minimal XPF stub interface for builds without the real XPF dependency.
// The real project uses XPF to parse kernelcache and resolve offsets; in stub
// builds we fall back to static offsets and simply keep the app linkable.
#pragma once

#include <stdint.h>

// Forward declarations (real types live in the XPF and choma projects).
typedef struct _xpc_object_s *xpc_object_t;

typedef struct {
    void *kernel;                 // Mach-O handle (choma) in real implementation
    const char *kernelVersionString;
    uint64_t kernelBase;
    uint64_t kernelEntry;
} xpf_context_t;

extern xpf_context_t gXPF;

int xpf_start_with_kernel_path(const char *path);
xpc_object_t xpf_construct_offset_dictionary(const char *const sets[]);
uint64_t xpf_item_resolve(const char *name);
const char *xpf_get_error(void);
void xpf_stop(void);

