#include "xpf.h"

#include <string.h>

xpf_context_t gXPF = {
    .kernel = 0,
    .kernelVersionString = "xpf-stub",
    .kernelBase = 0,
    .kernelEntry = 0,
};

static const char *g_xpf_last_error = "xpf stub: XPF is not bundled";

int xpf_start_with_kernel_path(const char *path) {
    (void)path;
    g_xpf_last_error = "xpf stub: start not supported";
    // Non-zero indicates failure in the real API; callers fall back.
    return -1;
}

xpc_object_t xpf_construct_offset_dictionary(const char *const sets[]) {
    (void)sets;
    g_xpf_last_error = "xpf stub: no dictionary";
    return (xpc_object_t)0;
}

uint64_t xpf_item_resolve(const char *name) {
    (void)name;
    // Returning 0 forces callers onto static fallbacks.
    return 0;
}

const char *xpf_get_error(void) {
    return g_xpf_last_error;
}

void xpf_stop(void) {
    // No-op.
}

