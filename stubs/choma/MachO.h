#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __OBJC__
typedef void (^macho_symbol_iter_t)(const char *name, uint8_t type, uint64_t vmaddr, bool *stop);
#else
typedef void *macho_symbol_iter_t;
#endif

// Stub declaration to satisfy builds when the real choma dependency is absent.
// Returns 0 on success in the real implementation; the stub is never executed
// when XPF is unavailable because the code path bails out earlier.
static inline int macho_enumerate_symbols(void *macho, macho_symbol_iter_t iter) {
    (void)macho;
    (void)iter;
    return -1;
}

