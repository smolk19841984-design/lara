/* stub xpc/xpc.h — minimal types for compilation with Theos SDK */
#ifndef XPC_XPC_H
#define XPC_XPC_H
#include <stdint.h>
#include <stdbool.h>
struct _xpc_type_s;
typedef const struct _xpc_type_s *xpc_type_t;
typedef struct _xpc_object_s *xpc_object_t;

// Minimal API surface used by XPF. On iOS these are provided by libxpc;
// Theos SDK may not ship the headers, so we declare what we need.
xpc_object_t xpc_dictionary_create_empty(void);
void xpc_dictionary_set_uint64(xpc_object_t xdict, const char *key, uint64_t value);
void xpc_release(xpc_object_t object);
#endif /* XPC_XPC_H */
