#include "CommonDigest.h"

// Implement CommonCrypto SHA API using OpenSSL libcrypto.
// This keeps the rest of the codebase unchanged while providing real hashes.
#include <openssl/sha.h>

unsigned char *CC_SHA1(const void *data, CC_LONG len, unsigned char *md) {
    if (!md) return NULL;
    return SHA1((const unsigned char *)data, (size_t)len, md);
}

unsigned char *CC_SHA256(const void *data, CC_LONG len, unsigned char *md) {
    if (!md) return NULL;
    return SHA256((const unsigned char *)data, (size_t)len, md);
}

unsigned char *CC_SHA384(const void *data, CC_LONG len, unsigned char *md) {
    if (!md) return NULL;
    return SHA384((const unsigned char *)data, (size_t)len, md);
}

