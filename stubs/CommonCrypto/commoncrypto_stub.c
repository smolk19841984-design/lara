#include "CommonDigest.h"

unsigned char *CC_SHA256(const void *data, CC_LONG len, unsigned char *md) {
    (void)data;
    (void)len;
    if (!md) return md;
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) md[i] = 0;
    return md;
}

