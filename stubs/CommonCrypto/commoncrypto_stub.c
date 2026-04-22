#include "CommonDigest.h"

static unsigned char *fill_zero(unsigned char *md, int len) {
    if (!md) return md;
    for (int i = 0; i < len; i++) md[i] = 0;
    return md;
}

unsigned char *CC_SHA1(const void *data, CC_LONG len, unsigned char *md) {
    (void)data;
    (void)len;
    return fill_zero(md, CC_SHA1_DIGEST_LENGTH);
}

unsigned char *CC_SHA256(const void *data, CC_LONG len, unsigned char *md) {
    (void)data;
    (void)len;
    return fill_zero(md, CC_SHA256_DIGEST_LENGTH);
}

unsigned char *CC_SHA384(const void *data, CC_LONG len, unsigned char *md) {
    (void)data;
    (void)len;
    return fill_zero(md, CC_SHA384_DIGEST_LENGTH);
}

