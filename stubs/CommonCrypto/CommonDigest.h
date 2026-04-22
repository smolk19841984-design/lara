#pragma once

#include <stddef.h>
#include <stdint.h>

typedef uint32_t CC_LONG;

#define CC_SHA1_DIGEST_LENGTH 20
#define CC_SHA256_DIGEST_LENGTH 32
#define CC_SHA384_DIGEST_LENGTH 48

unsigned char *CC_SHA1(const void *data, CC_LONG len, unsigned char *md);
unsigned char *CC_SHA256(const void *data, CC_LONG len, unsigned char *md);
unsigned char *CC_SHA384(const void *data, CC_LONG len, unsigned char *md);

