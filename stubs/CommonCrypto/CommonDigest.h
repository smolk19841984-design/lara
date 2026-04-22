#pragma once

#include <stddef.h>
#include <stdint.h>

typedef uint32_t CC_LONG;

#define CC_SHA256_DIGEST_LENGTH 32

unsigned char *CC_SHA256(const void *data, CC_LONG len, unsigned char *md);

