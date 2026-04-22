// Minimal stub of zstd.h, sufficient for compilation.
// This is NOT a real decompressor; it only exists to keep the project linkable
// when the real libzstd is not bundled in the checkout.
#pragma once

#include <stddef.h>

typedef struct ZSTD_DStream_s ZSTD_DStream;

typedef struct {
    const void *src;
    size_t size;
    size_t pos;
} ZSTD_inBuffer;

typedef struct {
    void *dst;
    size_t size;
    size_t pos;
} ZSTD_outBuffer;

size_t ZSTD_DStreamInSize(void);
size_t ZSTD_DStreamOutSize(void);

ZSTD_DStream *ZSTD_createDStream(void);
size_t ZSTD_initDStream(ZSTD_DStream *zds);
size_t ZSTD_decompressStream(ZSTD_DStream *zds, ZSTD_outBuffer *output, ZSTD_inBuffer *input);
unsigned ZSTD_isError(size_t code);
const char *ZSTD_getErrorName(size_t code);
size_t ZSTD_freeDStream(ZSTD_DStream *zds);

