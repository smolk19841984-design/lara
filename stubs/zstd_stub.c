#include "zstd.h"

#include <stdlib.h>

struct ZSTD_DStream_s {
    int unused;
};

size_t ZSTD_DStreamInSize(void) {
    return 64 * 1024;
}

size_t ZSTD_DStreamOutSize(void) {
    return 64 * 1024;
}

ZSTD_DStream *ZSTD_createDStream(void) {
    return (ZSTD_DStream *)calloc(1, sizeof(ZSTD_DStream));
}

size_t ZSTD_initDStream(ZSTD_DStream *zds) {
    (void)zds;
    return 0;
}

size_t ZSTD_decompressStream(ZSTD_DStream *zds, ZSTD_outBuffer *output, ZSTD_inBuffer *input) {
    (void)zds;
    if (output) output->pos = 0;
    if (input) input->pos = input->size;
    // Always signal error for the stub implementation.
    return 1;
}

unsigned ZSTD_isError(size_t code) {
    return code != 0;
}

const char *ZSTD_getErrorName(size_t code) {
    (void)code;
    return "zstd stub: unsupported";
}

size_t ZSTD_freeDStream(ZSTD_DStream *zds) {
    free(zds);
    return 0;
}

