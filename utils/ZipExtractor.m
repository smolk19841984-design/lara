//
//  ZipExtractor.m
//  lara
//

#import "ZipExtractor.h"
#include <zlib.h>
#include <stdint.h>

// ── ZIP format structs ────────────────────────────────────────────────────────

#pragma pack(1)
typedef struct {
    uint32_t sig;               // 0x04034b50
    uint16_t minVersion;
    uint16_t gpBitFlag;
    uint16_t compression;       // 0=STORE, 8=DEFLATE
    uint16_t modTime;
    uint16_t modDate;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t nameLen;
    uint16_t extraLen;
    // followed by: name[nameLen], extra[extraLen], data[compressedSize]
} ZipLocalHeader;
#pragma pack()

#define ZIP_LOCAL_SIG  0x04034b50u
#define ZIP_DATA_DESC  0x08074b50u
#define INFLATE_BUFSIZE (64 * 1024)

// ── Raw-deflate inflate ───────────────────────────────────────────────────────

static NSData * _Nullable _inflate(const uint8_t *src, size_t srcLen,
                                   size_t expectedLen, NSError **err)
{
    NSMutableData *out = [NSMutableData dataWithCapacity:expectedLen ?: srcLen * 4];
    uint8_t buf[INFLATE_BUFSIZE];

    z_stream strm = {0};
    strm.next_in  = (Bytef *)src;
    strm.avail_in = (uInt)srcLen;

    int ret = inflateInit2(&strm, -15); // raw deflate (no zlib/gzip header)
    if (ret != Z_OK) {
        if (err) *err = [NSError errorWithDomain:@"ZipExtractor"
                                            code:ret
                                        userInfo:@{NSLocalizedDescriptionKey:
                                            [NSString stringWithFormat:@"inflateInit2 failed: %d", ret]}];
        return nil;
    }

    do {
        strm.next_out  = buf;
        strm.avail_out = INFLATE_BUFSIZE;
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&strm);
            if (err) *err = [NSError errorWithDomain:@"ZipExtractor"
                                                code:ret
                                            userInfo:@{NSLocalizedDescriptionKey:
                                                [NSString stringWithFormat:@"inflate error: %d (%s)",
                                                 ret, strm.msg ?: "?"]}];
            return nil;
        }
        [out appendBytes:buf length:INFLATE_BUFSIZE - strm.avail_out];
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);
    return out;
}

// ── Public implementation ────────────────────────────────────────────────────

@implementation ZipExtractor

+ (BOOL)extractZipData:(NSData *)zipData
           toDirectory:(NSString *)destDir
         progressBlock:(void (^ _Nullable)(float))progress
                 error:(NSError *__autoreleasing _Nullable *)outError
{
    NSFileManager *fm = [NSFileManager defaultManager];
    const uint8_t *base = (const uint8_t *)zipData.bytes;
    const size_t   total = zipData.length;
    size_t pos = 0;
    NSUInteger fileCount = 0;

    // ── Count entries first for progress ────────────────────────────────────
    // (quick scan – only count, don't extract)
    NSUInteger totalEntries = 0;
    {
        size_t scan = 0;
        while (scan + sizeof(ZipLocalHeader) <= total) {
            const ZipLocalHeader *h = (const ZipLocalHeader *)(base + scan);
            if (h->sig != ZIP_LOCAL_SIG) break;
            scan += sizeof(ZipLocalHeader) + h->nameLen + h->extraLen + h->compressedSize;
            totalEntries++;
        }
    }

    // ── Extract loop ─────────────────────────────────────────────────────────
    while (pos + sizeof(ZipLocalHeader) <= total) {
        const ZipLocalHeader *hdr = (const ZipLocalHeader *)(base + pos);

        // End of local entries (central directory or EOF)
        if (hdr->sig != ZIP_LOCAL_SIG) break;

        pos += sizeof(ZipLocalHeader);

        // Entry name
        if (pos + hdr->nameLen > total) break;
        NSString *name = [[NSString alloc] initWithBytes:base + pos
                                                   length:hdr->nameLen
                                                 encoding:NSUTF8StringEncoding];
        pos += hdr->nameLen;

        // Skip extra
        pos += hdr->extraLen;

        // Compressed payload
        uint32_t compSz  = hdr->compressedSize;
        uint32_t uncompSz = hdr->uncompressedSize;

        if (pos + compSz > total) break;
        const uint8_t *compData = base + pos;
        pos += compSz;

        // ── Skip directories ─────────────────────────────────────────────────
        if ([name hasSuffix:@"/"]) continue;
        if (!name.length)          continue;

        // ── Build destination path ────────────────────────────────────────────
        NSString *destPath = [destDir stringByAppendingPathComponent:name];

        // Create intermediate dirs
        NSString *dirPath = [destPath stringByDeletingLastPathComponent];
        NSError *dirErr = nil;
        if (![fm createDirectoryAtPath:dirPath
           withIntermediateDirectories:YES attributes:nil error:&dirErr]) {
            if (outError) *outError = dirErr;
            return NO;
        }

        // ── Decompress / copy ─────────────────────────────────────────────────
        NSData *fileData = nil;
        NSError *inflErr = nil;

        switch (hdr->compression) {
            case 0: // STORE
                fileData = [NSData dataWithBytes:compData length:compSz];
                break;
            case 8: // DEFLATE
                fileData = _inflate(compData, compSz, uncompSz, &inflErr);
                if (!fileData) {
                    if (outError) *outError = inflErr;
                    return NO;
                }
                break;
            default:
                // Unknown compression — skip entry
                NSLog(@"[ZipExtractor] Skipping '%@': unknown compression %u", name, hdr->compression);
                continue;
        }

        // ── Write file ────────────────────────────────────────────────────────
        NSError *writeErr = nil;
        if (![fileData writeToFile:destPath options:NSDataWritingAtomic error:&writeErr]) {
            if (outError) *outError = writeErr;
            return NO;
        }

        fileCount++;
        if (progress && totalEntries > 0) {
            progress((float)fileCount / (float)totalEntries);
        }
    }

    return YES;
}

@end
