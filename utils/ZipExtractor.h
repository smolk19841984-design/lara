//
//  ZipExtractor.h
//  lara
//
//  Minimal ZIP extractor (STORE + DEFLATE) backed by zlib.
//  Designed for unpacking IPA files from memory — no external tools needed.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZipExtractor : NSObject

/**
 * Extract every entry in `zipData` into `destDir`.
 * Directories and sub-paths are created automatically.
 * Returns YES on success, NO if any entry fails (and sets *outError).
 *
 * Only compression methods 0 (STORE) and 8 (DEFLATE) are supported.
 */
+ (BOOL)extractZipData:(NSData *)zipData
           toDirectory:(NSString *)destDir
         progressBlock:(nullable void (^)(float progress))progress
                 error:(NSError *__autoreleasing _Nullable *)outError;

@end

NS_ASSUME_NONNULL_END
