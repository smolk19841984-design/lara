//
//  LaraManager.h
//  lara
//
//  Rewritten in Objective-C (was laramgr.swift)
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LaraManager : NSObject

// Exploit state
@property (nonatomic, assign) BOOL dsRunning;
@property (nonatomic, assign) BOOL dsReady;
@property (nonatomic, assign) BOOL dsAttempted;
@property (nonatomic, assign) BOOL dsFailed;
@property (nonatomic, assign) double dsProgress;
@property (nonatomic, assign) uint64_t kernBase;
@property (nonatomic, assign) uint64_t kernSlide;

// SBX state
@property (nonatomic, assign) BOOL sbxReady;
@property (nonatomic, assign) BOOL sbxAttempted;
@property (nonatomic, assign) BOOL sbxFailed;
@property (nonatomic, assign) BOOL sbxRunning;

// VFS state
@property (nonatomic, assign) BOOL vfsReady;
@property (nonatomic, assign) BOOL vfsAttempted;
@property (nonatomic, assign) BOOL vfsFailed;
@property (nonatomic, assign) BOOL vfsRunning;
@property (nonatomic, assign) double vfsProgress;
@property (nonatomic, copy) NSString *vfsInitLog;

// Misc
@property (nonatomic, copy) NSString *log;

+ (instancetype)shared;
+ (NSString *)fontPath;

- (void)runExploit:(nullable void(^)(BOOL success))completion;
- (void)vfsInit:(nullable void(^)(BOOL success))completion;
- (void)sbxEscape:(nullable void(^)(BOOL success))completion;
/// Уникальная цепочка `sbx_escape_root_first` (root → unsandbox → transplant), см. sbx.h.
- (void)sbxEscapeRootFirst:(nullable void(^)(BOOL success))completion;

- (void)logMessage:(NSString *)message;

- (uint64_t)kread64:(uint64_t)address;
- (void)kwrite64:(uint64_t)address value:(uint64_t)value;
- (uint32_t)kread32:(uint64_t)address;
- (void)kwrite32:(uint64_t)address value:(uint32_t)value;

- (void)panic;
- (void)respring;

- (nullable NSArray<NSDictionary *> *)vfsListDir:(NSString *)path;
- (nullable NSData *)vfsRead:(NSString *)path maxSize:(NSInteger)maxSize;
- (BOOL)vfsWrite:(NSString *)path data:(NSData *)data;
- (int64_t)vfsSize:(NSString *)path;
- (BOOL)vfsOverwriteFromLocalPath:(NSString *)target source:(NSString *)source;
- (BOOL)vfsOverwriteWithData:(NSString *)target data:(NSData *)data;
- (BOOL)vfsZeroPage:(NSString *)path;

- (nullable NSString *)sbxGetToken:(NSString *)path;
- (void)sbxElevate;

- (NSDictionary *)laraOverwriteFile:(NSString *)target source:(NSString *)source;
- (NSDictionary *)laraOverwriteFileWithData:(NSString *)target data:(NSData *)data;

@end

NS_ASSUME_NONNULL_END
