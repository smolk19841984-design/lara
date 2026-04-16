//
//  LaraManager.m
//  lara
//
//  Rewritten in Objective-C (was laramgr.swift)
//

#import "LaraManager.h"
#import "Logger.h"
#import "kexploit/darksword.h"
#import "kexploit/vfs.h"
#import "kexploit/sbx.h"
#include <sys/sysctl.h>
#import <notify.h>

// Legacy compatibility export expected by older bundled DarkSword/XPF objects.
__attribute__((used, visibility("default")))
NSString *const DSExploitDidFailNotification = @"DSExploitDidFailNotification";

// ── Static C callbacks (blocks cannot be passed as plain C function pointers) ─
static void _lara_ds_log(const char *msg) {
    if (!msg) return;
    NSString *s = @(msg);
    dispatch_async(dispatch_get_main_queue(), ^{
        [[LaraManager shared] logMessage:[NSString stringWithFormat:@"(ds) %@", s]];
    });
}
static void _lara_ds_prog(double p) {
    dispatch_async(dispatch_get_main_queue(), ^{ [LaraManager shared].dsProgress = p; });
}
static void _lara_vfs_log(const char *msg) {
    if (!msg) return;
    NSString *s = @(msg);
    dispatch_async(dispatch_get_main_queue(), ^{
        LaraManager *mgr = [LaraManager shared];
        mgr.vfsInitLog = [mgr.vfsInitLog stringByAppendingFormat:@"(vfs) %@\n", s];
        [mgr logMessage:[NSString stringWithFormat:@"(vfs) %@", s]];
    });
}
static void _lara_vfs_prog(double p) {
    dispatch_async(dispatch_get_main_queue(), ^{ [LaraManager shared].vfsProgress = p; });
}
static void _lara_sbx_log(const char *msg) {
    if (!msg) return;
    NSString *s = @(msg);
    dispatch_async(dispatch_get_main_queue(), ^{
        [[LaraManager shared] logMessage:[NSString stringWithFormat:@"(sbx) %@", s]];
    });
}

@implementation LaraManager

static LaraManager *_shared = nil;

+ (instancetype)shared {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _shared = [[LaraManager alloc] init];
    });
    return _shared;
}

+ (NSString *)fontPath {
    return @"/System/Library/Fonts/Core/SFUI.ttf";
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _log = @"";
        _vfsInitLog = @"";
        _dsRunning = NO;
        _dsReady = NO;
        _dsAttempted = NO;
        _dsFailed = NO;
        _dsProgress = 0.0;
        _kernBase = 0;
        _kernSlide = 0;
        _sbxReady = NO;
        _sbxAttempted = NO;
        _sbxFailed = NO;
        _sbxRunning = NO;
        _vfsReady = NO;
        _vfsAttempted = NO;
        _vfsFailed = NO;
        _vfsRunning = NO;
        _vfsProgress = 0.0;
    }
    return self;
}

#pragma mark - Exploit

- (void)runExploit:(nullable void(^)(BOOL))completion {
    if (self.dsRunning) return;

    self.dsRunning = YES;
    self.dsReady = NO;
    self.dsFailed = NO;
    self.dsAttempted = YES;
    self.dsProgress = 0.0;
    self.log = @"";

    __weak typeof(self) weakSelf = self;

    ds_set_log_callback(_lara_ds_log);
    ds_set_progress_callback(_lara_ds_prog);

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int result = ds_run();
        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;
            self.dsRunning = NO;
            BOOL success = (result == 0 && ds_is_ready());
            if (success) {
                self.dsReady = YES;
                self.dsFailed = NO;
                self.kernBase  = ds_get_kernel_base();
                self.kernSlide = ds_get_kernel_slide();
                [self logMessage:@"\nexploit success!"];
                [self logMessage:[NSString stringWithFormat:@"kernel_base:  0x%llx", self.kernBase]];
                [self logMessage:[NSString stringWithFormat:@"kernel_slide: 0x%llx\n", self.kernSlide]];
                [[Logger shared] log:@"exploit success!"];
                [[Logger shared] log:[NSString stringWithFormat:@"kernel_base:  0x%llx", self.kernBase]];
                [[Logger shared] log:[NSString stringWithFormat:@"kernel_slide: 0x%llx", self.kernSlide]];
                [[Logger shared] divider];
            } else {
                self.dsFailed = YES;
                [self logMessage:@"\nexploit failed.\n"];
                [[Logger shared] log:@"exploit failed."];
                [[Logger shared] divider];
            }
            self.dsProgress = 1.0;
            if (completion) completion(success);
        });
    });
}

#pragma mark - VFS

- (void)vfsInit:(nullable void(^)(BOOL))completion {
    __weak typeof(self) weakSelf = self;

    vfs_setlogcallback(_lara_vfs_log);
    vfs_setprogresscallback(_lara_vfs_prog);

    self.vfsAttempted = YES;
    self.vfsFailed = NO;
    self.vfsRunning = YES;
    self.vfsProgress = 0.0;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int r = vfs_init();
        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;
            self.vfsReady = (r == 0 && vfs_isready());
            if (self.vfsReady) {
                self.vfsFailed = NO;
                [self logMessage:@"\nvfs ready!\n"];
            } else {
                self.vfsFailed = YES;
                [self logMessage:@"\nvfs init failed.\n"];
            }
            self.vfsRunning = NO;
            self.vfsProgress = 1.0;
            if (completion) completion(self.vfsReady);
        });
    });
}

#pragma mark - SBX

- (void)sbxEscape:(nullable void(^)(BOOL))completion {
    if (!self.dsReady || self.sbxRunning) return;
    self.sbxAttempted = YES;
    self.sbxFailed = NO;
    self.sbxRunning = YES;

    __weak typeof(self) weakSelf = self;

    sbx_setlogcallback(_lara_sbx_log);

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int r = sbx_escape(ds_get_our_proc());
        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;
            self.sbxReady = (r == 0);
            if (self.sbxReady) {
                self.sbxFailed = NO;
                [self logMessage:@"\nsandbox escape ready!\n"];
            } else {
                self.sbxFailed = YES;
                [self logMessage:@"\nsandbox escape failed.\n"];
            }
            self.sbxRunning = NO;
            if (completion) completion(self.sbxReady);
        });
    });
}

- (void)sbxEscapeRootFirst:(nullable void(^)(BOOL))completion {
    if (!self.dsReady || self.sbxRunning) return;
    self.sbxAttempted = YES;
    self.sbxFailed = NO;
    self.sbxRunning = YES;

    __weak typeof(self) weakSelf = self;

    sbx_setlogcallback(_lara_sbx_log);

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int r = sbx_escape_root_first(ds_get_our_proc());
        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;
            self.sbxReady = (r == 0);
            if (self.sbxReady) {
                self.sbxFailed = NO;
                [self logMessage:@"\nsandbox escape ready! (root-first chain)\n"];
            } else {
                self.sbxFailed = YES;
                [self logMessage:@"\nsandbox escape failed (root-first chain).\n"];
            }
            self.sbxRunning = NO;
            if (completion) completion(self.sbxReady);
        });
    });
}

#pragma mark - Kernel R/W

- (uint64_t)kread64:(uint64_t)address {
    if (!self.dsReady) return 0;
    return ds_kread64(address);
}

- (void)kwrite64:(uint64_t)address value:(uint64_t)value {
    if (!self.dsReady) return;
    ds_kwrite64(address, value);
}

- (uint32_t)kread32:(uint64_t)address {
    if (!self.dsReady) return 0;
    return ds_kread32(address);
}

- (void)kwrite32:(uint64_t)address value:(uint32_t)value {
    if (!self.dsReady) return;
    ds_kwrite32(address, value);
}

#pragma mark - Panic / Respring

- (void)panic {
    if (!self.dsReady) return;
    [[Logger shared] log:@"triggering panic"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        uint64_t kernbase = ds_get_kernel_base();
        [[Logger shared] log:@"writing to read-only memory at kernel base"];
        ds_kwrite64(kernbase, 0xDEADBEEF);
    });
}

- (void)respring {
    notify_post("com.apple.springboard.toggleLockScreen");
}

#pragma mark - VFS Helpers

- (nullable NSArray<NSDictionary *> *)vfsListDir:(NSString *)path {
    if (!self.vfsReady) {
        [self logMessage:[NSString stringWithFormat:@" listdir: not ready (%@)", path]];
        return nil;
    }
    vfs_entry_t *ptr = NULL;
    int count = 0;
    int r = vfs_listdir(path.UTF8String, &ptr, &count);
    if (r != 0 || !ptr) {
        [self logMessage:[NSString stringWithFormat:@" listdir failed (%@) r=%d", path, r]];
        return nil;
    }

    NSMutableArray *items = [NSMutableArray array];
    for (int i = 0; i < count; i++) {
        vfs_entry_t e = ptr[i];
        NSString *name = [NSString stringWithUTF8String:e.name];
        BOOL isDir = (e.d_type == 4);
        [items addObject:@{@"name": name, @"isDir": @(isDir)}];
    }
    vfs_freelisting(ptr);

    [self logMessage:[NSString stringWithFormat:@" listdir %@ -> %lu", path, (unsigned long)items.count]];

    [items sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"name"] localizedCaseInsensitiveCompare:b[@"name"]];
    }];

    return [items copy];
}

- (nullable NSData *)vfsRead:(NSString *)path maxSize:(NSInteger)maxSize {
    if (!self.vfsReady) return nil;
    int64_t fsz = vfs_filesize(path.UTF8String);
    if (fsz <= 0) return nil;
    NSInteger toRead = MIN((NSInteger)fsz, maxSize);
    uint8_t *buf = (uint8_t *)malloc(toRead);
    if (!buf) return nil;
    int64_t n = vfs_read(path.UTF8String, buf, toRead, 0);
    NSData *result = nil;
    if (n > 0) {
        result = [NSData dataWithBytes:buf length:(NSUInteger)n];
    }
    free(buf);
    return result;
}

- (BOOL)vfsWrite:(NSString *)path data:(NSData *)data {
    if (!self.vfsReady) return NO;
    int64_t n = vfs_write(path.UTF8String, data.bytes, data.length, 0);
    return n > 0;
}

- (int64_t)vfsSize:(NSString *)path {
    if (!self.vfsReady) return -1;
    return vfs_filesize(path.UTF8String);
}

- (BOOL)vfsOverwriteFromLocalPath:(NSString *)target source:(NSString *)source {
    NSLog(@"(vfs) target %@ -> %@", source, target);
    if (!self.vfsReady) {
        NSLog(@"(vfs) not ready");
        return NO;
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:source]) {
        NSLog(@"(vfs) source file not found: %@", source);
        return NO;
    }
    int r = vfs_overwritefile(target.UTF8String, source.UTF8String);
    NSLog(@"(vfs) vfs_overwritefile returned: %d", r);
    return r == 0;
}

- (BOOL)vfsOverwriteWithData:(NSString *)target data:(NSData *)data {
    if (!self.vfsReady) return NO;
    NSString *tmp = [NSTemporaryDirectory() stringByAppendingPathComponent:
                     [NSString stringWithFormat:@"vfs_src_%u.bin", arc4random()]];
    [data writeToFile:tmp atomically:YES];
    BOOL ok = [self vfsOverwriteFromLocalPath:target source:tmp];
    [[NSFileManager defaultManager] removeItemAtPath:tmp error:nil];
    return ok;
}

- (BOOL)vfsZeroPage:(NSString *)path {
    int r = vfs_zeropage(path.UTF8String, 0);
    if (r != 0) {
        [self logMessage:@"(vfs) zeropage failed"];
        return NO;
    }
    [self logMessage:[NSString stringWithFormat:@"(vfs) zeroed first page of %@", path]];
    return YES;
}

#pragma mark - SBX Helpers

- (nullable NSString *)sbxGetToken:(NSString *)path {
    NSString *result = sbx_gettoken(path);
    return result;
}

- (void)sbxElevate {
    dispatch_async(dispatch_get_main_queue(), ^{
        sbx_elevate();
    });
}

#pragma mark - Unified Overwrite

- (NSDictionary *)laraOverwriteFile:(NSString *)target source:(NSString *)source {
    if (![[NSFileManager defaultManager] fileExistsAtPath:source]) {
        return @{@"ok": @NO, @"message": [NSString stringWithFormat:@"source file not found: %@", source]};
    }

    if (self.sbxReady) {
        NSError *err;
        NSData *data = [NSData dataWithContentsOfFile:source options:0 error:&err];
        if (data) {
            NSDictionary *r = [self sbxOverwrite:target data:data];
            if ([r[@"ok"] boolValue]) return r;
            // fall through to vfs
            if (!self.vfsReady) return @{@"ok": @NO, @"message": r[@"message"]};
        }
    }

    if (!self.vfsReady) {
        return @{@"ok": @NO, @"message": @"sbx not ready and vfs not ready"};
    }
    BOOL ok = [self vfsOverwriteFromLocalPath:target source:source];
    return ok ? @{@"ok": @YES, @"message": @"ok (vfs overwrite)"}
              : @{@"ok": @NO,  @"message": @"vfs overwrite failed"};
}

- (NSDictionary *)laraOverwriteFileWithData:(NSString *)target data:(NSData *)data {
    if (self.sbxReady) {
        NSDictionary *r = [self sbxOverwrite:target data:data];
        if ([r[@"ok"] boolValue]) return r;
        if (!self.vfsReady) return @{@"ok": @NO, @"message": r[@"message"]};
    }
    if (!self.vfsReady) {
        return @{@"ok": @NO, @"message": @"sbx not ready, vfs not ready"};
    }
    BOOL ok = [self vfsOverwriteWithData:target data:data];
    return ok ? @{@"ok": @YES, @"message": @"vfs overwrite ok"}
              : @{@"ok": @NO,  @"message": @"vfs overwrite failed"};
}

#pragma mark - Private

- (void)logMessage:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.log = [self.log stringByAppendingFormat:@"%@\n", message];
        [[Logger shared] log:message];
    });
}

- (NSDictionary *)sbxOverwrite:(NSString *)path data:(NSData *)data {
    int fd = open(path.UTF8String, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        return @{@"ok": @NO,
                 @"message": [NSString stringWithFormat:@"sbx open failed: errno=%d %s",
                               errno, strerror(errno)]};
    }

    NSInteger total = 0;
    const uint8_t *base = (const uint8_t *)data.bytes;
    NSInteger len = (NSInteger)data.length;
    BOOL wrote = YES;
    while (total < len) {
        ssize_t n = write(fd, base + total, len - total);
        if (n <= 0) { wrote = NO; break; }
        total += n;
    }
    close(fd);

    if (!wrote) {
        return @{@"ok": @NO,
                 @"message": [NSString stringWithFormat:@"sbx write failed: errno=%d %s",
                               errno, strerror(errno)]};
    }
    return @{@"ok": @YES, @"message": [NSString stringWithFormat:@"ok (%ld bytes)", (long)total]};
}

@end
