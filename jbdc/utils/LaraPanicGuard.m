//
//  LaraPanicGuard.m
//  Lara Jailbreak - Panic Protection & Logging Implementation
//
//  Реализация защиты от kernel panic с аварийным сохранением логов
//  Совместимо с iOS 17.3.1 (rootless)
//

#import "LaraPanicGuard.h"
#import <pthread.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <execinfo.h>
#import <signal.h>
#import <fcntl.h>
#import <unistd.h>
#import <sys/mman.h>

// Private frameworks
typedef struct {
    uint64_t timestamp;
    uint32_t cpu_id;
    uint32_t reserved;
    uint64_t exception_type;
    uint64_t exception_code;
    uint64_t lr;
    uint64_t pc;
    uint64_t sp;
    uint64_t x[29];
    char message[256];
    char backtrace[1024];
} KernelPanicData;

@interface LaraPanicGuard () {
    os_log_t _logHandle;
    NSString *_logDirectory;
    NSString *_currentLogFile;
    FILE *_logFileHandle;
    pthread_mutex_t _logMutex;
    
    // Black box buffer in RAM (persisted across panic)
    void *_blackBoxBuffer;
    size_t _blackBoxSize;
    volatile uint32_t _blackBoxIndex;
    
    // Pre-panic callbacks
    NSMutableArray<LaraPrePanicCallback> *_prePanicCallbacks;
    
    // Panic hook state
    BOOL _panicHookEnabled;
    struct sigaction _oldSigAction;
}

@property (nonatomic, assign) BOOL initialized;
@property (nonatomic, strong) NSMutableArray *savedPanics;

@end

#pragma mark - Global Variables

static LaraPanicGuard *_sharedInstance = nil;
static volatile BOOL g_isInPanic = NO;
static const size_t kBlackBoxSize = 64 * 1024;  // 64KB ring buffer

#pragma mark - Signal Handler

static void panic_signal_handler(int sig, siginfo_t *info, void *context) {
    if (g_isInPanic) return;  // Prevent re-entry
    g_isInPanic = YES;
    
    LaraPanicGuard *guard = [LaraPanicGuard sharedInstance];
    
    // Capture registers from context
    LaraPanicContext panicContext = {0};
    panicContext.timestamp = (uint64_t)[NSDate date].timeIntervalSince1970;
    panicContext.exception_type = (uint64_t)sig;
    panicContext.exception_code = (uint64_t)info->si_code;
    
#if defined(__arm64__)
    ucontext_t *uap = (ucontext_t *)context;
    if (uap) {
        panicContext.pc = uap->uc_mcontext->__ss.__pc;
        panicContext.lr = uap->uc_mcontext->__ss.__lr;
        panicContext.sp = uap->uc_mcontext->__ss.__sp;
        for (int i = 0; i < 29; i++) {
            panicContext.x[i] = uap->uc_mcontext->__ss.__x[i];
        }
    }
#endif
    
    snprintf(panicContext.message, sizeof(panicContext.message), 
             "Signal %d at PC: 0x%llx", sig, panicContext.pc);
    
    // Capture backtrace
    void *backtrace[32];
    int depth = backtrace(backtrace, 32);
    char **symbols = backtrace_symbols(backtrace, depth);
    
    StringBuilder sb;
    sb.length = 0;
    for (int i = 0; i < depth && sb.length < sizeof(panicContext.backtrace) - 50; i++) {
        if (symbols && symbols[i]) {
            int len = strlen(symbols[i]);
            if (sb.length + len + 2 < sizeof(panicContext.backtrace)) {
                strcpy(panicContext.backtrace + sb.length, symbols[i]);
                sb.length += len;
                panicContext.backtrace[sb.length++] = '\n';
                panicContext.backtrace[sb.length] = '\0';
            }
        }
    }
    
    if (symbols) free(symbols);
    
    // Execute pre-panic callbacks
    for (LaraPrePanicCallback callback in guard->_prePanicCallbacks) {
        @try {
            callback();
        } @catch (...) {
            // Ignore callback errors during panic
        }
    }
    
    // Force flush logs to disk
    [guard flushLogs];
    
    // Save panic context
    [guard savePanicContext:&panicContext];
    
    // Write to black box
    if (guard->_blackBoxBuffer) {
        memcpy((char*)guard->_blackBoxBuffer + (guard->_blackBoxIndex % kBlackBoxSize), 
               &panicContext, sizeof(panicContext));
        guard->_blackBoxIndex += sizeof(panicContext);
        msync(guard->_blackBoxBuffer, kBlackBoxSize, MS_ASYNC);
    }
    
    // Re-raise signal after saving
    if (guard->_oldSigAction.sa_sigaction) {
        guard->_oldSigAction.sa_sigaction(sig, info, context);
    } else {
        _exit(128 + sig);
    }
}

#pragma mark - Singleton

+ (instancetype)sharedInstance {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _sharedInstance = [[LaraPanicGuard alloc] init];
    });
    return _sharedInstance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _prePanicCallbacks = [NSMutableArray array];
        _savedPanics = [NSMutableArray array];
        pthread_mutex_init(&_logMutex, NULL);
    }
    return self;
}

#pragma mark - Initialization

- (void)initializeWithLogPath:(NSString *)logPath panicHookEnabled:(BOOL)enablePanicHook {
    if (self.initialized) return;
    
    _logDirectory = logPath;
    _panicHookEnabled = enablePanicHook;
    
    // Create log directory
    [[NSFileManager defaultManager] createDirectoryAtPath:logPath 
                              withIntermediateDirectories:YES 
                                               attributes:nil 
                                                    error:nil];
    
    // Initialize os_log
    _logHandle = os_log_create("com.ruter.lara", "panic_guard");
    
    // Rotate log files
    [self rotateLogFiles];
    
    // Open current log file
    _currentLogFile = [logPath stringByAppendingPathComponent:
                       [NSString stringWithFormat:@"lara_%@.log", 
                        [[NSDate date] descriptionByReplacingColonsWithUnderscores]]];
    _logFileHandle = fopen(_currentLogFile.fileSystemRepresentation, "a");
    
    if (!_logFileHandle) {
        NSLog(@"[LaraPanicGuard] Failed to open log file: %@", _currentLogFile);
        return;
    }
    
    // Set line buffering for immediate writes
    setvbuf(_logFileHandle, NULL, _IOLBF, 0);
    
    // Setup panic hooks
    if (enablePanicHook) {
        [self setupPanicHooks];
    }
    
    // Initialize black box
    [self enableBlackBoxMode];
    
    // Load saved panics
    [self loadSavedPanics];
    
    self.initialized = YES;
    
    LARA_LOG_INFO(@"PanicGuard initialized at %@ with hooks=%d", logPath, enablePanicHook);
}

- (void)setupPanicHooks {
    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sa.sa_sigaction = panic_signal_handler;
    
    // Register for critical signals
    sigaction(SIGSEGV, &sa, &_oldSigAction);
    sigaction(SIGBUS, &sa, &_oldSigAction);
    sigaction(SIGABRT, &sa, &_oldSigAction);
    sigaction(SIGILL, &sa, &_oldSigAction);
    sigaction(SIGTRAP, &sa, &_oldSigAction);
    
    LARA_LOG_DEBUG(@"Panic hooks installed for SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGTRAP");
}

#pragma mark - Logging

- (void)logLevel:(LaraLogLevel)level format:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    
    [self logVerbose:[self levelTag:level] message:message];
}

- (void)logVerbose:(NSString *)tag message:(NSString *)message {
    pthread_mutex_lock(&_logMutex);
    
    // Format: [TIMESTAMP] [THREAD] [LEVEL] MESSAGE
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
    NSString *timestamp = [formatter stringFromDate:[NSDate date]];
    
    NSString *threadName = [NSThread currentThread].name ?: 
                           [NSString stringWithFormat:@"%p", [NSThread currentThread]];
    
    NSString *logLine = [NSString stringWithFormat:@"[%@] [%@] %@\n", 
                         timestamp, tag, message];
    
    // Write to file
    if (_logFileHandle) {
        fwrite(logLine.UTF8String, 1, logLine.length, _logFileHandle);
        fflush(_logFileHandle);  // Force write to disk
    }
    
    // Write to os_log
    if (_logHandle) {
        os_log_with_type(_logHandle, OS_LOG_TYPE_DEFAULT, "%{public}@", logLine);
    }
    
    // Write to black box (ring buffer)
    if (_blackBoxBuffer) {
        const char *data = logLine.UTF8String;
        size_t len = strlen(data);
        
        if (len < kBlackBoxSize / 2) {
            size_t pos = _blackBoxIndex % kBlackBoxSize;
            
            // Handle wrap-around
            if (pos + len > kBlackBoxSize) {
                size_t firstPart = kBlackBoxSize - pos;
                memcpy((char*)_blackBoxBuffer + pos, data, firstPart);
                memcpy(_blackBoxBuffer, data + firstPart, len - firstPart);
            } else {
                memcpy((char*)_blackBoxBuffer + pos, data, len);
            }
            
            _blackBoxIndex += (uint32_t)len;
            msync(_blackBoxBuffer, kBlackBoxSize, MS_ASYNC);
        }
    }
    
    pthread_mutex_unlock(&_logMutex);
}

- (NSString *)levelTag:(LaraLogLevel)level {
    switch (level) {
        case LaraLogLevelDebug: return @"DEBUG";
        case LaraLogLevelInfo: return @"INFO";
        case LaraLogLevelWarning: return @"WARN";
        case LaraLogLevelError: return @"ERROR";
        case LaraLogLevelCritical: return @"CRITICAL";
        case LaraLogLevelPanic: return @"PANIC";
        default: return @"UNKNOWN";
    }
}

- (void)flushLogs {
    pthread_mutex_lock(&_logMutex);
    
    if (_logFileHandle) {
        fflush(_logFileHandle);
        fsync(fileno(_logFileHandle));  // Force sync to NAND
    }
    
    if (_blackBoxBuffer) {
        msync(_blackBoxBuffer, kBlackBoxSize, MS_SYNC);  // Sync black box
    }
    
    pthread_mutex_unlock(&_logMutex);
    
    LARA_LOG_DEBUG(@"Logs flushed to disk");
}

#pragma mark - Panic Context Management

- (void)savePanicContext:(const LaraPanicContext *)context {
    if (!context) return;
    
    NSString *panicFile = [_logDirectory stringByAppendingPathComponent:
                           [NSString stringWithFormat:@"panic_%llu.bin", context->timestamp]];
    
    NSData *panicData = [NSData dataWithBytes:context length:sizeof(LaraPanicContext)];
    
    if ([panicData writeToFile:panicFile atomically:YES]) {
        LARA_LOG_CRITICAL(@"Panic context saved to %@", panicFile);
        
        // Also save as JSON for easy reading
        NSDictionary *json = [self panicContextToDictionary:context];
        NSString *jsonString = [self prettyJSON:json];
        NSString *jsonFile = [_logDirectory stringByAppendingPathComponent:
                              [NSString stringWithFormat:@"panic_%llu.json", context->timestamp]];
        [jsonString writeToFile:jsonFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } else {
        LARA_LOG_ERROR(@"Failed to save panic context");
    }
}

- (NSArray<LaraPanicContext *> *)loadSavedPanics {
    NSMutableArray *panics = [NSMutableArray array];
    
    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:_logDirectory error:nil];
    
    for (NSString *file in files) {
        if ([file hasPrefix:@"panic_"] && [file hasSuffix:@".bin"]) {
            NSString *filePath = [_logDirectory stringByAppendingPathComponent:file];
            NSData *data = [NSData dataWithContentsOfFile:filePath];
            
            if (data.length == sizeof(LaraPanicContext)) {
                LaraPanicContext context;
                [data getBytes:&context length:sizeof(context)];
                [panics addObject:[NSValue valueWithBytes:&context objCType:@encode(LaraPanicContext)]];
            }
        }
    }
    
    _savedPanics = panics;
    return [panics copy];
}

- (NSDictionary *)panicContextToDictionary:(const LaraPanicContext *)context {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    
    dict[@"timestamp"] = @(context->timestamp);
    dict[@"cpu_id"] = @(context->cpu_id);
    dict[@"exception_type"] = @(context->exception_type);
    dict[@"exception_code"] = @(context->exception_code);
    dict[@"lr"] = [NSString stringWithFormat:@"0x%llx", context->lr];
    dict[@"pc"] = [NSString stringWithFormat:@"0x%llx", context->pc];
    dict[@"sp"] = [NSString stringWithFormat:@"0x%llx", context->sp];
    dict[@"message"] = [NSString stringWithUTF8String:context->message];
    dict[@"backtrace"] = [NSString stringWithUTF8String:context->backtrace];
    
    NSMutableArray *registers = [NSMutableArray array];
    for (int i = 0; i < 29; i++) {
        [registers addObject:[NSString stringWithFormat:@"x%d: 0x%llx", i, context->x[i]]];
    }
    dict[@"registers"] = registers;
    
    return dict;
}

- (NSString *)prettyJSON:(NSDictionary *)dict {
    NSError *error = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dict 
                                                       options:NSJSONWritingPrettyPrinted 
                                                         error:&error];
    if (error) {
        return [NSString stringWithFormat:@"Error: %@", error.localizedDescription];
    }
    return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}

#pragma mark - Black Box Mode

- (void)enableBlackBoxMode {
    if (_blackBoxBuffer) {
        munmap(_blackBoxBuffer, kBlackBoxSize);
    }
    
    // Allocate memory that persists across fork/exec (MAP_SHARED)
    // In practice, we use MAP_ANONYMOUS | MAP_NOCORE for crash resilience
    _blackBoxBuffer = mmap(NULL, kBlackBoxSize, 
                          PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    
    if (_blackBoxBuffer == MAP_FAILED) {
        _blackBoxBuffer = NULL;
        LARA_LOG_ERROR(@"Failed to allocate black box buffer");
    } else {
        _blackBoxSize = kBlackBoxSize;
        _blackBoxIndex = 0;
        memset(_blackBoxBuffer, 0, kBlackBoxSize);
        LARA_LOG_INFO(@"Black box mode enabled (%zu KB)", kBlackBoxSize / 1024);
    }
}

- (NSData *)extractBlackBoxData {
    if (!_blackBoxBuffer || _blackBoxIndex == 0) {
        return nil;
    }
    
    // Extract valid data from ring buffer
    size_t validSize = MIN(_blackBoxIndex, kBlackBoxSize);
    size_t startPos = (kBlackBoxSize - validSize + (_blackBoxIndex % kBlackBoxSize)) % kBlackBoxSize;
    
    NSMutableData *data = [NSMutableData dataWithLength:validSize];
    
    if (startPos + validSize <= kBlackBoxSize) {
        memcpy(data.mutableBytes, (char*)_blackBoxBuffer + startPos, validSize);
    } else {
        size_t firstPart = kBlackBoxSize - startPos;
        memcpy(data.mutableBytes, (char*)_blackBoxBuffer + startPos, firstPart);
        memcpy((char*)data.mutableBytes + firstPart, _blackBoxBuffer, validSize - firstPart);
    }
    
    return data;
}

#pragma mark - Callbacks

- (void)registerPrePanicCallback:(LaraPrePanicCallback)callback {
    if (callback) {
        [_prePanicCallbacks addObject:[callback copy]];
    }
}

#pragma mark - Report Generation

- (NSDictionary *)generatePanicReport {
    NSMutableDictionary *report = [NSMutableDictionary dictionary];
    
    report[@"app_version"] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    report[@"build_number"] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
    report[@"ios_version"] = [[UIDevice currentDevice] systemVersion];
    report[@"device_model"] = [self deviceModel];
    report[@"timestamp"] = [[NSDate date] iso8601String];
    
    // Add last panic if exists
    if (_savedPanics.count > 0) {
        LaraPanicContext lastPanic;
        [_savedPanics.lastObject getValue:&lastPanic];
        report[@"last_panic"] = [self panicContextToDictionary:&lastPanic];
    }
    
    // Add black box data
    NSData *blackBoxData = [self extractBlackBoxData];
    if (blackBoxData) {
        report[@"black_box"] = [blackBoxData base64EncodedStringWithOptions:0];
    }
    
    // Add recent logs (last 100 lines)
    NSString *recentLogs = [self extractRecentLogs:100];
    if (recentLogs) {
        report[@"recent_logs"] = recentLogs;
    }
    
    return [report copy];
}

- (NSString *)deviceModel {
    size_t size;
    sysctlbyname("hw.machine", NULL, &size, NULL, 0);
    char *model = malloc(size);
    sysctlbyname("hw.machine", model, &size, NULL, 0);
    NSString *result = [NSString stringWithUTF8String:model];
    free(model);
    return result;
}

- (NSString *)extractRecentLogs:(NSInteger)lineCount {
    if (!_currentLogFile || ![[NSFileManager defaultManager] fileExistsAtPath:_currentLogFile]) {
        return nil;
    }
    
    NSString *content = [NSString stringWithContentsOfFile:_currentLogFile 
                                                  encoding:NSUTF8StringEncoding 
                                                     error:nil];
    if (!content) return nil;
    
    NSArray *lines = [content componentsSeparatedByString:@"\n"];
    NSInteger start = MAX(0, lines.count - lineCount);
    NSArray *recentLines = [lines subarrayWithRange:NSMakeRange(start, lines.count - start)];
    
    return [recentLines componentsJoinedByString:@"\n"];
}

#pragma mark - Cleanup

- (void)cleanupOldLogs {
    NSDate *cutoffDate = [[NSDate date] dateByAddingTimeInterval:-7 * 24 * 60 * 60];  // 7 days ago
    
    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:_logDirectory error:nil];
    
    for (NSString *file in files) {
        if (![file hasPrefix:@"lara_"] && ![file hasPrefix:@"panic_"]) continue;
        
        NSString *filePath = [_logDirectory stringByAppendingPathComponent:file];
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:filePath error:nil];
        NSDate *modificationDate = attrs[NSFileModificationDate];
        
        if (modificationDate && [modificationDate compare:cutoffDate] == NSOrderedAscending) {
            [[NSFileManager defaultManager] removeItemAtPath:filePath error:nil];
            LARA_LOG_DEBUG(@"Cleaned up old log: %@", file);
        }
    }
}

- (void)rotateLogFiles {
    // Keep only last 10 log files
    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:_logDirectory error:nil];
    NSMutableArray *logFiles = [NSMutableArray array];
    
    for (NSString *file in files) {
        if ([file hasPrefix:@"lara_"] && [file hasSuffix:@".log"]) {
            [logFiles addObject:file];
        }
    }
    
    if (logFiles.count > 10) {
        [logFiles sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
            return [a compare:b];
        }];
        
        for (NSInteger i = 0; i < logFiles.count - 10; i++) {
            NSString *filePath = [_logDirectory stringByAppendingPathComponent:logFiles[i]];
            [[NSFileManager defaultManager] removeItemAtPath:filePath error:nil];
        }
    }
}

- (NSString *)currentLogFilePath {
    return _currentLogFile;
}

#pragma mark - Trace Helper

const char* lara_trace_enter(const char *function) {
    LARA_LOG_DEBUG(@"[TRACE] Enter: %s", [NSString stringWithUTF8String:function]);
    return function;
}

#pragma mark - NSDate Category for Colon Replacement

@implementation NSDate (LaraPanicGuard)

- (NSString *)descriptionByReplacingColonsWithUnderscores {
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd_HH-mm-ss";
    return [formatter stringFromDate:self];
}

- (NSString *)iso8601String {
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ssZ";
    return [formatter stringFromDate:self];
}

@end
