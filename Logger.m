//
//  Logger.m
//  lara
//
//  Rewritten in Objective-C (was Logger.swift)
//

#import "Logger.h"
#include <unistd.h>

static NSArray<NSString *> *ignoredSubstrings(void) {
    static NSArray *arr;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        arr = @[
            @"Faulty glyph",
            @"outline detected - replacing with a space/null glyph",
            @"Gesture: System gesture gate timed out",
            @"tcp_output [",
            @"Error Domain=",
            @"com.apple.UIKit.dragInitiation",
            @"OSLOG",
            @"_UISystemGestureGateGestureRecognizer",
            @"NSError",
            @"UITouch",
            @"com.apple",
            @"gestureRecognizers",
            @"graph: {(",
            @"UILongPressGestureRecognizer",
            @"UIScrollViewPanGestureRecognizer",
            @"UIScrollViewDelayedTouchesBeganGestureRecognizer",
            @"_UISwipeActionPanGestureRecognizer",
            @"_UISecondaryClickDriverGestureRecognizer",
            @"SwiftUI.UIHostingViewDebugLayer",
            @"ValueType:",
            @"EventType:",
            @"AttributeDataLength:",
            @"AttributeData:",
            @"SenderID:",
            @"Timestamp:",
            @"TransducerType:",
            @"TransducerIndex:",
            @"GenerationCount:",
            @"WillUpdateMask:",
            @"DidUpdateMask:",
            @"Pressure:",
            @"AuxiliaryPressure:",
            @"TiltX:",
            @"TiltY:",
            @"MajorRadius:",
            @"MinorRadius:",
            @"Accuracy:",
            @"Quality:",
            @"Density:",
            @"Irregularity:",
            @"Range:",
            @"Touch:",
            @"Events:",
            @"ChildEvents:",
            @"DisplayIntegrated:",
            @"BuiltIn:",
            @"EventMask:",
            @"ButtonMask:",
            @"Flags:",
            @"Identity:",
            @"Twist:",
            @"X:",
            @"Y:",
            @"Z:",
            @"Total Latency:",
            @"Timestamp type:",
            @"lara[",
            @"};",
        ];
    });
    return arr;
}

@interface Logger ()
@property (nonatomic, strong) NSMutableArray<NSString *> *mutableLogs;
@property (nonatomic, copy)   NSString *lastMessage;
@property (nonatomic, assign) NSInteger repeatCount;
@property (nonatomic, assign) BOOL lastWasDivider;
@property (nonatomic, assign) BOOL pendingDivider;
@property (nonatomic, strong) NSPipe *stdoutPipe;
@property (nonatomic, assign) int ogStdout;
@property (nonatomic, assign) int ogStderr;
@property (nonatomic, copy)   NSString *pending;
@property (nonatomic, strong) NSFileHandle *logFileHandle;
@property (nonatomic, copy)   NSString *logFilePath;
@end

@implementation Logger

+ (instancetype)shared {
    static Logger *instance;
    static dispatch_once_t token;
    dispatch_once(&token, ^{ instance = [[Logger alloc] init]; });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _mutableLogs = [NSMutableArray array];
        _ogStdout = -1;
        _ogStderr = -1;
        _pending = @"";
        [self setupLogFile];
    }
    return self;
}

- (NSArray<NSString *> *)logs {
    return [self.mutableLogs copy];
}

#pragma mark - Public

- (void)log:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        BOOL divEnabled = ![[NSUserDefaults standardUserDefaults] boolForKey:@"loggernobullshit"];
        if (divEnabled && self.pendingDivider) {
            [self divider];
            self.pendingDivider = NO;
        } else if (!divEnabled) {
            self.pendingDivider = NO;
            self.lastWasDivider = NO;
        }

        if ([message isEqualToString:self.lastMessage]) {
            self.repeatCount++;
            if (self.mutableLogs.count > 0) {
                self.mutableLogs[self.mutableLogs.count - 1] =
                    [NSString stringWithFormat:@"%@ (%ldx)", message, (long)(self.repeatCount + 1)];
            }
        } else {
            self.repeatCount = 0;
            if (divEnabled) {
                if (self.lastWasDivider || self.mutableLogs.count == 0) {
                    [self.mutableLogs addObject:message];
                } else {
                    self.mutableLogs[self.mutableLogs.count - 1] =
                        [self.mutableLogs.lastObject stringByAppendingFormat:@"\n%@", message];
                }
            } else {
                [self.mutableLogs addObject:message];
            }
            self.lastMessage = message;
        }
        self.lastWasDivider = NO;
    });

    [self appendToFile:@[message]];
    [self emit:message];
}

- (void)divider {
    if ([[NSUserDefaults standardUserDefaults] boolForKey:@"loggernobullshit"]) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        self.lastWasDivider = YES;
        self.lastMessage = nil;
        self.repeatCount = 0;
    });
}

- (void)enclosedLog:(NSString *)message {
    if ([[NSUserDefaults standardUserDefaults] boolForKey:@"loggernobullshit"]) {
        [self log:message];
        return;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!self.lastWasDivider && self.mutableLogs.count > 0) {
            [self divider];
        }
        if (self.lastWasDivider || self.mutableLogs.count == 0) {
            [self.mutableLogs addObject:message];
        } else {
            self.mutableLogs[self.mutableLogs.count - 1] =
                [self.mutableLogs.lastObject stringByAppendingFormat:@"\n%@", message];
        }
        self.lastWasDivider = NO;
        self.pendingDivider = YES;
    });
}

- (void)flushDivider {
    if ([[NSUserDefaults standardUserDefaults] boolForKey:@"loggernobullshit"]) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.pendingDivider) {
            [self divider];
            self.pendingDivider = NO;
        }
    });
}

- (void)clear {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.mutableLogs removeAllObjects];
        self.lastWasDivider = NO;
        self.pendingDivider = NO;
        self.lastMessage = nil;
        self.repeatCount = 0;
    });
    if (self.logFilePath) {
        [self.logFileHandle synchronizeFile];
        [self.logFileHandle closeFile];
        self.logFileHandle = nil;
        [@"" writeToFile:self.logFilePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        self.logFileHandle = [NSFileHandle fileHandleForWritingAtPath:self.logFilePath];
    }
}

#pragma mark - Capture

- (void)capture {
    if (self.stdoutPipe) return;
    [self reopenLogFileOnDemand];

    NSPipe *pipe = [NSPipe pipe];
    self.stdoutPipe = pipe;

    self.ogStdout = dup(STDOUT_FILENO);
    self.ogStderr = dup(STDERR_FILENO);

    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    dup2(pipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO);
    dup2(pipe.fileHandleForWriting.fileDescriptor, STDERR_FILENO);

    __weak typeof(self) weakSelf = self;
    pipe.fileHandleForReading.readabilityHandler = ^(NSFileHandle *handle) {
        NSData *data = handle.availableData;
        if (data.length == 0) return;
        NSString *chunk = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (chunk) [weakSelf appendRaw:chunk];
    };
}

- (void)stopCapture {
    if (!self.stdoutPipe) return;
    self.stdoutPipe.fileHandleForReading.readabilityHandler = nil;

    if (self.ogStdout != -1) {
        dup2(self.ogStdout, STDOUT_FILENO);
        close(self.ogStdout);
        self.ogStdout = -1;
    }
    if (self.ogStderr != -1) {
        dup2(self.ogStderr, STDERR_FILENO);
        close(self.ogStderr);
        self.ogStderr = -1;
    }

    [self.stdoutPipe.fileHandleForWriting closeFile];
    [self.stdoutPipe.fileHandleForReading closeFile];
    self.stdoutPipe = nil;

    [self.logFileHandle synchronizeFile];
    [self.logFileHandle closeFile];
    self.logFileHandle = nil;
}

#pragma mark - Private

- (void)appendRaw:(NSString *)chunk {
    NSString *text = [self.pending stringByAppendingString:chunk];
    NSMutableArray<NSString *> *lines = [[text componentsSeparatedByString:@"\n"] mutableCopy];
    self.pending = lines.lastObject ?: @"";
    [lines removeLastObject];

    if (lines.count == 0) return;

    // Write absolutely EVERYTHING to lara.log for debugging
    [self appendToFile:lines];

    NSMutableArray *filtered = [NSMutableArray array];
    for (NSString *line in lines) {
        if (![self shouldIgnore:line]) [filtered addObject:line];
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        [self.mutableLogs addObjectsFromArray:filtered];
    });

    for (NSString *line in filtered) [self emit:line];
}

- (void)emit:(NSString *)message {
    if ([self shouldIgnore:message]) return;
    if (self.ogStdout == -1) return;
    NSString *line = [message stringByAppendingString:@"\n"];
    const char *cstr = line.UTF8String;
    write(self.ogStdout, cstr, strlen(cstr));
}

- (BOOL)shouldIgnore:(NSString *)message {
    NSString *trimmed = [message stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (trimmed.length == 0) return YES;
    if ([self isGarbageLine:trimmed]) return YES;
    for (NSString *fragment in ignoredSubstrings()) {
        if ([message containsString:fragment]) return YES;
    }
    return NO;
}

- (BOOL)isGarbageLine:(NSString *)line {
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:
                                @"0123456789-+|*.:(){}[]/\\_ \t"];
    for (NSUInteger i = 0; i < line.length; i++) {
        unichar c = [line characterAtIndex:i];
        if (![allowed characterIsMember:c]) return NO;
    }
    return YES;
}

- (void)appendToFile:(NSArray<NSString *> *)lines {
    if (!self.logFileHandle) return;
    NSString *combined = [[lines componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
    NSData *data = [combined dataUsingEncoding:NSUTF8StringEncoding];
    if (data) [self.logFileHandle writeData:data];
}

- (void)setupLogFile {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    self.logFilePath = [docs stringByAppendingPathComponent:@"lara.log"];

    if ([[NSFileManager defaultManager] fileExistsAtPath:self.logFilePath]) {
        [[NSFileManager defaultManager] removeItemAtPath:self.logFilePath error:nil];
    }
    [[NSFileManager defaultManager] createFileAtPath:self.logFilePath contents:nil attributes:nil];
    self.logFileHandle = [NSFileHandle fileHandleForWritingAtPath:self.logFilePath];
}

- (void)reopenLogFileOnDemand {
    if (!self.logFileHandle && self.logFilePath) {
        if (![[NSFileManager defaultManager] fileExistsAtPath:self.logFilePath]) {
            [[NSFileManager defaultManager] createFileAtPath:self.logFilePath contents:nil attributes:nil];
        }
        self.logFileHandle = [NSFileHandle fileHandleForWritingAtPath:self.logFilePath];
    }
}

@end
