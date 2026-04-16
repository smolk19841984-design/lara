//
//  LaraMobAIServer.m
//  lara
//
//  Built-in HTTP server for remote control from PC (BSD sockets)
//

#import "LaraMobAIServer.h"
#import "../kexploit/term.h"
#import "../kexploit/darksword.h"
#import "../kexploit/ppl.h"
#import <UIKit/UIKit.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>

static LaraMobAIServer *g_shared = nil;

@interface LaraMobAIServer ()
@property (nonatomic, assign) int listenSocket;
@property (nonatomic, assign) BOOL shouldAccept;
@end

@implementation LaraMobAIServer

- (NSString *)handleMobAIKRead:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\"error\":\"Invalid JSON\"}"];
    NSString *addrStr = json[@"address"] ?: json[@"addr"] ?: @"";
    if (addrStr.length == 0) return [self httpResponse:400 body:@"{\"error\":\"Missing address\"}"];

    uint64_t addr = 0;
    if ([addrStr hasPrefix:@"0x"] || [addrStr hasPrefix:@"0X"]) {
        NSScanner *scanner = [NSScanner scannerWithString:addrStr];
        unsigned long long val = 0;
        [scanner scanHexLongLong:&val];
        addr = (uint64_t)val;
    } else {
        addr = (uint64_t)[addrStr longLongValue];
    }
    if (addr == 0) return [self httpResponse:400 body:@"{\"error\":\"Invalid address\"}"];

    uint64_t value = ds_kread64(addr);
    NSString *jsonResp = [NSString stringWithFormat:@"{\"address\":\"0x%016llx\",\"value\":\"0x%016llx\",\"value_dec\":\"%llu\"}", addr, value, value];
    return [self httpResponse:200 contentType:@"application/json" body:jsonResp];
}

- (NSString *)handleMobAIKWrite:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\"error\":\"Invalid JSON\"}"];
    NSString *addrStr = json[@"address"] ?: json[@"addr"] ?: @"";
    NSString *valStr = json[@"value"] ?: @"";
    if (addrStr.length == 0 || valStr.length == 0) return [self httpResponse:400 body:@"{\"error\":\"Missing address or value\"}"];

    uint64_t addr = 0, val = 0;
    if ([addrStr hasPrefix:@"0x"] || [addrStr hasPrefix:@"0X"]) {
        NSScanner *scanner = [NSScanner scannerWithString:addrStr];
        unsigned long long v = 0;
        [scanner scanHexLongLong:&v];
        addr = (uint64_t)v;
    } else {
        addr = (uint64_t)[addrStr longLongValue];
    }
    if ([valStr hasPrefix:@"0x"] || [valStr hasPrefix:@"0X"]) {
        NSScanner *scanner = [NSScanner scannerWithString:valStr];
        unsigned long long v = 0;
        [scanner scanHexLongLong:&v];
        val = (uint64_t)v;
    } else {
        val = (uint64_t)[valStr longLongValue];
    }
    if (addr == 0) return [self httpResponse:400 body:@"{\"error\":\"Invalid address\"}"];

    ds_kwrite64(addr, val);
    uint64_t verify = ds_kread64(addr);
    NSString *jsonResp = [NSString stringWithFormat:@"{\"address\":\"0x%016llx\",\"written\":\"0x%016llx\",\"verified\":\"0x%016llx\",\"match\":%@}", addr, val, verify, (verify == val) ? @"true" : @"false"];
    return [self httpResponse:200 contentType:@"application/json" body:jsonResp];
}

- (NSString *)handleMobAIKernel {
    uint64_t kbase = ds_get_kernel_base();
    uint64_t kslide = ds_get_kernel_slide();
    uint64_t kernproc = kbase ? kbase + 0x96B928ULL : 0;
    uint64_t rootvnode = kbase ? kbase + 0x3213640ULL : 0;
    NSString *jsonResp = [NSString stringWithFormat:
        @"{\"kernel_base\":\"0x%016llx\",\"kernel_slide\":\"0x%016llx\",\"kernproc\":\"0x%016llx\",\"rootvnode\":\"0x%016llx\",\"ready\":%@}",
        kbase, kslide, kernproc, rootvnode, kbase > 0 ? @"true" : @"false"];
    return [self httpResponse:200 contentType:@"application/json" body:jsonResp];
}

- (NSString *)handleMobAIPPL:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\"error\":\"Invalid JSON\"}"];
    
    NSString *action = json[@"action"] ?: @"";
    if (action.length == 0) return [self httpResponse:400 body:@"{\"error\":\"Missing action\"}"];
    
    if ([action isEqualToString:@"init"]) {
        BOOL ok = ppl_init();
        NSString *jsonResp = [NSString stringWithFormat:@"{\"action\":\"init\",\"success\":%@}", ok ? @"true" : @"false"];
        return [self httpResponse:200 contentType:@"application/json" body:jsonResp];
    }
    
    if ([action isEqualToString:@"write_kernel64"]) {
        NSString *addrStr = json[@"address"] ?: @"";
        NSString *valStr = json[@"value"] ?: @"";
        if (addrStr.length == 0 || valStr.length == 0) return [self httpResponse:400 body:@"{\"error\":\"Missing address or value\"}"];
        uint64_t addr = 0, val = 0;
        if ([addrStr hasPrefix:@"0x"] || [addrStr hasPrefix:@"0X"]) { NSScanner *s = [NSScanner scannerWithString:addrStr]; [s scanHexLongLong:&addr]; }
        else { addr = (uint64_t)[addrStr longLongValue]; }
        if ([valStr hasPrefix:@"0x"] || [valStr hasPrefix:@"0X"]) { NSScanner *s = [NSScanner scannerWithString:valStr]; [s scanHexLongLong:&val]; }
        else { val = (uint64_t)[valStr longLongValue]; }
        BOOL ok = ppl_write_kernel64(addr, val);
        uint64_t verify = ds_kread64(addr);
        NSString *jsonResp = [NSString stringWithFormat:@"{\"action\":\"write_kernel64\",\"address\":\"0x%016llx\",\"written\":\"0x%016llx\",\"verified\":\"0x%016llx\",\"success\":%@}", addr, val, verify, (ok && verify == val) ? @"true" : @"false"];
        return [self httpResponse:200 contentType:@"application/json" body:jsonResp];
    }
    
    if ([action isEqualToString:@"sandbox_escape"]) {
        NSString *procStr = json[@"proc"] ?: @"";
        if (procStr.length == 0) return [self httpResponse:400 body:@"{\"error\":\"Missing proc address\"}"];
        uint64_t proc = 0;
        if ([procStr hasPrefix:@"0x"] || [procStr hasPrefix:@"0X"]) { NSScanner *s = [NSScanner scannerWithString:procStr]; [s scanHexLongLong:&proc]; }
        else { proc = (uint64_t)[procStr longLongValue]; }
        BOOL ok = ppl_data_only_attack_sandbox(proc);
        NSString *jsonResp = [NSString stringWithFormat:@"{\"action\":\"sandbox_escape\",\"proc\":\"0x%016llx\",\"success\":%@}", proc, ok ? @"true" : @"false"];
        return [self httpResponse:200 contentType:@"application/json" body:jsonResp];
    }
    
    if ([action isEqualToString:@"rollback"]) {
        BOOL ok = ppl_rollback_last();
        NSString *jsonResp = [NSString stringWithFormat:@"{\"action\":\"rollback\",\"success\":%@}", ok ? @"true" : @"false"];
        return [self httpResponse:200 contentType:@"application/json" body:jsonResp];
    }
    
    return [self httpResponse:400 body:@"{\"error\":\"Unknown action\"}"];
}

+ (instancetype)shared {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_shared = [[LaraMobAIServer alloc] init];
    });
    return g_shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _listenSocket = -1;
        _shouldAccept = NO;
    }
    return self;
}

- (BOOL)startOnPort:(NSInteger)port error:(NSError **)error {
    if (_isRunning) return YES;

    signal(SIGPIPE, SIG_IGN);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        if (error) *error = [NSError errorWithDomain:@"LaraMobAI" code:errno userInfo:@{NSLocalizedDescriptionKey: @(strerror(errno))}];
        return NO;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (error) *error = [NSError errorWithDomain:@"LaraMobAI" code:errno userInfo:@{NSLocalizedDescriptionKey: @(strerror(errno))}];
        close(sock);
        return NO;
    }

    if (listen(sock, 5) < 0) {
        if (error) *error = [NSError errorWithDomain:@"LaraMobAI" code:errno userInfo:@{NSLocalizedDescriptionKey: @(strerror(errno))}];
        close(sock);
        return NO;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    _listenSocket = sock;
    _port = port;
    _isRunning = YES;
    _shouldAccept = YES;

    NSLog(@"[MobAI] HTTP server started on port %ld", (long)port);

    [self acceptLoop];
    return YES;
}

- (void)stop {
    if (!_isRunning) return;
    _isRunning = NO;
    _shouldAccept = NO;
    if (_listenSocket >= 0) {
        close(_listenSocket);
        _listenSocket = -1;
    }
    NSLog(@"[MobAI] HTTP server stopped");
}

- (void)acceptLoop {
    if (!_shouldAccept) return;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        while (self->_shouldAccept && self->_listenSocket >= 0) {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            int clientSock = accept(self->_listenSocket, (struct sockaddr *)&clientAddr, &clientLen);
            if (clientSock < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    usleep(50000);
                    continue;
                }
                break;
            }

            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [self handleClient:clientSock];
                close(clientSock);
            });
        }
    });
}

- (void)handleClient:(int)sock {
    NSMutableData *buffer = [NSMutableData data];
    uint8_t readBuf[4096];
    BOOL headersComplete = NO;
    NSString *requestStr = nil;

    while (!headersComplete) {
        ssize_t n = read(sock, readBuf, sizeof(readBuf));
        if (n <= 0) return;
        [buffer appendBytes:readBuf length:(size_t)n];

        NSString *partial = [[NSString alloc] initWithData:buffer encoding:NSUTF8StringEncoding];
        if (partial && [partial containsString:@"\r\n\r\n"]) {
            headersComplete = YES;
            requestStr = partial;
        }
    }

    if (!requestStr) return;

    NSUInteger contentLength = 0;
    NSArray *lines = [requestStr componentsSeparatedByString:@"\r\n"];
    for (NSString *line in lines) {
        if ([line hasPrefix:@"Content-Length:"]) {
            NSArray *kv = [line componentsSeparatedByString:@":"];
            NSString *val = [[kv objectAtIndex:1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            contentLength = (NSUInteger)[val integerValue];
        }
        if ([line isEqualToString:@""]) break;
    }

    if (contentLength > 0) {
        size_t alreadyRead = buffer.length;
        size_t headerEnd = [requestStr rangeOfString:@"\r\n\r\n"].location + 4;
        size_t bodyAlready = alreadyRead > headerEnd ? alreadyRead - headerEnd : 0;
        size_t remaining = contentLength > bodyAlready ? contentLength - bodyAlready : 0;

        while (remaining > 0) {
            ssize_t n = read(sock, readBuf, MIN(remaining, sizeof(readBuf)));
            if (n <= 0) break;
            [buffer appendBytes:readBuf length:(size_t)n];
            remaining -= (size_t)n;
        }
    }

    NSString *fullRequest = [[NSString alloc] initWithData:buffer encoding:NSUTF8StringEncoding];
    if (!fullRequest) return;

    // Check if this is a screenshot request - handle separately with raw binary
    if ([fullRequest containsString:@"GET /screenshot"]) {
        // Capture screenshot on main thread asynchronously
        __block NSData *pngData = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_main_queue(), ^{
            @autoreleasepool {
                CGSize size = [UIScreen mainScreen].bounds.size;
                UIGraphicsBeginImageContextWithOptions(size, NO, 0.0);
                for (UIWindow *window in [UIApplication sharedApplication].windows) {
                    if (window.windowLevel == UIWindowLevelNormal) {
                        [window.layer renderInContext:UIGraphicsGetCurrentContext()];
                    }
                }
                UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
                UIGraphicsEndImageContext();
                if (img) {
                    pngData = UIImagePNGRepresentation(img);
                }
            }
            dispatch_semaphore_signal(sem);
        });
        // Wait up to 5 seconds for screenshot
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

        if (pngData) {
            NSString *headers = [NSString stringWithFormat:
                @"HTTP/1.1 200 OK\r\n"
                @"Content-Type: image/png\r\n"
                @"Content-Length: %lu\r\n"
                @"Access-Control-Allow-Origin: *\r\n"
                @"Connection: close\r\n"
                @"\r\n",
                (unsigned long)pngData.length];
            NSData *headerData = [headers dataUsingEncoding:NSUTF8StringEncoding];
            const uint8_t *p = headerData.bytes;
            size_t remaining = headerData.length;
            while (remaining > 0) {
                ssize_t n = write(sock, p, remaining);
                if (n <= 0) break;
                p += n;
                remaining -= n;
            }
            p = pngData.bytes;
            remaining = pngData.length;
            while (remaining > 0) {
                ssize_t n = write(sock, p, remaining);
                if (n <= 0) break;
                p += n;
                remaining -= n;
            }
        } else {
            NSString *err = @"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nScreenshot failed";
            NSData *errData = [err dataUsingEncoding:NSUTF8StringEncoding];
            write(sock, errData.bytes, errData.length);
        }
        return;
    }

    NSString *response = [self handleRequest:fullRequest];
    NSData *responseData = [response dataUsingEncoding:NSUTF8StringEncoding];
    if (responseData) {
        const uint8_t *p = responseData.bytes;
        size_t remaining = responseData.length;
        while (remaining > 0) {
            ssize_t n = write(sock, p, remaining);
            if (n <= 0) break;
            p += n;
            remaining -= n;
        }
    }
}

- (NSString *)handleRequest:(NSString *)request {
    NSArray *lines = [request componentsSeparatedByString:@"\r\n"];
    if (lines.count == 0) return [self httpResponse:400 body:@"Bad Request"];

    NSString *firstLine = lines[0];
    NSArray *parts = [firstLine componentsSeparatedByString:@" "];
    if (parts.count < 2) return [self httpResponse:400 body:@"Bad Request"];

    NSString *method = parts[0];
    NSString *path = parts[1];

    NSString *body = @"";
    BOOL inBody = NO;
    for (NSString *line in lines) {
        if (inBody) {
            body = [body length] > 0 ? [body stringByAppendingString:@"\n"] : @"";
            body = [body stringByAppendingString:line];
        }
        if ([line isEqualToString:@""]) {
            inBody = YES;
        }
    }

    NSLog(@"[MobAI] %@ %@", method, path);

    if ([method isEqualToString:@"GET"]) {
        if ([path isEqualToString:@"/"] || [path isEqualToString:@"/info"]) {
            return [self handleInfo];
        } else if ([path isEqualToString:@"/screenshot"]) {
            return [self handleScreenshot];
        } else if ([path isEqualToString:@"/ui"]) {
            return [self handleUI];
        } else if ([path isEqualToString:@"/health"]) {
            return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"ok\"}"];
        }
    } else if ([method isEqualToString:@"POST"]) {
        if ([path isEqualToString:@"/tap"]) {
            return [self handleTap:body];
        } else if ([path isEqualToString:@"/swipe"]) {
            return [self handleSwipe:body];
        } else if ([path isEqualToString:@"/type"]) {
            return [self handleType:body];
        } else if ([path isEqualToString:@"/term"]) {
            return [self handleTerm:body];
        } else if ([path isEqualToString:@"/key"]) {
            return [self handleKey:body];
        }
    }

    // MobAI API v1 routes
    if ([path hasPrefix:@"/api/v1/"]) {
        NSString *route = [path substringFromIndex:@"/api/v1/".length];
        if ([method isEqualToString:@"GET"]) {
            if ([route isEqualToString:@"info"]) return [self handleMobAIInfo];
            if ([route isEqualToString:@"screenshot"]) return [self handleMobAIScreenshot];
            if ([route isEqualToString:@"ui"]) return [self handleMobAIUI];
            if ([route isEqualToString:@"health"]) return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"ok\"}"];
            if ([route isEqualToString:@"device"]) return [self handleMobAIDevice];
            if ([route isEqualToString:@"status"]) return [self handleMobAIStatus];
            if ([route isEqualToString:@"accessibility"]) return [self handleMobAIAccessibility];
            if ([route isEqualToString:@"kernel"]) return [self handleMobAIKernel];
        } else if ([method isEqualToString:@"POST"]) {
            if ([route isEqualToString:@"tap"]) return [self handleMobAITap:body];
            if ([route isEqualToString:@"swipe"]) return [self handleMobAISwipe:body];
            if ([route isEqualToString:@"type"]) return [self handleMobAIType:body];
            if ([route isEqualToString:@"key"]) return [self handleMobAIKey:body];
            if ([route isEqualToString:@"dsl"]) return [self handleMobAIDSL:body];
            if ([route isEqualToString:@"term"]) return [self handleMobAITerm:body];
            if ([route isEqualToString:@"wait"]) return [self handleMobAIWait:body];
            if ([route isEqualToString:@"assert"]) return [self handleMobAIAssert:body];
            if ([route isEqualToString:@"longpress"]) return [self handleMobAILongPress:body];
            if ([route isEqualToString:@"scroll"]) return [self handleMobAIScroll:body];
            if ([route isEqualToString:@"kread"]) return [self handleMobAIKRead:body];
            if ([route isEqualToString:@"kwrite"]) return [self handleMobAIKWrite:body];
            if ([route isEqualToString:@"ppl"]) return [self handleMobAIPPL:body];
        }
    }

    return [self httpResponse:404 body:@"{\"error\":\"Not Found\"}"];
}

- (NSString *)handleInfo {
    struct utsname u;
    uname(&u);

    NSString *deviceModel = @(u.machine);
    NSString *osVersion = [[UIDevice currentDevice] systemVersion];
    NSString *deviceName = [[UIDevice currentDevice] name];
    CGSize screen = [UIScreen mainScreen].bounds.size;

    NSString *json = [NSString stringWithFormat:
        @"{\"device\":\"%@\",\"os\":\"%@\",\"name\":\"%@\",\"screen\":{\"w\":%.0f,\"h\":%.0f},\"status\":\"running\"}",
        deviceModel, osVersion, deviceName, screen.width, screen.height];

    return [self httpResponse:200 contentType:@"application/json" body:json];
}

- (NSString *)handleScreenshot {
    __block NSData *pngData = nil;
    dispatch_sync(dispatch_get_main_queue(), ^{
        UIGraphicsBeginImageContextWithOptions([UIScreen mainScreen].bounds.size, NO, 0.0);
        CGContextRef ctx = UIGraphicsGetCurrentContext();
        for (UIWindow *window in [UIApplication sharedApplication].windows) {
            if (window.windowLevel == UIWindowLevelNormal) {
                [window.layer renderInContext:ctx];
            }
        }
        UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
        UIGraphicsEndImageContext();
        if (img) {
            pngData = UIImagePNGRepresentation(img);
        }
    });

    if (!pngData) {
        return [self httpResponse:500 body:@"Screenshot failed"];
    }

    NSString *b64 = [pngData base64EncodedStringWithOptions:0];
    NSString *json = [NSString stringWithFormat:@"{\"screenshot\":\"%@\",\"type\":\"png\"}", b64];

    return [self httpResponse:200 contentType:@"application/json" body:json];
}

- (NSString *)handleUI {
    __block NSMutableArray *elements = nil;
    dispatch_sync(dispatch_get_main_queue(), ^{
        elements = [NSMutableArray array];
        for (UIWindow *window in [UIApplication sharedApplication].windows) {
            if (window.isKeyWindow || window.windowLevel == UIWindowLevelNormal) {
                [self collectUIElementsFromView:window intoArray:elements depth:0];
                break;
            }
        }
    });

    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:elements options:0 error:nil];
    NSString *jsonStr = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];

    return [self httpResponse:200 contentType:@"application/json" body:jsonStr ?: @"[]"];
}

- (void)collectUIElementsFromView:(UIView *)view intoArray:(NSMutableArray *)array depth:(int)depth {
    if (depth > 10) return;

    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"type"] = NSStringFromClass([view class]);
    dict[@"frame"] = NSStringFromCGRect(view.frame);

    if (view.accessibilityLabel.length > 0) dict[@"label"] = view.accessibilityLabel;
    if (view.accessibilityValue.length > 0) dict[@"value"] = view.accessibilityValue;
    if (view.accessibilityHint.length > 0) dict[@"hint"] = view.accessibilityHint;
    if ([view isKindOfClass:[UIButton class]]) {
        UIButton *btn = (UIButton *)view;
        if (btn.currentTitle.length > 0) dict[@"title"] = btn.currentTitle;
    }
    if ([view isKindOfClass:[UILabel class]]) {
        UILabel *lbl = (UILabel *)view;
        if (lbl.text.length > 0) dict[@"text"] = lbl.text;
    }
    if ([view isKindOfClass:[UITextField class]]) {
        UITextField *tf = (UITextField *)view;
        if (tf.text.length > 0) dict[@"text"] = tf.text;
    }
    dict[@"isButton"] = @([view isKindOfClass:[UIButton class]]);
    dict[@"isTextField"] = @([view isKindOfClass:[UITextField class]]);
    dict[@"isLabel"] = @([view isKindOfClass:[UILabel class]]);
    dict[@"isVisible"] = @(!view.isHidden && view.alpha > 0);

    if (view.subviews.count > 0 && depth < 8) {
        NSMutableArray *children = [NSMutableArray array];
        for (UIView *sub in view.subviews) {
            if (!sub.isHidden && sub.alpha > 0) {
                [self collectUIElementsFromView:sub intoArray:children depth:depth + 1];
            }
        }
        if (children.count > 0) dict[@"children"] = children;
    }

    [array addObject:dict];
}

- (NSString *)handleTap:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"Invalid JSON"];

    dispatch_async(dispatch_get_main_queue(), ^{
        if (json[@"x"] && json[@"y"]) {
            CGFloat x = [json[@"x"] doubleValue];
            CGFloat y = [json[@"y"] doubleValue];
            [self tapAtPoint:CGPointMake(x, y)];
        } else if (json[@"text"]) {
            [self tapByText:json[@"text"]];
        }
    });

    return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"ok\"}"];
}

- (void)tapAtPoint:(CGPoint)point {
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    if (!keyWindow) return;

    UIView *target = [keyWindow hitTest:point withEvent:nil];
    if (!target) return;

    if ([target isKindOfClass:[UIControl class]]) {
        [(UIControl *)target sendActionsForControlEvents:UIControlEventTouchUpInside];
    } else if ([target respondsToSelector:@selector(touchesBegan:withEvent:)]) {
        NSSet *touches = [NSSet setWithObject:[[NSObject alloc] init]];
        [target touchesBegan:touches withEvent:nil];
        [target touchesEnded:touches withEvent:nil];
    }
}

- (void)tapByText:(NSString *)text {
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    if (!keyWindow) return;
    [self findAndTapText:text inView:keyWindow];
}

- (BOOL)findAndTapText:(NSString *)text inView:(UIView *)view {
    BOOL match = NO;
    if ([view.accessibilityLabel isEqualToString:text]) match = YES;
    if ([view.accessibilityValue isEqualToString:text]) match = YES;
    if ([view isKindOfClass:[UIButton class]]) {
        if ([((UIButton *)view).currentTitle isEqualToString:text]) match = YES;
    }
    if ([view isKindOfClass:[UILabel class]]) {
        if ([((UILabel *)view).text isEqualToString:text]) match = YES;
    }

    if (match) {
        if ([view isKindOfClass:[UIControl class]]) {
            [(UIControl *)view sendActionsForControlEvents:UIControlEventTouchUpInside];
        }
        return YES;
    }

    for (UIView *sub in view.subviews) {
        if ([self findAndTapText:text inView:sub]) return YES;
    }
    return NO;
}

- (NSString *)handleSwipe:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"Invalid JSON"];

    NSString *direction = json[@"direction"] ?: @"up";

    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
        if (!keyWindow) return;

        CGFloat w = keyWindow.bounds.size.width;
        CGFloat h = keyWindow.bounds.size.height;
        CGFloat cx = w / 2;
        CGFloat cy = h / 2;

        CGPoint from = CGPointMake(cx, cy);
        CGPoint to = CGPointMake(cx, cy);

        CGFloat offset = MIN(w, h) * 0.3;
        if ([direction isEqualToString:@"up"]) to.y -= offset;
        else if ([direction isEqualToString:@"down"]) to.y += offset;
        else if ([direction isEqualToString:@"left"]) to.x -= offset;
        else if ([direction isEqualToString:@"right"]) to.x += offset;

        [self swipeFrom:from to:to inView:keyWindow];
    });

    return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"ok\"}"];
}

- (void)swipeFrom:(CGPoint)from to:(CGPoint)to inView:(UIView *)view {
    if ([view isKindOfClass:[UIScrollView class]]) {
        UIScrollView *sv = (UIScrollView *)view;
        CGPoint offset = sv.contentOffset;
        offset.x += (from.x - to.x);
        offset.y += (from.y - to.y);
        [sv setContentOffset:offset animated:YES];
    } else {
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:nil action:nil];
        [view addGestureRecognizer:pan];
        [pan setState:UIGestureRecognizerStateBegan];
        [pan setTranslation:from inView:view];
        [pan setState:UIGestureRecognizerStateChanged];
        [pan setTranslation:to inView:view];
        [pan setState:UIGestureRecognizerStateEnded];
        [view removeGestureRecognizer:pan];
    }
}

- (NSString *)handleType:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"Invalid JSON"];

    NSString *text = json[@"text"] ?: @"";

    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
        if (!keyWindow) return;

        UITextField *tf = [self findFirstResponder:keyWindow];
        if (tf) {
            tf.text = text;
            [tf sendActionsForControlEvents:UIControlEventEditingChanged];
        } else {
            tf = [self findAnyTextField:keyWindow];
            if (tf) {
                [tf becomeFirstResponder];
                tf.text = text;
                [tf sendActionsForControlEvents:UIControlEventEditingChanged];
            }
        }
    });

    return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"ok\"}"];
}

- (UITextField *)findFirstResponder:(UIView *)view {
    if (view.isFirstResponder && [view isKindOfClass:[UITextField class]]) return (UITextField *)view;
    for (UIView *sub in view.subviews) {
        UITextField *tf = [self findFirstResponder:sub];
        if (tf) return tf;
    }
    return nil;
}

- (UITextField *)findAnyTextField:(UIView *)view {
    if ([view isKindOfClass:[UITextField class]]) return (UITextField *)view;
    for (UIView *sub in view.subviews) {
        UITextField *tf = [self findAnyTextField:sub];
        if (tf) return tf;
    }
    return nil;
}

- (NSString *)handleTerm:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"Invalid JSON"];

    NSString *cmd = json[@"cmd"] ?: @"";
    if (cmd.length == 0) return [self httpResponse:400 body:@"Empty command"];

    size_t outLen = 0;
    char *result = term_exec(cmd.UTF8String, &outLen);

    NSString *output = @"";
    if (result && outLen > 0) {
        output = [[NSString alloc] initWithBytes:result length:outLen encoding:NSUTF8StringEncoding] ?: @"";
        free(result);
    }

    output = [output stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
    output = [output stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
    output = [output stringByReplacingOccurrencesOfString:@"\n" withString:@"\\n"];
    output = [output stringByReplacingOccurrencesOfString:@"\r" withString:@"\\r"];
    output = [output stringByReplacingOccurrencesOfString:@"\t" withString:@"\\t"];

    NSString *jsonResp = [NSString stringWithFormat:@"{\"output\":\"%@\"}", output];
    return [self httpResponse:200 contentType:@"application/json" body:jsonResp];
}

- (NSString *)handleKey:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"Invalid JSON"];

    NSString *key = json[@"key"] ?: @"";

    dispatch_async(dispatch_get_main_queue(), ^{
        if ([key isEqualToString:@"enter"] || [key isEqualToString:@"return"]) {
            UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
            UITextField *tf = [self findFirstResponder:keyWindow];
            if (tf && [tf.delegate respondsToSelector:@selector(textFieldShouldReturn:)]) {
                if ([tf.delegate textFieldShouldReturn:tf]) {
                    [tf resignFirstResponder];
                }
            }
        } else if ([key isEqualToString:@"backspace"]) {
            UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
            UITextField *tf = [self findFirstResponder:keyWindow];
            if (tf && tf.text.length > 0) {
                tf.text = [tf.text substringToIndex:tf.text.length - 1];
                [tf sendActionsForControlEvents:UIControlEventEditingChanged];
            }
        }
    });

    return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"ok\"}"];
}

- (NSDictionary *)parseJSON:(NSString *)body {
    if (!body || body.length == 0) return nil;
    NSData *data = [body dataUsingEncoding:NSUTF8StringEncoding];
    return [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
}

- (NSString *)httpResponse:(NSInteger)status body:(NSString *)body {
    return [self httpResponse:status contentType:@"text/plain" body:body];
}

- (NSString *)httpResponse:(NSInteger)status contentType:(NSString *)contentType body:(NSString *)body {
    NSString *statusText = @"OK";
    if (status == 400) statusText = @"Bad Request";
    else if (status == 404) statusText = @"Not Found";
    else if (status == 500) statusText = @"Internal Server Error";

    return [NSString stringWithFormat:
        @"HTTP/1.1 %ld %@\r\n"
         @"Content-Type: %@\r\n"
         @"Content-Length: %lu\r\n"
         @"Access-Control-Allow-Origin: *\r\n"
         @"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
         @"Access-Control-Allow-Headers: Content-Type\r\n"
         @"\r\n"
         @"%@",
        (long)status, statusText, contentType,
        (unsigned long)[body lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
        body];
}

// ============================================================
// MobAI API v1 Handlers
// ============================================================

- (NSString *)handleMobAIInfo {
    struct utsname u; uname(&u);
    NSString *json = [NSString stringWithFormat:@"{\"device\":\"%@\",\"os\":\"%@\",\"name\":\"%@\",\"screen\":{\"w\":%.0f,\"h\":%.0f},\"platform\":\"ios\",\"status\":\"running\"}", @(u.machine), [[UIDevice currentDevice] systemVersion], [[UIDevice currentDevice] name], [UIScreen mainScreen].bounds.size.width, [UIScreen mainScreen].bounds.size.height];
    return [self httpResponse:200 contentType:@"application/json" body:json];
}

- (NSString *)handleMobAIScreenshot {
    __block NSData *pngData = nil;
    dispatch_sync(dispatch_get_main_queue(), ^{
        UIGraphicsBeginImageContextWithOptions([UIScreen mainScreen].bounds.size, NO, 0.0);
        for (UIWindow *window in [UIApplication sharedApplication].windows) {
            if (window.windowLevel == UIWindowLevelNormal) [window.layer renderInContext:UIGraphicsGetCurrentContext()];
        }
        UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
        UIGraphicsEndImageContext();
        if (img) pngData = UIImagePNGRepresentation(img);
    });
    if (!pngData) return [self httpResponse:500 body:@"{\"error\":\"Screenshot failed\"}"];
    NSString *b64 = [pngData base64EncodedStringWithOptions:0];
    NSString *json = [NSString stringWithFormat:@"{\"screenshot\":\"data:image/png;base64,%@\",\"type\":\"png\",\"width\":%.0f,\"height\":%.0f}", b64, [UIScreen mainScreen].bounds.size.width, [UIScreen mainScreen].bounds.size.height];
    return [self httpResponse:200 contentType:@"application/json" body:json];
}

- (NSString *)handleMobAIUI {
    __block NSMutableArray *elements = nil;
    dispatch_sync(dispatch_get_main_queue(), ^{
        elements = [NSMutableArray array];
        for (UIWindow *window in [UIApplication sharedApplication].windows) {
            if (window.isKeyWindow || window.windowLevel == UIWindowLevelNormal) {
                [self collectUIElementsFromView:window intoArray:elements depth:0];
                break;
            }
        }
    });
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:elements options:0 error:nil];
    NSString *jsonStr = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    return [self httpResponse:200 contentType:@"application/json" body:jsonStr ?: @"[]"];
}

- (NSString *)handleMobAIDevice {
    struct utsname u; uname(&u);
    NSString *json = [NSString stringWithFormat:@"{\"model\":\"%@\",\"os\":\"%@\",\"name\":\"%@\",\"platform\":\"ios\",\"screen\":{\"width\":%.0f,\"height\":%.0f,\"scale\":%.1f}}", @(u.machine), [[UIDevice currentDevice] systemVersion], [[UIDevice currentDevice] name], [UIScreen mainScreen].bounds.size.width, [UIScreen mainScreen].bounds.size.height, [UIScreen mainScreen].scale];
    return [self httpResponse:200 contentType:@"application/json" body:json];
}

- (NSString *)handleMobAIStatus {
    return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"running\",\"device_connected\":true,\"platform\":\"ios\",\"server\":\"lara-mobai\",\"version\":\"1.0.0\"}"];
}

- (NSString *)handleMobAIAccessibility {
    __block NSMutableArray *elements = nil;
    dispatch_sync(dispatch_get_main_queue(), ^{
        elements = [NSMutableArray array];
        for (UIWindow *window in [UIApplication sharedApplication].windows) {
            if (window.isKeyWindow || window.windowLevel == UIWindowLevelNormal) {
                [self collectAccessibilityElementsFromView:window intoArray:elements];
                break;
            }
        }
    });
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:elements options:0 error:nil];
    NSString *jsonStr = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    return [self httpResponse:200 contentType:@"application/json" body:jsonStr ?: @"[]"];
}

- (NSString *)handleMobAITap:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\"error\":\"Invalid JSON\"}"];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (json[@"x"] && json[@"y"]) [self tapAtPoint:CGPointMake([json[@"x"] doubleValue], [json[@"y"] doubleValue])];
        else if (json[@"text"]) [self tapByText:json[@"text"]];
        else if (json[@"label"]) [self tapByAccessibilityLabel:json[@"label"]];
    });
    return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"ok\"}"];
}

- (NSString *)handleMobAISwipe:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\"error\":\"Invalid JSON\"}"];
    NSString *direction = json[@"direction"] ?: @"up";
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
        if (!keyWindow) return;
        CGFloat w = keyWindow.bounds.size.width, h = keyWindow.bounds.size.height;
        CGFloat fromX = json[@"fromX"] ? [json[@"fromX"] doubleValue] : w/2;
        CGFloat fromY = json[@"fromY"] ? [json[@"fromY"] doubleValue] : h/2;
        CGFloat toX = json[@"toX"] ? [json[@"toX"] doubleValue] : fromX;
        CGFloat toY = json[@"toY"] ? [json[@"toY"] doubleValue] : fromY;
        if (![json objectForKey:@"fromX"] && ![json objectForKey:@"toX"]) {
            CGFloat offset = MIN(w, h) * 0.3;
            if ([direction isEqualToString:@"up"]) toY -= offset;
            else if ([direction isEqualToString:@"down"]) toY += offset;
            else if ([direction isEqualToString:@"left"]) toX -= offset;
            else if ([direction isEqualToString:@"right"]) toX += offset;
        }
        [self swipeFrom:CGPointMake(fromX, fromY) to:CGPointMake(toX, toY) inView:keyWindow];
    });
    return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"ok\"}"];
}

- (NSString *)handleMobAIType:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\"error\":\"Invalid JSON\"}"];
    NSString *text = json[@"text"] ?: @"";
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
        if (!keyWindow) return;
        UITextField *tf = [self findFirstResponder:keyWindow];
        if (!tf) { tf = [self findAnyTextField:keyWindow]; if (tf) [tf becomeFirstResponder]; }
        if (tf) { tf.text = [tf.text stringByAppendingString:text]; [tf sendActionsForControlEvents:UIControlEventEditingChanged]; }
    });
    return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"ok\"}"];
}

- (NSString *)handleMobAIKey:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\"error\":\"Invalid JSON\"}"];
    NSString *key = json[@"key"] ?: @"";
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
        if ([key isEqualToString:@"enter"] || [key isEqualToString:@"return"]) {
            UITextField *tf = [self findFirstResponder:keyWindow];
            if (tf && [tf.delegate respondsToSelector:@selector(textFieldShouldReturn:)]) { if ([tf.delegate textFieldShouldReturn:tf]) [tf resignFirstResponder]; }
        } else if ([key isEqualToString:@"backspace"]) {
            UITextField *tf = [self findFirstResponder:keyWindow];
            if (tf && tf.text.length > 0) { tf.text = [tf.text substringToIndex:tf.text.length - 1]; [tf sendActionsForControlEvents:UIControlEventEditingChanged]; }
        } else if ([key isEqualToString:@"escape"]) { [keyWindow endEditing:YES]; }
    });
    return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"ok\"}"];
}

- (NSString *)handleMobAIDSL:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\"error\":\"Invalid JSON\"}"];
    NSString *script = json[@"script"] ?: json[@"dsl"] ?: @"";
    if (script.length == 0) return [self httpResponse:400 body:@"{\"error\":\"Empty script\"}"];
    NSError *dslError = nil;
    NSDictionary *result = [self executeDSL:script error:&dslError];
    if (dslError) {
        NSString *errJson = [NSString stringWithFormat:@"{\"error\":\"%@\",\"status\":\"failed\"}", dslError.localizedDescription];
        return [self httpResponse:400 contentType:@"application/json" body:errJson];
    }
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
    NSString *jsonStr = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    return [self httpResponse:200 contentType:@"application/json" body:jsonStr ?: @"{\"status\":\"ok\"}"];
}

- (NSString *)handleMobAITerm:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\"error\":\"Invalid JSON\"}"];
    NSString *cmd = json[@"cmd"] ?: @"";
    if (cmd.length == 0) return [self httpResponse:400 body:@"{\"error\":\"Empty command\"}"];
    size_t outLen = 0;
    char *result = term_exec(cmd.UTF8String, &outLen);
    NSString *output = @"";
    if (result && outLen > 0) { output = [[NSString alloc] initWithBytes:result length:outLen encoding:NSUTF8StringEncoding] ?: @""; free(result); }
    NSData *outputData = [output dataUsingEncoding:NSUTF8StringEncoding];
    NSString *b64 = [outputData base64EncodedStringWithOptions:0];
    NSString *jsonResp = [NSString stringWithFormat:@"{\"output\":\"%@\",\"output_base64\":\"%@\",\"exit_code\":0}", output, b64];
    return [self httpResponse:200 contentType:@"application/json" body:jsonResp];
}

- (NSString *)handleMobAIWait:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\"error\":\"Invalid JSON\"}"];
    NSTimeInterval seconds = [json[@"seconds"] doubleValue] ?: [json[@"duration"] doubleValue] ?: 1.0;
    dispatch_sync(dispatch_get_main_queue(), ^{
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:seconds]];
    });
    NSString *jsonResp = [NSString stringWithFormat:@"{\"status\":\"ok\",\"waited\":%f}", seconds];
    return [self httpResponse:200 contentType:@"application/json" body:jsonResp];
}

- (NSString *)handleMobAIAssert:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\"error\":\"Invalid JSON\"}"];
    __block BOOL found = NO;
    NSString *text = json[@"text"] ?: json[@"label"] ?: @"";
    dispatch_sync(dispatch_get_main_queue(), ^{
        for (UIWindow *window in [UIApplication sharedApplication].windows) {
            if (window.windowLevel == UIWindowLevelNormal) { found = [self findElementByText:text inView:window]; break; }
        }
    });
    if (found) return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"passed\"}"];
    NSString *errJson = [NSString stringWithFormat:@"{\"status\":\"failed\",\"error\":\"Element '%@' not found\"}", text];
    return [self httpResponse:400 contentType:@"application/json" body:errJson];
}

- (NSString *)handleMobAILongPress:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\"error\":\"Invalid JSON\"}"];
    CGFloat x = json[@"x"] ? [json[@"x"] doubleValue] : [UIScreen mainScreen].bounds.size.width / 2;
    CGFloat y = json[@"y"] ? [json[@"y"] doubleValue] : [UIScreen mainScreen].bounds.size.height / 2;
    NSTimeInterval duration = [json[@"duration"] doubleValue] ?: 1.0;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
        if (!keyWindow) return;
        UIView *target = [keyWindow hitTest:CGPointMake(x, y) withEvent:nil];
        if (!target) return;
        if ([target isKindOfClass:[UIControl class]]) {
            UIControl *control = (UIControl *)target;
            [control sendActionsForControlEvents:UIControlEventTouchDown];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(duration * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [control sendActionsForControlEvents:UIControlEventTouchUpInside];
            });
        }
    });
    return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"ok\"}"];
}

- (NSString *)handleMobAIScroll:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\"error\":\"Invalid JSON\"}"];
    NSString *direction = json[@"direction"] ?: @"down";
    CGFloat distance = [json[@"distance"] doubleValue] ?: 200.0;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
        if (!keyWindow) return;
        UIScrollView *scrollView = [self findScrollView:keyWindow];
        if (scrollView) {
            CGPoint offset = scrollView.contentOffset;
            if ([direction isEqualToString:@"up"]) offset.y -= distance;
            else if ([direction isEqualToString:@"down"]) offset.y += distance;
            else if ([direction isEqualToString:@"left"]) offset.x -= distance;
            else if ([direction isEqualToString:@"right"]) offset.x += distance;
            [scrollView setContentOffset:offset animated:YES];
        }
    });
    return [self httpResponse:200 contentType:@"application/json" body:@"{\"status\":\"ok\"}"];
}

// ============================================================
// DSL Parser and Executor (MobAI Script .mob format)
// ============================================================

- (NSDictionary *)executeDSL:(NSString *)script error:(NSError **)error {
    NSMutableArray *results = [NSMutableArray array];
    NSArray *lines = [script componentsSeparatedByString:@"\n"];
    NSInteger lineNum = 0, passed = 0, failed = 0;
    for (NSString *rawLine in lines) {
        lineNum++;
        NSString *line = [rawLine stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (line.length == 0 || [line hasPrefix:@"#"]) continue;
        NSDictionary *result = [self executeDSLLine:line lineNumber:lineNum];
        [results addObject:result];
        if ([result[@"status"] isEqualToString:@"ok"]) { passed++; }
        else {
            failed++;
            if (error) *error = [NSError errorWithDomain:@"LaraMobAI-DSL" code:lineNum userInfo:@{NSLocalizedDescriptionKey: result[@"error"] ?: @"Unknown error"}];
            break;
        }
    }
    return @{@"status": failed > 0 ? @"failed" : @"passed", @"total": @(lineNum), @"passed": @(passed), @"failed": @(failed), @"results": results};
}

- (NSDictionary *)executeDSLLine:(NSString *)line lineNumber:(NSInteger)lineNum {
    NSString *command = nil, *arg1 = nil, *arg2 = nil;
    NSRange arrowRange = [line rangeOfString:@"->"];
    if (arrowRange.location != NSNotFound) {
        NSString *beforeArrow = [line substringToIndex:arrowRange.location];
        NSString *afterArrow = [line substringFromIndex:NSMaxRange(arrowRange)];
        NSArray *cmdParts = [self parseDSLCommand:beforeArrow];
        command = cmdParts[0]; arg1 = cmdParts[1];
        arg2 = [afterArrow stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        arg2 = [self stripQuotes:arg2];
    } else {
        NSArray *cmdParts = [self parseDSLCommand:line];
        command = cmdParts[0]; arg1 = cmdParts[1];
    }
    if (!command) return @{@"status": @"error", @"error": [NSString stringWithFormat:@"Line %ld: Empty command", (long)lineNum]};
    NSLog(@"[MobAI-DSL] Executing: %@ (arg1=%@, arg2=%@)", command, arg1, arg2);
    __block NSDictionary *result = nil;
    dispatch_sync(dispatch_get_main_queue(), ^{
        if ([command isEqualToString:@"tap"]) result = [self dslTap:arg1];
        else if ([command isEqualToString:@"type"]) result = [self dslType:arg1 text:arg2];
        else if ([command isEqualToString:@"wait_for"] || [command isEqualToString:@"wait"]) result = [self dslWaitFor:arg1];
        else if ([command isEqualToString:@"assert_exists"] || [command isEqualToString:@"assert"]) result = [self dslAssertExists:arg1];
        else if ([command isEqualToString:@"swipe"]) result = [self dslSwipe:arg1];
        else if ([command isEqualToString:@"longpress"]) result = [self dslLongPress:arg1];
        else if ([command isEqualToString:@"key"]) result = [self dslKey:arg1];
        else if ([command isEqualToString:@"scroll"]) result = [self dslScroll:arg1];
        else result = @{@"status": @"error", @"error": [NSString stringWithFormat:@"Unknown command: %@", command]};
    });
    return result;
}

- (NSArray *)parseDSLCommand:(NSString *)line {
    line = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSMutableArray *parts = [NSMutableArray array];
    NSMutableString *current = [NSMutableString string];
    BOOL inQuotes = NO;
    for (NSUInteger i = 0; i < line.length; i++) {
        unichar c = [line characterAtIndex:i];
        if (c == '"') inQuotes = !inQuotes;
        else if (c == ' ' && !inQuotes) { if (current.length > 0) { [parts addObject:[current copy]]; [current setString:@""]; } }
        else [current appendFormat:@"%c", c];
    }
    if (current.length > 0) [parts addObject:[current copy]];
    NSString *command = parts.count > 0 ? parts[0] : nil;
    NSString *arg = parts.count > 1 ? [self stripQuotes:parts[1]] : nil;
    return @[command ?: @"", arg ?: @""];
}

- (NSString *)stripQuotes:(NSString *)str {
    if ([str hasPrefix:@"\""] && [str hasSuffix:@"\""]) return [str substringWithRange:NSMakeRange(1, str.length - 2)];
    return str;
}

- (NSDictionary *)dslTap:(NSString *)text {
    if (!text || text.length == 0) return @{@"status": @"error", @"error": @"tap: No text specified"};
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    if (!keyWindow) return @{@"status": @"error", @"error": @"No key window"};
    BOOL found = [self findAndTapText:text inView:keyWindow];
    return found ? @{@"status": @"ok", @"action": @"tap", @"text": text} : @{@"status": @"error", @"error": [NSString stringWithFormat:@"Element '%@' not found", text]};
}

- (NSDictionary *)dslType:(NSString *)field text:(NSString *)text {
    if (!text || text.length == 0) return @{@"status": @"error", @"error": @"type: No text specified"};
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    if (!keyWindow) return @{@"status": @"error", @"error": @"No key window"};
    UITextField *tf = field && field.length > 0 ? [self findTextFieldByPlaceholder:field inView:keyWindow] : nil;
    if (!tf) tf = [self findFirstResponder:keyWindow];
    if (!tf) { tf = [self findAnyTextField:keyWindow]; if (tf) [tf becomeFirstResponder]; }
    if (tf) { tf.text = [tf.text stringByAppendingString:text]; [tf sendActionsForControlEvents:UIControlEventEditingChanged]; return @{@"status": @"ok", @"action": @"type", @"text": text}; }
    return @{@"status": @"error", @"error": @"No text field found"};
}

- (NSDictionary *)dslWaitFor:(NSString *)text {
    if (!text || text.length == 0) return @{@"status": @"error", @"error": @"wait_for: No text specified"};
    __block BOOL found = NO;
    NSTimeInterval timeout = 5.0, start = [[NSDate date] timeIntervalSince1970];
    while ([[NSDate date] timeIntervalSince1970] - start < timeout) {
        for (UIWindow *window in [UIApplication sharedApplication].windows) {
            if (window.windowLevel == UIWindowLevelNormal) { found = [self findElementByText:text inView:window]; if (found) break; }
        }
        if (found) break;
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
    return found ? @{@"status": @"ok", @"action": @"wait_for", @"text": text} : @{@"status": @"error", @"error": [NSString stringWithFormat:@"Element '%@' not found within timeout", text]};
}

- (NSDictionary *)dslAssertExists:(NSString *)text {
    if (!text || text.length == 0) return @{@"status": @"error", @"error": @"assert_exists: No text specified"};
    __block BOOL found = NO;
    for (UIWindow *window in [UIApplication sharedApplication].windows) {
        if (window.windowLevel == UIWindowLevelNormal) { found = [self findElementByText:text inView:window]; if (found) break; }
    }
    return found ? @{@"status": @"ok", @"action": @"assert_exists", @"text": text} : @{@"status": @"error", @"error": [NSString stringWithFormat:@"Assertion failed: '%@' not found", text]};
}

- (NSDictionary *)dslSwipe:(NSString *)direction {
    if (!direction || direction.length == 0) direction = @"up";
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    if (!keyWindow) return @{@"status": @"error", @"error": @"No key window"};
    CGFloat w = keyWindow.bounds.size.width, h = keyWindow.bounds.size.height;
    CGFloat cx = w/2, cy = h/2;
    CGPoint from = CGPointMake(cx, cy), to = CGPointMake(cx, cy);
    CGFloat offset = MIN(w, h) * 0.3;
    if ([direction isEqualToString:@"up"]) to.y -= offset;
    else if ([direction isEqualToString:@"down"]) to.y += offset;
    else if ([direction isEqualToString:@"left"]) to.x -= offset;
    else if ([direction isEqualToString:@"right"]) to.x += offset;
    [self swipeFrom:from to:to inView:keyWindow];
    return @{@"status": @"ok", @"action": @"swipe", @"direction": direction};
}

- (NSDictionary *)dslLongPress:(NSString *)durationStr {
    NSTimeInterval duration = durationStr ? [durationStr doubleValue] : 1.0;
    if (duration <= 0) duration = 1.0;
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    if (!keyWindow) return @{@"status": @"error", @"error": @"No key window"};
    CGFloat cx = keyWindow.bounds.size.width / 2, cy = keyWindow.bounds.size.height / 2;
    UIView *target = [keyWindow hitTest:CGPointMake(cx, cy) withEvent:nil];
    if (!target) return @{@"status": @"error", @"error": @"No target view"};
    if ([target isKindOfClass:[UIControl class]]) {
        UIControl *control = (UIControl *)target;
        [control sendActionsForControlEvents:UIControlEventTouchDown];
        usleep((useconds_t)(duration * 1000000));
        [control sendActionsForControlEvents:UIControlEventTouchUpInside];
    }
    return @{@"status": @"ok", @"action": @"longpress", @"duration": @(duration)};
}

- (NSDictionary *)dslKey:(NSString *)key {
    if (!key || key.length == 0) return @{@"status": @"error", @"error": @"key: No key specified"};
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    if ([key isEqualToString:@"enter"] || [key isEqualToString:@"return"]) {
        UITextField *tf = [self findFirstResponder:keyWindow];
        if (tf && [tf.delegate respondsToSelector:@selector(textFieldShouldReturn:)]) { if ([tf.delegate textFieldShouldReturn:tf]) [tf resignFirstResponder]; }
    } else if ([key isEqualToString:@"backspace"]) {
        UITextField *tf = [self findFirstResponder:keyWindow];
        if (tf && tf.text.length > 0) { tf.text = [tf.text substringToIndex:tf.text.length - 1]; [tf sendActionsForControlEvents:UIControlEventEditingChanged]; }
    }
    return @{@"status": @"ok", @"action": @"key", @"key": key};
}

- (NSDictionary *)dslScroll:(NSString *)direction {
    if (!direction || direction.length == 0) direction = @"down";
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    if (!keyWindow) return @{@"status": @"error", @"error": @"No key window"};
    UIScrollView *scrollView = [self findScrollView:keyWindow];
    if (scrollView) {
        CGPoint offset = scrollView.contentOffset;
        CGFloat distance = 200.0;
        if ([direction isEqualToString:@"up"]) offset.y -= distance;
        else if ([direction isEqualToString:@"down"]) offset.y += distance;
        else if ([direction isEqualToString:@"left"]) offset.x -= distance;
        else if ([direction isEqualToString:@"right"]) offset.x += distance;
        [scrollView setContentOffset:offset animated:YES];
        return @{@"status": @"ok", @"action": @"scroll", @"direction": direction};
    }
    return @{@"status": @"error", @"error": @"No scroll view found"};
}

// ============================================================
// Additional UI Helpers
// ============================================================

- (void)collectAccessibilityElementsFromView:(UIView *)view intoArray:(NSMutableArray *)array {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"type"] = NSStringFromClass([view class]);
    dict[@"frame"] = NSStringFromCGRect(view.frame);
    if (view.accessibilityLabel.length > 0) dict[@"accessibilityLabel"] = view.accessibilityLabel;
    if (view.accessibilityValue.length > 0) dict[@"accessibilityValue"] = view.accessibilityValue;
    if (view.accessibilityHint.length > 0) dict[@"accessibilityHint"] = view.accessibilityHint;
    if (view.isAccessibilityElement) dict[@"isAccessibilityElement"] = @YES;
    if ([view isKindOfClass:[UIButton class]]) { UIButton *btn = (UIButton *)view; if (btn.currentTitle.length > 0) dict[@"title"] = btn.currentTitle; }
    if ([view isKindOfClass:[UILabel class]]) { UILabel *lbl = (UILabel *)view; if (lbl.text.length > 0) dict[@"text"] = lbl.text; }
    if ([view isKindOfClass:[UITextField class]]) { UITextField *tf = (UITextField *)view; if (tf.text.length > 0) dict[@"text"] = tf.text; if (tf.placeholder.length > 0) dict[@"placeholder"] = tf.placeholder; }
    dict[@"isVisible"] = @(!view.isHidden && view.alpha > 0);
    for (UIView *sub in view.subviews) { if (!sub.isHidden && sub.alpha > 0) [self collectAccessibilityElementsFromView:sub intoArray:array]; }
    [array addObject:dict];
}

- (void)tapByAccessibilityLabel:(NSString *)label {
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    if (keyWindow) [self findAndTapByAccessibilityLabel:label inView:keyWindow];
}

- (BOOL)findAndTapByAccessibilityLabel:(NSString *)label inView:(UIView *)view {
    if ([view.accessibilityLabel isEqualToString:label]) { if ([view isKindOfClass:[UIControl class]]) [(UIControl *)view sendActionsForControlEvents:UIControlEventTouchUpInside]; return YES; }
    for (UIView *sub in view.subviews) { if ([self findAndTapByAccessibilityLabel:label inView:sub]) return YES; }
    return NO;
}

- (BOOL)findElementByText:(NSString *)text inView:(UIView *)view {
    if ([view.accessibilityLabel isEqualToString:text]) return YES;
    if ([view.accessibilityValue isEqualToString:text]) return YES;
    if ([view isKindOfClass:[UIButton class]] && [((UIButton *)view).currentTitle isEqualToString:text]) return YES;
    if ([view isKindOfClass:[UILabel class]] && [((UILabel *)view).text isEqualToString:text]) return YES;
    if ([view isKindOfClass:[UITextField class]] && [((UITextField *)view).text isEqualToString:text]) return YES;
    for (UIView *sub in view.subviews) { if ([self findElementByText:text inView:sub]) return YES; }
    return NO;
}

- (UITextField *)findTextFieldByPlaceholder:(NSString *)placeholder inView:(UIView *)view {
    if ([view isKindOfClass:[UITextField class]] && [((UITextField *)view).placeholder isEqualToString:placeholder]) return (UITextField *)view;
    for (UIView *sub in view.subviews) { UITextField *tf = [self findTextFieldByPlaceholder:placeholder inView:sub]; if (tf) return tf; }
    return nil;
}

- (UIScrollView *)findScrollView:(UIView *)view {
    if ([view isKindOfClass:[UIScrollView class]]) return (UIScrollView *)view;
    for (UIView *sub in view.subviews) { UIScrollView *sv = [self findScrollView:sub]; if (sv) return sv; }
    return nil;
}

@end
