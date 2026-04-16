//
//  LaraRemoteServer.m
//  lara
//
//  Built-in HTTP server for remote control from PC (BSD sockets)
//

#import "LaraRemoteServer.h"
#import "../kexploit/term.h"
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

static LaraRemoteServer *g_shared = nil;

@interface LaraRemoteServer ()
@property (nonatomic, assign) int listenSocket;
@property (nonatomic, assign) BOOL shouldAccept;
@end

@implementation LaraRemoteServer

+ (instancetype)shared {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_shared = [[LaraRemoteServer alloc] init];
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
        if (error) *error = [NSError errorWithDomain:@"LaraRemote" code:errno userInfo:@{NSLocalizedDescriptionKey: @(strerror(errno))}];
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
        if (error) *error = [NSError errorWithDomain:@"LaraRemote" code:errno userInfo:@{NSLocalizedDescriptionKey: @(strerror(errno))}];
        close(sock);
        return NO;
    }

    if (listen(sock, 5) < 0) {
        if (error) *error = [NSError errorWithDomain:@"LaraRemote" code:errno userInfo:@{NSLocalizedDescriptionKey: @(strerror(errno))}];
        close(sock);
        return NO;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    _listenSocket = sock;
    _port = port;
    _isRunning = YES;
    _shouldAccept = YES;

    NSLog(@"[Remote] HTTP server started on port %ld", (long)port);

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
    NSLog(@"[Remote] HTTP server stopped");
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

    NSLog(@"[Remote] %@ %@", method, path);

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

    return [self httpResponse:404 body:@"Not Found"];
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

- (void)findAndTapText:(NSString *)text inView:(UIView *)view {
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
        return;
    }

    for (UIView *sub in view.subviews) {
        [self findAndTapText:text inView:sub];
    }
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

@end
