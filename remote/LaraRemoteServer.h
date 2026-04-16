//
//  LaraRemoteServer.h
//  lara
//
//  Built-in HTTP server for remote control from PC
//

#import <Foundation/Foundation.h>

@interface LaraRemoteServer : NSObject

@property (nonatomic, readonly) BOOL isRunning;
@property (nonatomic, readonly) NSInteger port;

+ (instancetype)shared;

- (BOOL)startOnPort:(NSInteger)port error:(NSError **)error;
- (void)stop;

@end
