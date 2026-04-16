//
//  LaraMobAIServer.h
//  lara
//
//  MobAI-compatible HTTP API server (localhost:8686/api/v1)
//  Provides MCP-compatible endpoints for mobile automation
//

#import <Foundation/Foundation.h>

@interface LaraMobAIServer : NSObject

@property (nonatomic, readonly) BOOL isRunning;
@property (nonatomic, readonly) NSInteger port;

+ (instancetype)shared;

- (BOOL)startOnPort:(NSInteger)port error:(NSError **)error;
- (void)stop;

// DSL execution
- (NSDictionary *)executeDSL:(NSString *)script error:(NSError **)error;

@end
