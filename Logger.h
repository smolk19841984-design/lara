//
//  Logger.h
//  lara
//
//  Rewritten in Objective-C (was Logger.swift)
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface Logger : NSObject

@property (nonatomic, copy, readonly) NSArray<NSString *> *logs;

+ (instancetype)shared;

- (void)log:(NSString *)message;
- (void)divider;
- (void)enclosedLog:(NSString *)message;
- (void)flushDivider;
- (void)clear;

- (void)capture;
- (void)stopCapture;

@end

NS_ASSUME_NONNULL_END
