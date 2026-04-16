//
//  IsLCInstalled.m
//  lara
//
//  Rewritten in Objective-C (was islcinstalled.swift)
//

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import "IsLCInstalled.h"
#import "../Logger.h"

BOOL islcinstalled(void) {
    BOOL detected = NO;
    uint32_t count = _dyld_image_count();

    for (uint32_t i = 0; i < count; i++) {
        const char *cName = _dyld_get_image_name(i);
        if (!cName) continue;
        NSString *name  = [[NSString stringWithUTF8String:cName] lowercaseString];
        if ([name containsString:@"tweakinjector.dylib"] ||
            [name containsString:@"tweakloader.dylib"]) {
            detected = YES;
        }
    }

    [[Logger shared] log:[NSString stringWithFormat:@"\nlivecontainer detected: %@", detected ? @"yeah" : @"nah"]];
    return detected;
}
