//
//  IsUnsupported.m
//  lara
//
//  Rewritten in Objective-C (was isunsupported.swift)
//

#import <UIKit/UIKit.h>
#import <sys/utsname.h>
#import "IsUnsupported.h"
#import "IsLCInstalled.h"

NSString *devicemachine(void) {
    struct utsname info;
    uname(&info);
    return [NSString stringWithUTF8String:info.machine];
}

BOOL hasmie(void) {
    NSString *machine = devicemachine();
    return [machine hasPrefix:@"iPhone18,"];
}

BOOL isunsupported(void) {
    NSOperatingSystemVersion v = [NSProcessInfo processInfo].operatingSystemVersion;

    if (v.majorVersion < 17)  return YES;
    if (v.majorVersion > 26)  return YES;

    if (v.majorVersion == 26) {
        if (v.minorVersion > 0) return YES;
        if (v.minorVersion == 0 && v.patchVersion > 1) return YES;
    }

    if (hasmie())          return YES;
    if (islcinstalled())   return YES;

    return NO;
}
