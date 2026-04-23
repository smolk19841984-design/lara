//
//  main.m
//  lara
//
//  Rewritten in Objective-C
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

int main(int argc, char * argv[]) {
    // Do not freopen stdout/stderr here: Logger setupLogFile removes Documents/lara.log on first use,
    // so freopen would leave stdout writing to a deleted inode while the on-disk lara.log stays empty.
    // [[Logger shared] capture] in AppDelegate owns tee to lara.log + in-memory log.

    NSString * appDelegateClassName;
    @autoreleasepool {
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
