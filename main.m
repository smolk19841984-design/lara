//
//  main.m
//  lara
//
//  Rewritten in Objective-C
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

int main(int argc, char * argv[]) {
    NSString * docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString * logPath = [docs stringByAppendingPathComponent:@"lara.log"];
    
    // Redirect stdout and stderr to lara.log for full tracking
    freopen([logPath fileSystemRepresentation], "a+", stdout);
    freopen([logPath fileSystemRepresentation], "a+", stderr);
    
    NSString * appDelegateClassName;
    @autoreleasepool {
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
