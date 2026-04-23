//
//  AppDelegate.m
//  lara
//
//  Rewritten in Objective-C
//

#import "AppDelegate.h"
#import "LaraManager.h"
#import "LaraTargetProfile.h"
#import "Logger.h"
#import "remote/LaraMobAIServer.h"
#include <objc/runtime.h>
#include <objc/message.h>
#import "funcs/Keepalive.h"
#import "funcs/IsUnsupported.h"
#import "views/RootTabBarController.h"
#import "kexploit/offsets.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(nullable NSDictionary *)launchOptions {
    // Install stdout/stderr pipe + lara.log before code that may printf/NSLog.
    [[Logger shared] capture];

    // Один целевой профиль: iPad8,9 + iOS 17.3.x (21D61) — env до любого эксплойта.
    lara_apply_single_device_profile();
    lara_seed_embedded_if_needed();

    // Fix UIDocumentPickerViewController – force asCopy:YES
    [self fixDocumentPicker];

    // Default method setting
    if (![[NSUserDefaults standardUserDefaults] objectForKey:@"selectedmethod"]) {
        [[NSUserDefaults standardUserDefaults] setObject:@"sbx" forKey:@"selectedmethod"];
    }

    // Keepalive
    if ([[NSUserDefaults standardUserDefaults] boolForKey:@"keepalive"]) {
        if (!kaenabled()) {
            toggleka();
        }
    }

    // Unsupported notice
    if (isunsupported()) {
        NSLog(@"device may be unsupported");
    } else {
        NSLog(@"device should be supported");
    }

    // Set up window and root view controller
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[RootTabBarController alloc] init];
    [self.window makeKeyAndVisible];

    // Start MobAI-compatible HTTP API server on port 8686 (disabled by default, start from Tools tab)
    // [[LaraMobAIServer shared] startOnPort:8686 error:nil];

    return YES;
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    [[Logger shared] stopCapture];
    [[LaraMobAIServer shared] stop];
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    [[Logger shared] capture];
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    [[Logger shared] capture];
}

#pragma mark - Private

- (void)fixDocumentPicker {
    // Swizzle init(forOpeningContentTypes:asCopy:) to always pass asCopy:YES
    Class cls = [UIDocumentPickerViewController class];
    SEL origSel = @selector(initForOpeningContentTypes:asCopy:);
    SEL fixedSel = @selector(fixed_initForOpeningContentTypes:asCopy:);

    Method origMethod = class_getInstanceMethod(cls, origSel);
    Method fixMethod  = class_getInstanceMethod(cls, fixedSel);
    if (origMethod && fixMethod) {
        method_exchangeImplementations(origMethod, fixMethod);
    }
}

@end

@implementation UIDocumentPickerViewController (LaraFix)

- (instancetype)fixed_initForOpeningContentTypes:(NSArray<UTType *> *)contentTypes asCopy:(BOOL)asCopy {
    return [self fixed_initForOpeningContentTypes:contentTypes asCopy:YES];
}

@end
