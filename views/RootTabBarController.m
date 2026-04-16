//
//  RootTabBarController.m
//  lara
//
//  Rewritten in Objective-C (replaces SwiftUI TabView in lara.swift)
//

#import "RootTabBarController.h"
#import "ExploitViewController.h"
#import "BetaViewController.h"
#import "LogsViewController.h"
#import "../funcs/IsUnsupported.h"
#import "kexploit/offsets.h"
#import "kexploit/utils.h"

// Forward declare SantanderPathListViewController for the file manager tab
@interface SantanderPathListViewController : UITableViewController
- (instancetype)initWithPath:(NSString *)path readUsesSBX:(BOOL)sbx useVFSOverwrite:(BOOL)vfs;
@end

@implementation RootTabBarController

- (void)viewDidLoad {
    [super viewDidLoad];

    // ── File Manager ──────────────────────────────────────────────────────────
    UINavigationController *fmNav = [[UINavigationController alloc] init];
    fmNav.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Files"
                                                     image:[UIImage systemImageNamed:@"folder.fill"]
                                                       tag:0];

    // ── Exploit / Main ────────────────────────────────────────────────────────
    ExploitViewController *exploitVC = [[ExploitViewController alloc] init];
    UINavigationController *exploitNav = [[UINavigationController alloc] initWithRootViewController:exploitVC];
    exploitNav.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"lara"
                                                          image:[UIImage systemImageNamed:@"ant.fill"]
                                                            tag:1];

    // ── Beta (модули из third_party/darksword-kexploit-fun) ─────────────────
    BetaViewController *betaVC = [[BetaViewController alloc] init];
    UINavigationController *betaNav = [[UINavigationController alloc] initWithRootViewController:betaVC];
    betaNav.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Beta"
                                                       image:[UIImage systemImageNamed:@"flask.fill"]
                                                         tag:2];

    // ── Logs ──────────────────────────────────────────────────────────────────
    LogsViewController *logsVC = [[LogsViewController alloc] init];
    UINavigationController *logsNav = [[UINavigationController alloc] initWithRootViewController:logsVC];
    logsNav.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Logs"
                                                       image:[UIImage systemImageNamed:@"doc.text.fill"]
                                                        tag:3];

    self.viewControllers = @[fmNav, exploitNav, betaNav, logsNav];
    self.selectedIndex = 1;

    // ── iPad tab bar size tweaks ───────────────────────────────────────────────
    BOOL isIPad = UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad;
    if (isIPad) {
        self.tabBar.tintColor = [UIColor colorWithRed:0.4 green:0.3 blue:1.0 alpha:1.0];
        // Expand content width on iPad (use readable content guide in child VCs)
        self.tabBar.itemPositioning = UITabBarItemPositioningCentered;
    }

    // Trigger offset init on appear
    dispatch_async(dispatch_get_main_queue(), ^{
        init_offsets();
    });

    // Show unsupported alert if needed
    if (isunsupported()) {
        dispatch_async(dispatch_get_main_queue(), ^{
            UIAlertController *alert = [UIAlertController
                alertControllerWithTitle:@"Unsupported"
                                 message:@"Lara is currently not supported on this device.\n\n"
                                          "Possible reasons:\n"
                                          "Your device is newer than iOS 26.0.1\n"
                                          "Your device is older than iOS 17.0\n"
                                          "Your device has MIE\n"
                                          "You installed lara via LiveContainer\n\n"
                                          "Lara will probably not work."
                          preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        });
    }
}

@end
