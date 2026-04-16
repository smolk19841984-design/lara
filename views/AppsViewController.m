//
//  AppsViewController.m
//  lara
//
//  Rewritten in Objective-C (was AppsView.swift)
//

#import "AppsViewController.h"
#import "../LaraManager.h"
#import <sys/stat.h>
#include <sys/xattr.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

@interface ScannedApp : NSObject
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy) NSString *bundleId;
@property (nonatomic, copy) NSString *bundlePath;
@property (nonatomic, assign) BOOL hasMobileProvision;
@property (nonatomic, assign) BOOL notBypassed;
@end
@implementation ScannedApp @end

@interface AppsViewController ()
@property (nonatomic, strong) LaraManager *mgr;
@property (nonatomic, strong) NSArray<ScannedApp *> *apps;
@property (nonatomic, assign) BOOL scanning;
@end

@implementation AppsViewController

- (instancetype)initWithMgr:(LaraManager *)mgr {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    _mgr = mgr;
    _apps = @[];
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"3-App Bypass";
    UIBarButtonItem *scanBtn = [[UIBarButtonItem alloc]
        initWithTitle:@"Scan"
                style:UIBarButtonItemStylePlain
               target:self
               action:@selector(scanApps)];
    self.navigationItem.rightBarButtonItem = scanBtn;
}

- (void)scanApps {
    if (self.scanning) return;
    self.scanning = YES;
    [self.tableView reloadData];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSArray *found = [self doScan];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.apps = found;
            self.scanning = NO;
            [self.tableView reloadData];
        });
    });
}

- (NSArray<ScannedApp *> *)doScan {
    NSMutableArray *result = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *roots = @[@"/private/var/containers/Bundle/Application",
                       @"/var/containers/Bundle/Application"];
    NSMutableSet *seen = [NSMutableSet set];

    for (NSString *root in roots) {
        NSArray *entries = [fm contentsOfDirectoryAtPath:root error:nil];
        for (NSString *uuid in entries) {
            NSString *uuidPath = [root stringByAppendingPathComponent:uuid];
            BOOL isDir; [fm fileExistsAtPath:uuidPath isDirectory:&isDir];
            if (!isDir) continue;

            NSArray *apps = [fm contentsOfDirectoryAtPath:uuidPath error:nil];
            for (NSString *app in apps) {
                if (![app hasSuffix:@".app"]) continue;
                NSString *bundlePath = [uuidPath stringByAppendingPathComponent:app];
                NSString *normalized = [bundlePath hasPrefix:@"/private/"]
                    ? [bundlePath substringFromIndex:8] : bundlePath;
                if ([seen containsObject:normalized]) continue;
                [seen addObject:normalized];

                NSString *mp = [bundlePath stringByAppendingPathComponent:@"embedded.mobileprovision"];
                if (access(mp.UTF8String, F_OK) != 0) continue;

                // Read Info.plist for name and bundleId
                NSString *infoPlist = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPlist];

                ScannedApp *appObj = [[ScannedApp alloc] init];
                appObj.name = info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"] ?: app;
                appObj.bundleId = info[@"CFBundleIdentifier"] ?: @"unknown";
                appObj.bundlePath = bundlePath;
                appObj.hasMobileProvision = YES;
                appObj.notBypassed = ![self isBypassed:bundlePath];
                [result addObject:appObj];
            }
        }
    }
    return result;
}

- (BOOL)isBypassed:(NSString *)bundlePath {
    const char *key = "com.apple.installd.validatedByFreeProfile";
    uint8_t value = 0;
    ssize_t size = getxattr(bundlePath.UTF8String, key, &value, 1, 0, 0);
    return size == 1 && value != 0;
}

- (void)bypassApp:(ScannedApp *)app {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self.mgr logMessage:[NSString stringWithFormat:@"(sbx) bypassing %@", app.name]];

        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *stagingRoot = [NSTemporaryDirectory() stringByAppendingPathComponent:@"sbx_bypass_test"];
        [fm removeItemAtPath:stagingRoot error:nil];
        [fm createDirectoryAtPath:stagingRoot withIntermediateDirectories:YES attributes:nil error:nil];

        NSString *appName = app.bundlePath.lastPathComponent;
        NSString *staged  = [stagingRoot stringByAppendingPathComponent:appName];
        NSError *err;
        if (![fm copyItemAtPath:app.bundlePath toPath:staged error:&err]) {
            [self.mgr logMessage:[NSString stringWithFormat:@"(sbx) copy failed: %@", err.localizedDescription]];
            return;
        }

        const char *key = "com.apple.installd.validatedByFreeProfile";
        uint8_t val[3] = {1, 2, 3};
        int rc = setxattr(staged.UTF8String, key, val, sizeof(val), 0, 0);
        [self.mgr logMessage:rc == 0
            ? [NSString stringWithFormat:@"(sbx) set xattr on %@", app.name]
            : [NSString stringWithFormat:@"(sbx) xattr failed errno=%d %s", errno, strerror(errno)]];

        dispatch_async(dispatch_get_main_queue(), ^{
            [self scanApps];
        });
    });
}

#pragma mark - Table View

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return self.scanning ? 1 : (self.apps.count == 0 ? 2 : 1 + (NSInteger)self.apps.count);
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == 0) return 1;
    return 3; // name, bundleId, bypass button
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == 0) return @"Actions";
    if (self.apps.count == 0) return @"No Apps";
    return self.apps[section - 1].name;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];

    if (indexPath.section == 0) {
        if (self.scanning) {
            cell.textLabel.text = @"Scanning...";
            UIActivityIndicatorView *sp = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
            [sp startAnimating]; cell.accessoryView = sp;
        } else {
            cell.textLabel.text = @"Scan Apps";
        }
        return cell;
    }

    if (self.apps.count == 0) {
        cell.textLabel.text = @"No apps with embedded.mobileprovision found.";
        cell.textLabel.textColor = UIColor.secondaryLabelColor;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }

    ScannedApp *app = self.apps[indexPath.section - 1];
    switch (indexPath.row) {
        case 0:
            cell.textLabel.text = @"Bundle ID:";
            cell.detailTextLabel.text = app.bundleId;
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            break;
        case 1:
            cell.textLabel.text = @"Status:";
            cell.detailTextLabel.text = app.notBypassed ? @"not bypassed" : @"bypassed";
            cell.detailTextLabel.textColor = app.notBypassed ? UIColor.systemOrangeColor : UIColor.systemGreenColor;
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            break;
        case 2:
            cell.textLabel.text = @"Bypass";
            if (!self.mgr.sbxReady) {
                cell.textLabel.textColor = UIColor.secondaryLabelColor;
                cell.selectionStyle = UITableViewCellSelectionStyleNone;
            }
            break;
    }
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section == 0) { [self scanApps]; return; }
    if (self.apps.count == 0) return;
    if (indexPath.row == 2) {
        ScannedApp *app = self.apps[indexPath.section - 1];
        [self bypassApp:app];
    }
}

@end
