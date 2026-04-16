//
//  WhitelistViewController.m
//  lara
//
//  Rewritten in Objective-C (was WhitelistView.swift)
//

#import "WhitelistViewController.h"
#import "../LaraManager.h"

static NSArray<NSDictionary *> *whitelistFiles(void) {
    return @[
        @{@"name": @"Rejections.plist",               @"path": @"/private/var/db/MobileIdentityData/Rejections.plist"},
        @{@"name": @"AuthListBannedUpps.plist",        @"path": @"/private/var/db/MobileIdentityData/AuthListBannedUpps.plist"},
        @{@"name": @"AuthListBannedCdHashes.plist",    @"path": @"/private/var/db/MobileIdentityData/AuthListBannedCdHashes.plist"},
    ];
}

@interface WhitelistViewController ()
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSString *> *contents;
@property (nonatomic, assign) BOOL patching;
@end

@implementation WhitelistViewController

- (instancetype)init {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Whitelist";
    self.contents = [NSMutableDictionary dictionary];

    if ([LaraManager shared].sbxReady) {
        [self loadAll];
    }
}

#pragma mark - Actions

- (void)loadAll {
    if (![LaraManager shared].sbxReady) {
        [self showStatus:@"sandbox escape not ready"];
        return;
    }
    self.patching = YES;
    [self.tableView reloadData];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSMutableDictionary *next = [NSMutableDictionary dictionary];
        for (NSDictionary *f in whitelistFiles()) {
            NSString *path = f[@"path"];
            NSData *data = [self sbxRead:path maxSize:2 * 1024 * 1024];
            next[path] = data ? [self renderData:data] : @"(failed to read)";
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.contents addEntriesFromDictionary:next];
            self.patching = NO;
            [self.tableView reloadData];
        });
    });
}

- (void)patchAll {
    if (![LaraManager shared].sbxReady) {
        [self showStatus:@"sandbox escape not ready"];
        return;
    }
    self.patching = YES;
    [self.tableView reloadData];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSError *err;
        NSData *emptyPlist = [NSPropertyListSerialization dataWithPropertyList:@{}
                                                                        format:NSPropertyListXMLFormat_v1_0
                                                                       options:0
                                                                         error:&err];
        if (!emptyPlist) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.patching = NO;
                [self showStatus:@"failed to build empty plist"];
                [self.tableView reloadData];
            });
            return;
        }

        NSMutableArray *failures = [NSMutableArray array];
        for (NSDictionary *f in whitelistFiles()) {
            BOOL ok = [self sbxWrite:f[@"path"] data:emptyPlist];
            if (!ok) [failures addObject:f[@"name"]];
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            self.patching = NO;
            NSString *msg = failures.count == 0
                ? @"Patched all files!"
                : [NSString stringWithFormat:@"Failed: %@", [failures componentsJoinedByString:@", "]];
            [self showStatus:msg];
            [self loadAll];
        });
    });
}

#pragma mark - Table View

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1 + (NSInteger)whitelistFiles().count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == 0) return @"Actions";
    return whitelistFiles()[section - 1][@"name"];
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == 0) return @"Overwrites MobileIdentityData blacklist files with an empty plist.";
    return whitelistFiles()[section - 1][@"path"];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return section == 0 ? 2 : 1;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    LaraManager *mgr = [LaraManager shared];
    BOOL disabled = !mgr.sbxReady || self.patching;

    if (indexPath.section == 0) {
        if (indexPath.row == 0) {
            if (self.patching) {
                UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
                [spinner startAnimating];
                cell.accessoryView = spinner;
                cell.textLabel.text = @"Working...";
            } else {
                cell.textLabel.text = @"Refresh";
            }
            if (disabled) cell.textLabel.textColor = UIColor.secondaryLabelColor;
        } else {
            cell.textLabel.text = @"Patch (Empty Plist)";
            cell.textLabel.textColor = disabled ? UIColor.secondaryLabelColor : UIColor.systemBlueColor;
        }
        if (disabled) cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }

    NSDictionary *f = whitelistFiles()[indexPath.section - 1];
    NSString *content = self.contents[f[@"path"]] ?: @"(not loaded)";
    cell.textLabel.text = content;
    cell.textLabel.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    cell.textLabel.numberOfLines = 0;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section != 0) return;
    if (self.patching || ![LaraManager shared].sbxReady) return;
    if (indexPath.row == 0) [self loadAll];
    else                    [self patchAll];
}

#pragma mark - Helpers

- (nullable NSData *)sbxRead:(NSString *)path maxSize:(NSInteger)maxSize {
    NSError *err;
    NSData *data = [NSData dataWithContentsOfURL:[NSURL fileURLWithPath:path] options:NSDataReadingMappedIfSafe error:&err];
    if (!data) return nil;
    if ((NSInteger)data.length > maxSize) return [data subdataWithRange:NSMakeRange(0, maxSize)];
    return data;
}

- (BOOL)sbxWrite:(NSString *)path data:(NSData *)data {
    return [data writeToFile:path atomically:YES];
}

- (NSString *)renderData:(NSData *)data {
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return str ?: [NSString stringWithFormat:@"<binary %lu bytes>", (unsigned long)data.length];
}

- (void)showStatus:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Status"
                                                                       message:msg
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    });
}

@end
