//
//  SettingsViewController.m
//  lara
//
//  Rewritten in Objective-C (was SettingsView.swift)
//

#import "SettingsViewController.h"
#import "../LaraManager.h"
#import "../Logger.h"
#import "../funcs/Keepalive.h"
#import "kexploit/offsets.h"

typedef NS_ENUM(NSInteger, SettingsSection) {
    SettingsSectionAppInfo   = 0,
    SettingsSectionMethod    = 1,
    SettingsSectionGeneral   = 2,
    SettingsSectionOffsets   = 3,
    SettingsSectionDanger    = 4,
    SettingsSectionCount
};

typedef NS_ENUM(NSInteger, LaraMethod) {
    LaraMethodVFS    = 0,
    LaraMethodSBX    = 1,
    LaraMethodHybrid = 2,
};

@interface SettingsViewController ()
@property (nonatomic, assign) BOOL downloading;
@property (nonatomic, strong) NSString *downloadStage;
@end

@implementation SettingsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Settings";
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                             target:self
                             action:@selector(dismiss)];
}

- (void)dismiss {
    [self dismissViewControllerAnimated:YES completion:nil];
}

#pragma mark - Table View

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return SettingsSectionCount;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    switch (section) {
        case SettingsSectionAppInfo:  return 1;
        case SettingsSectionMethod:   return 1; // segmented control cell
        case SettingsSectionGeneral:  return 3; // log dividers, keepalive, show FM in tabs
        case SettingsSectionOffsets:  return 2; // download offsets, reset
        case SettingsSectionDanger:   return 1; // reset all
    }
    return 0;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    switch (section) {
        case SettingsSectionAppInfo:  return @"Lara";
        case SettingsSectionMethod:   return @"Method";
        case SettingsSectionGeneral:  return @"General";
        case SettingsSectionOffsets:  return @"Offsets";
        case SettingsSectionDanger:   return @"Danger Zone";
    }
    return nil;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == SettingsSectionMethod) {
        NSString *sel = [[NSUserDefaults standardUserDefaults] stringForKey:@"selectedmethod"] ?: @"sbx";
        if ([sel isEqualToString:@"vfs"]) return @"VFS only.";
        if ([sel isEqualToString:@"sbx"]) return @"SBX only.";
        return @"Hybrid: SBX for read, VFS for write.\nBest method ever. (Thanks Huy)";
    }
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    switch (indexPath.section) {
        case SettingsSectionAppInfo: {
            UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
            cell.selectionStyle = UITableViewCellSelectionStyleNone;

            NSString *name    = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleDisplayName"]
                             ?: [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleName"]
                             ?: @"Unknown App";
            NSString *version = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"?";

            cell.textLabel.text       = name;
            cell.textLabel.font       = [UIFont boldSystemFontOfSize:16];
            cell.detailTextLabel.text = [NSString stringWithFormat:@"Version %@", version];

            // App icon
            UIImage *icon = [self appIcon];
            if (icon) {
                UIImageView *iv = [[UIImageView alloc] initWithImage:icon];
                iv.frame = CGRectMake(0, 0, 40, 40);
                iv.layer.cornerRadius = 9;
                iv.clipsToBounds = YES;
                cell.imageView.image = icon;
            }
            return cell;
        }

        case SettingsSectionMethod: {
            UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
            cell.selectionStyle = UITableViewCellSelectionStyleNone;

            UISegmentedControl *seg = [[UISegmentedControl alloc] initWithItems:@[@"VFS", @"SBX", @"Hybrid"]];
            NSString *sel = [[NSUserDefaults standardUserDefaults] stringForKey:@"selectedmethod"] ?: @"sbx";
            if ([sel isEqualToString:@"vfs"])    seg.selectedSegmentIndex = 0;
            else if ([sel isEqualToString:@"sbx"]) seg.selectedSegmentIndex = 1;
            else                                   seg.selectedSegmentIndex = 2;
            [seg addTarget:self action:@selector(methodChanged:) forControlEvents:UIControlEventValueChanged];

            seg.translatesAutoresizingMaskIntoConstraints = NO;
            [cell.contentView addSubview:seg];
            [NSLayoutConstraint activateConstraints:@[
                [seg.leadingAnchor constraintEqualToAnchor:cell.contentView.leadingAnchor constant:16],
                [seg.trailingAnchor constraintEqualToAnchor:cell.contentView.trailingAnchor constant:-16],
                [seg.centerYAnchor constraintEqualToAnchor:cell.contentView.centerYAnchor],
                [seg.topAnchor constraintGreaterThanOrEqualToAnchor:cell.contentView.topAnchor constant:8],
                [seg.bottomAnchor constraintLessThanOrEqualToAnchor:cell.contentView.bottomAnchor constant:-8],
            ]];
            return cell;
        }

        case SettingsSectionGeneral: {
            UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            UISwitch *sw = [[UISwitch alloc] init];
            cell.accessoryView = sw;

            if (indexPath.row == 0) {
                cell.textLabel.text = @"Disable Log Dividers";
                sw.on = [[NSUserDefaults standardUserDefaults] boolForKey:@"loggernobullshit"];
                sw.tag = 0;
            } else if (indexPath.row == 1) {
                cell.textLabel.text = @"Keep Alive";
                sw.on = [[NSUserDefaults standardUserDefaults] boolForKey:@"keepalive"];
                sw.tag = 1;
            } else {
                cell.textLabel.text = @"Show File Manager in Tabs";
                sw.on = [[NSUserDefaults standardUserDefaults] boolForKey:@"showfmintabs"];
                sw.tag = 2;
            }
            [sw addTarget:self action:@selector(toggleChanged:) forControlEvents:UIControlEventValueChanged];
            return cell;
        }

        case SettingsSectionOffsets: {
            UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
            if (indexPath.row == 0) {
                if (self.downloading) {
                    cell.textLabel.text = @"Downloading Kernelcache…";
                    cell.detailTextLabel.text = self.downloadStage ?: @"Initialising…";
                    cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
                    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
                    [spinner startAnimating];
                    cell.accessoryView = spinner;
                } else {
                    cell.textLabel.text = @"Download Kernelcache Offsets";
                }
            } else {
                cell.textLabel.text = @"Clear Offset Data";
                cell.textLabel.textColor = UIColor.systemRedColor;
            }
            return cell;
        }

        case SettingsSectionDanger: {
            UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
            cell.textLabel.text = @"Reset All Settings";
            cell.textLabel.textColor = UIColor.systemRedColor;
            return cell;
        }
    }

    return [[UITableViewCell alloc] init];
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    if (indexPath.section == SettingsSectionOffsets) {
        if (indexPath.row == 0) {
            [self downloadOffsets];
        } else {
            clearkerncachedata();
            if (self.onOffsetsChanged) self.onOffsetsChanged(haskernproc());
            [tableView reloadData];
        }
    }

    if (indexPath.section == SettingsSectionDanger) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Reset All Settings?"
                                                                       message:@"This will clear all user preferences."
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Reset" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
            NSString *domain = [[NSBundle mainBundle] bundleIdentifier];
            [[NSUserDefaults standardUserDefaults] removePersistentDomainForName:domain];
        }]];
        [self presentViewController:alert animated:YES completion:nil];
    }
}

#pragma mark - Actions

- (void)methodChanged:(UISegmentedControl *)seg {
    NSArray *methods = @[@"vfs", @"sbx", @"hybrid"];
    NSString *selected = methods[seg.selectedSegmentIndex];
    [[NSUserDefaults standardUserDefaults] setObject:selected forKey:@"selectedmethod"];
    [self.tableView reloadSections:[NSIndexSet indexSetWithIndex:SettingsSectionMethod]
                  withRowAnimation:UITableViewRowAnimationNone];
}

- (void)toggleChanged:(UISwitch *)sw {
    switch (sw.tag) {
        case 0: {
            [[NSUserDefaults standardUserDefaults] setBool:sw.on forKey:@"loggernobullshit"];
            [[Logger shared] clear];
            break;
        }
        case 1: {
            [[NSUserDefaults standardUserDefaults] setBool:sw.on forKey:@"keepalive"];
            if (sw.on) { if (!kaenabled()) toggleka(); }
            else       { if (kaenabled())  toggleka(); }
            break;
        }
        case 2:
            [[NSUserDefaults standardUserDefaults] setBool:sw.on forKey:@"showfmintabs"];
            break;
    }
}

- (void)downloadOffsets {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self downloadOffsets]; });
        return;
    }

    if (self.downloading) return;
    self.downloading = YES;
    [self.tableView reloadData];

    // Periodic status ticker: updates cell text every ~3s so user sees it's alive
    __block NSInteger tick = 0;
    NSArray *stages = @[
        @"Fetching firmware URL…",
        @"Connecting to AppleDB…",
        @"Locating kernelcache…",
        @"Downloading (partial zip)…",
        @"Parsing kernel symbols…",
    ];
        NSTimer *ticker = [NSTimer timerWithTimeInterval:3.0
                                                                                            target:self
                                                                                        selector:@selector(_tickerFired:)
                                                                                        userInfo:stages
                                                                                         repeats:YES];
        [[NSRunLoop mainRunLoop] addTimer:ticker forMode:NSRunLoopCommonModes];
    // Store ticker state in an ivar-like associated object trick via NSMutableDictionary
    // Simpler: just set the cell subtitle via a stored property
    self.downloadStage = stages[0];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        BOOL ok = dlkerncache();
        dispatch_async(dispatch_get_main_queue(), ^{
            [ticker invalidate];
            self.downloading = NO;
            self.downloadStage = nil;
            if (self.onOffsetsChanged) self.onOffsetsChanged(ok);
            [self.tableView reloadData];

            if (!ok) {
                UIAlertController *alert = [UIAlertController
                    alertControllerWithTitle:@"Download Failed"
                                     message:@"Could not download the kernelcache.\n\n"
                                              "Possible reasons:\n"
                                              "• No internet connection\n"
                                              "• Your iOS version is not yet in the AppleDB database "
                                                "(api.appledb.dev)\n"
                                              "• Apple CDN returned an error\n\n"
                                              "Check the Logs tab for details, then retry."
                              preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"Retry"
                                                          style:UIAlertActionStyleDefault
                                                        handler:^(UIAlertAction *_) {
                    [self downloadOffsets];
                }]];
                [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                                          style:UIAlertActionStyleCancel
                                                        handler:nil]];
                [self presentViewController:alert animated:YES completion:nil];
            }
        });
    });
}

- (void)_tickerFired:(NSTimer *)timer {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self _tickerFired:timer]; });
        return;
    }

    NSArray *stages = timer.userInfo;
    if (!stages) return;
    static NSInteger idx = 0;
    idx = (idx + 1) % (NSInteger)stages.count;
    self.downloadStage = stages[idx];
    NSIndexPath *ip = [NSIndexPath indexPathForRow:0 inSection:SettingsSectionOffsets];
    [self.tableView reloadRowsAtIndexPaths:@[ip] withRowAnimation:UITableViewRowAnimationNone];
}

#pragma mark - Helpers

- (UIImage *)appIcon {
    NSDictionary *icons = [NSBundle.mainBundle.infoDictionary objectForKey:@"CFBundleIcons"];
    NSDictionary *primary = icons[@"CFBundlePrimaryIcon"];
    NSArray *files = primary[@"CFBundleIconFiles"];
    NSString *last = files.lastObject;
    if (last) return [UIImage imageNamed:last];
    return [UIImage imageNamed:@"unknown"];
}

@end
