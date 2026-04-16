//
//  CustomViewController.m
//  lara
//
//  Rewritten in Objective-C (was CustomView.swift)
//

#import "CustomViewController.h"
#import "../LaraManager.h"
#import "../Logger.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

@interface CustomViewController () <UIDocumentPickerDelegate>
@property (nonatomic, strong) LaraManager *mgr;
@property (nonatomic, copy)   NSString *targetPath;
@property (nonatomic, copy)   NSString *sourcePath;
@property (nonatomic, copy)   NSString *sourceName;
@property (nonatomic, assign) BOOL isOverwriting;
@property (nonatomic, weak)   UITextField *targetField;
@end

@implementation CustomViewController

- (instancetype)initWithMgr:(LaraManager *)mgr {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _mgr = mgr;
        _targetPath = @"/";
        _sourcePath = @"";
        _sourceName = @"No file selected";
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Custom Overwrite";
}

#pragma mark - Table View

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 2; }

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return section == 0 ? 4 : 1;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return section == 0 ? @"Custom Path Overwrite" : @"Log";
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == 0) {
        return @"This will overwrite the target file with the selected source file.\nTarget size must be >= source size.";
    }
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc]
        initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];

    if (indexPath.section == 1) {
        cell.textLabel.text = [[Logger shared] logs].lastObject ?: @"No logs yet.";
        cell.textLabel.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
        cell.textLabel.numberOfLines = 0;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }

    switch (indexPath.row) {
        case 0: {
            // Target path text field
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            UITextField *tf = [[UITextField alloc] initWithFrame:cell.contentView.bounds];
            tf.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
            tf.placeholder = @"/path/to/target";
            tf.text = self.targetPath;
            tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
            tf.autocorrectionType = UITextAutocorrectionTypeNo;
            tf.translatesAutoresizingMaskIntoConstraints = NO;
            [tf addTarget:self action:@selector(targetChanged:) forControlEvents:UIControlEventEditingChanged];
            [cell.contentView addSubview:tf];
            [NSLayoutConstraint activateConstraints:@[
                [tf.leadingAnchor constraintEqualToAnchor:cell.contentView.leadingAnchor constant:16],
                [tf.trailingAnchor constraintEqualToAnchor:cell.contentView.trailingAnchor constant:-16],
                [tf.centerYAnchor constraintEqualToAnchor:cell.contentView.centerYAnchor],
            ]];
            self.targetField = tf;
            break;
        }
        case 1:
            cell.textLabel.text = @"Source";
            cell.detailTextLabel.text = self.sourceName;
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            break;
        case 2:
            cell.textLabel.text = @"Choose Source File";
            break;
        case 3: {
            BOOL canOverwrite = self.mgr.vfsReady && self.targetPath.length > 0 && self.sourcePath.length > 0 && !self.isOverwriting;
            cell.textLabel.text = self.isOverwriting ? @"Overwriting..." : @"Overwrite Target";
            if (!canOverwrite) {
                cell.textLabel.textColor = UIColor.secondaryLabelColor;
                cell.selectionStyle = UITableViewCellSelectionStyleNone;
            }
            break;
        }
    }
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section != 0) return;
    if (indexPath.row == 2) [self chooseSource];
    if (indexPath.row == 3) [self overwrite];
}

#pragma mark - Actions

- (void)targetChanged:(UITextField *)tf {
    self.targetPath = tf.text ?: @"";
    [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:3 inSection:0]]
                          withRowAnimation:UITableViewRowAnimationNone];
}

- (void)chooseSource {
    UIDocumentPickerViewController *picker;
    if (@available(iOS 14.0, *)) {
        picker = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeItem] asCopy:YES];
    } else {
        picker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.item"] inMode:UIDocumentPickerModeImport];
    }
    picker.delegate = self;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (!url) return;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *tmp = [NSTemporaryDirectory() stringByAppendingPathComponent:
                     [NSString stringWithFormat:@"vfs_custom_%@", [[NSUUID UUID] UUIDString]]];

    NSError *err;
    if ([fm fileExistsAtPath:tmp]) [fm removeItemAtPath:tmp error:nil];
    if ([fm copyItemAtURL:url toURL:[NSURL fileURLWithPath:tmp] error:&err]) {
        self.sourcePath = tmp;
        self.sourceName = url.lastPathComponent;
        [self.mgr logMessage:[NSString stringWithFormat:@"selected source: %@", self.sourceName]];
    } else {
        [self.mgr logMessage:[NSString stringWithFormat:@"failed to import source: %@", err.localizedDescription]];
    }
    [self.tableView reloadData];
}

- (void)overwrite {
    BOOL canOverwrite = self.mgr.vfsReady && self.targetPath.length > 0 && self.sourcePath.length > 0 && !self.isOverwriting;
    if (!canOverwrite) return;

    self.isOverwriting = YES;
    [self.tableView reloadData];

    NSString *target = self.targetPath;
    NSString *source = self.sourcePath;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL ok = [self.mgr vfsOverwriteFromLocalPath:target source:source];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.isOverwriting = NO;
            NSString *msg = ok
                ? [NSString stringWithFormat:@"overwrite ok: %@", target]
                : [NSString stringWithFormat:@"overwrite failed: %@", target];
            [self.mgr logMessage:msg];
            [self.tableView reloadData];
        });
    });
}

@end
