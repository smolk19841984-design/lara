//
//  CardViewController.m
//  lara
//
//  Rewritten in Objective-C (was CardView.swift)
//

#import "CardViewController.h"
#import "../LaraManager.h"
#import <Photos/Photos.h>

@interface CardItem : NSObject
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *imagePath;
@property (nonatomic, copy) NSString *directoryPath;
@property (nonatomic, copy) NSString *bundleName;
@property (nonatomic, copy) NSString *backgroundFileName;
@end
@implementation CardItem @end

@interface CardViewController () <UIImagePickerControllerDelegate, UINavigationControllerDelegate>
@property (nonatomic, strong) NSArray<CardItem *> *cards;
@property (nonatomic, assign) BOOL working;
@property (nonatomic, strong) CardItem *pendingCard;
@end

@implementation CardViewController

- (instancetype)init {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Card Overwrite";
    self.cards = @[];
}

#pragma mark - Card Scanning

- (void)refreshCards {
    if (self.working) return;
    self.working = YES;
    [self.tableView reloadData];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSArray *found = [self scanCards];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.cards = found;
            self.working = NO;
            [self.tableView reloadData];
        });
    });
}

- (NSArray<CardItem *> *)scanCards {
    NSMutableArray *result = [NSMutableArray array];
    NSString *root = @"/private/var/mobile/Library/Passes";
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *err;

    NSArray *uuids = [fm contentsOfDirectoryAtPath:root error:&err];
    if (!uuids) return result;

    for (NSString *uuid in uuids) {
        NSString *uuidPath = [root stringByAppendingPathComponent:uuid];
        BOOL isDir; [fm fileExistsAtPath:uuidPath isDirectory:&isDir];
        if (!isDir) continue;

        NSArray *bundles = [fm contentsOfDirectoryAtPath:uuidPath error:nil];
        for (NSString *bundle in bundles) {
            if (![bundle hasSuffix:@".pass"]) continue;
            NSString *bundlePath = [uuidPath stringByAppendingPathComponent:bundle];

            // Look for background image
            NSArray *candidates = @[@"background.png", @"background@2x.png", @"background@3x.png", @"logo.png", @"logo@2x.png"];
            for (NSString *bg in candidates) {
                NSString *imgPath = [bundlePath stringByAppendingPathComponent:bg];
                if ([fm fileExistsAtPath:imgPath]) {
                    CardItem *item = [[CardItem alloc] init];
                    item.identifier = [bundlePath stringByAppendingString:bg];
                    item.imagePath = imgPath;
                    item.directoryPath = bundlePath;
                    item.bundleName = [bundle stringByDeletingPathExtension];
                    item.backgroundFileName = bg;
                    [result addObject:item];
                    break;
                }
            }
        }
    }
    return result;
}

- (nullable UIImage *)previewImage:(CardItem *)card {
    return [UIImage imageWithContentsOfFile:card.imagePath];
}

#pragma mark - Image Replace

- (void)replaceCardImageWithPhotos:(CardItem *)card {
    self.pendingCard = card;
    UIImagePickerController *picker = [[UIImagePickerController alloc] init];
    picker.sourceType = UIImagePickerControllerSourceTypePhotoLibrary;
    picker.allowsEditing = NO;
    picker.delegate = self;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)imagePickerController:(UIImagePickerController *)picker didFinishPickingMediaWithInfo:(NSDictionary *)info {
    [picker dismissViewControllerAnimated:YES completion:nil];
    UIImage *img = info[UIImagePickerControllerOriginalImage];
    if (!img || !self.pendingCard) return;

    NSData *data = UIImagePNGRepresentation(img);
    if (!data) return;

    CardItem *card = self.pendingCard;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *r = [[LaraManager shared] laraOverwriteFileWithData:card.imagePath data:data];
        dispatch_async(dispatch_get_main_queue(), ^{
            [self showStatus:[r[@"ok"] boolValue] ? @"Card image replaced!" : r[@"message"]];
            [self refreshCards];
        });
    });
}

- (void)imagePickerControllerDidCancel:(UIImagePickerController *)picker {
    [picker dismissViewControllerAnimated:YES completion:nil];
}

- (void)restoreImage:(CardItem *)card {
    // For simplicity: zero the image (same as VFS zero page)
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        BOOL ok = [[LaraManager shared] vfsZeroPage:card.imagePath];
        dispatch_async(dispatch_get_main_queue(), ^{
            [self showStatus:ok ? @"Restored (zeroed)." : @"Failed to restore."];
            [self refreshCards];
        });
    });
}

#pragma mark - Table View

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1 + (NSInteger)self.cards.count;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == 0) return 1;
    return 3; // preview, replace, restore
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == 0) return @"Actions";
    return self.cards[section - 1].backgroundFileName;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == 0) return @"Uses SBX first and falls back to VFS for overwrite.";
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];

    if (indexPath.section == 0) {
        if (self.working) {
            cell.textLabel.text = @"Scanning...";
            UIActivityIndicatorView *sp = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
            [sp startAnimating];
            cell.accessoryView = sp;
        } else {
            cell.textLabel.text = self.cards.count == 0 ? @"Refresh (no cards found)" : @"Refresh";
        }
        return cell;
    }

    CardItem *card = self.cards[indexPath.section - 1];
    if (indexPath.row == 0) {
        // Preview
        cell.textLabel.text = card.bundleName;
        UIImage *preview = [self previewImage:card];
        if (preview) {
            UIImageView *iv = [[UIImageView alloc] initWithFrame:CGRectMake(0, 0, 90, 58)];
            iv.image = preview;
            iv.contentMode = UIViewContentModeScaleAspectFit;
            iv.layer.cornerRadius = 6;
            iv.clipsToBounds = YES;
            cell.accessoryView = iv;
        }
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
    } else if (indexPath.row == 1) {
        cell.textLabel.text = @"Replace with Photo";
    } else {
        cell.textLabel.text = @"Restore (zero)";
        cell.textLabel.textColor = UIColor.systemRedColor;
    }
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    if (indexPath.section == 0) {
        [self refreshCards];
        return;
    }

    CardItem *card = self.cards[indexPath.section - 1];
    if (indexPath.row == 1) {
        [self replaceCardImageWithPhotos:card];
    } else if (indexPath.row == 2) {
        [self restoreImage:card];
    }
}

- (void)showStatus:(NSString *)msg {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Status"
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
