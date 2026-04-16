//
//  PasscodeViewController.m
//  lara
//
//  Rewritten in Objective-C (was PasscodeView.swift)
//

#import "PasscodeViewController.h"
#import "../LaraManager.h"
#import "../Logger.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <Photos/Photos.h>
#import <PhotosUI/PhotosUI.h>
#include <spawn.h>
#include <sys/wait.h>

// ─── Digit key model ─────────────────────────────────────────────────────────
@interface PasscodeKey : NSObject
@property (nonatomic, copy) NSString *keyId;   // "0"…"9"
@property (nonatomic, copy) NSString *label;
+ (instancetype)keyWithId:(NSString *)keyId;
- (NSString *)targetFilename;
@end

@implementation PasscodeKey
+ (instancetype)keyWithId:(NSString *)keyId {
    PasscodeKey *k = [[PasscodeKey alloc] init];
    k.keyId = keyId;
    k.label = keyId;
    return k;
}
- (NSString *)targetFilename {
    return [NSString stringWithFormat:@"other-2-%@--dark.png", self.keyId];
}
@end

// ─── Collection cell for a digit key ─────────────────────────────────────────
@interface PasscodeKeyCell : UICollectionViewCell
@property (nonatomic, strong) UIImageView *imageView;
@property (nonatomic, strong) UILabel *digitLabel;
@property (nonatomic, strong) UILabel *selectedLabel;
- (void)configureWithKey:(PasscodeKey *)key imageData:(NSData * _Nullable)imageData;
@end

@implementation PasscodeKeyCell

- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    self.contentView.backgroundColor = [UIColor colorWithDynamicProvider:^UIColor *(UITraitCollection *t) {
        return t.userInterfaceStyle == UIUserInterfaceStyleDark
            ? [UIColor colorWithWhite:0.2 alpha:1]
            : [UIColor colorWithWhite:0.88 alpha:1];
    }];
    self.contentView.layer.cornerRadius = 8;
    self.contentView.clipsToBounds = YES;

    _imageView = [[UIImageView alloc] initWithFrame:self.contentView.bounds];
    _imageView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    _imageView.contentMode = UIViewContentModeScaleAspectFill;
    _imageView.clipsToBounds = YES;
    [self.contentView addSubview:_imageView];

    _digitLabel = [[UILabel alloc] init];
    _digitLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _digitLabel.font = [UIFont systemFontOfSize:24 weight:UIFontWeightSemibold];
    _digitLabel.textAlignment = NSTextAlignmentCenter;
    [self.contentView addSubview:_digitLabel];
    [NSLayoutConstraint activateConstraints:@[
        [_digitLabel.centerXAnchor constraintEqualToAnchor:self.contentView.centerXAnchor],
        [_digitLabel.centerYAnchor constraintEqualToAnchor:self.contentView.centerYAnchor],
    ]];

    _selectedLabel = [[UILabel alloc] init];
    _selectedLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _selectedLabel.text = @"✓";
    _selectedLabel.textColor = UIColor.systemGreenColor;
    _selectedLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightBold];
    _selectedLabel.hidden = YES;
    [self.contentView addSubview:_selectedLabel];
    [NSLayoutConstraint activateConstraints:@[
        [_selectedLabel.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:4],
        [_selectedLabel.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-4],
    ]];
    return self;
}

- (void)configureWithKey:(PasscodeKey *)key imageData:(NSData *)imageData {
    _digitLabel.text = key.label;
    if (imageData) {
        _imageView.image = [UIImage imageWithData:imageData];
        _imageView.hidden = NO;
        _digitLabel.textColor = UIColor.whiteColor;
        _selectedLabel.hidden = NO;
    } else {
        _imageView.image = nil;
        _imageView.hidden = YES;
        _digitLabel.textColor = [UIColor labelColor];
        _selectedLabel.hidden = YES;
    }
}

@end

// ─── Main view controller ────────────────────────────────────────────────────
@interface PasscodeViewController () <PHPickerViewControllerDelegate>
@end

@implementation PasscodeViewController {
    UICollectionView   *_collectionView;
    UILabel            *_statusLabel;
    UIButton           *_applyBtn;

    // 12-slot layout matching the iOS passcode UI (4 rows × 3 cols, last row nil/0/nil)
    NSArray<NSString *> *_layout;   // nil represented by empty string ""
    NSArray<PasscodeKey *> *_keys;  // 10 keys 0-9
    NSDictionary<NSString *, PasscodeKey *> *_keyMap;

    NSMutableDictionary<NSString *, NSData *> *_selectedImages; // keyId → PNG data
    NSString *_pendingPickKeyId;  // key being picked

    NSArray<NSString *> *_telephonyVersions;
}

static NSString *const kCellId = @"PasscodeCell";

#pragma mark - Init

- (instancetype)init {
    self = [super init];
    _selectedImages = [NSMutableDictionary dictionary];
    _layout = @[@"1",@"2",@"3", @"4",@"5",@"6", @"7",@"8",@"9", @"",@"0",@""];

    NSMutableArray *keys = [NSMutableArray array];
    NSMutableDictionary *map = [NSMutableDictionary dictionary];
    for (NSInteger i = 0; i <= 9; i++) {
        PasscodeKey *k = [PasscodeKey keyWithId:[@(i) stringValue]];
        [keys addObject:k];
        map[k.keyId] = k;
    }
    _keys = keys;
    _keyMap = map;

    _telephonyVersions = @[
        @"TelephonyUI-15", @"TelephonyUI-14", @"TelephonyUI-13",
        @"TelephonyUI-12", @"TelephonyUI-11", @"TelephonyUI-10",
        @"TelephonyUI-9",  @"TelephonyUI-8"
    ];
    return self;
}

#pragma mark - View Lifecycle

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Passcode Theme";
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;

    [self buildLayout];
}

- (void)buildLayout {
    // --- Import button ---
    UIButton *importBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [importBtn setTitle:@"Import .passthm / .zip Theme" forState:UIControlStateNormal];
    [importBtn setImage:[UIImage systemImageNamed:@"square.and.arrow.down"] forState:UIControlStateNormal];
    importBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [importBtn addTarget:self action:@selector(importTheme) forControlEvents:UIControlEventTouchUpInside];

    // --- Collection view with 3-column grid ---
    UICollectionViewFlowLayout *layout = [[UICollectionViewFlowLayout alloc] init];
    layout.minimumInteritemSpacing = 4;
    layout.minimumLineSpacing = 4;
    _collectionView = [[UICollectionView alloc] initWithFrame:CGRectZero collectionViewLayout:layout];
    _collectionView.translatesAutoresizingMaskIntoConstraints = NO;
    _collectionView.delegate   = self;
    _collectionView.dataSource = self;
    _collectionView.backgroundColor = UIColor.clearColor;
    [_collectionView registerClass:[PasscodeKeyCell class] forCellWithReuseIdentifier:kCellId];

    // --- Apply button ---
    _applyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [_applyBtn setTitle:@"Apply Passcode Theme" forState:UIControlStateNormal];
    _applyBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [_applyBtn addTarget:self action:@selector(applyTheme) forControlEvents:UIControlEventTouchUpInside];

    // --- Status label ---
    _statusLabel = [[UILabel alloc] init];
    _statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    _statusLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
    _statusLabel.textColor = UIColor.secondaryLabelColor;
    _statusLabel.numberOfLines = 0;

    // --- Clear button ---
    UIButton *clearBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [clearBtn setTitle:@"Clear All Keys" forState:UIControlStateNormal];
    [clearBtn setTitleColor:UIColor.systemRedColor forState:UIControlStateNormal];
    clearBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [clearBtn addTarget:self action:@selector(clearAll) forControlEvents:UIControlEventTouchUpInside];

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
        importBtn, _collectionView, _applyBtn, _statusLabel, clearBtn
    ]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];

    [NSLayoutConstraint activateConstraints:@[
        [stack.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:16],
        [stack.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [stack.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],
        [stack.bottomAnchor constraintLessThanOrEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-16],
        // Make collection view take up a natural height (4 rows)
        [_collectionView.heightAnchor constraintEqualToAnchor:self.view.widthAnchor multiplier:0.85],
    ]];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    UICollectionViewFlowLayout *layout = (UICollectionViewFlowLayout *)_collectionView.collectionViewLayout;
    CGFloat side = (_collectionView.bounds.size.width - 8) / 3.0;
    layout.itemSize = CGSizeMake(side, side);
}

#pragma mark - UICollectionViewDataSource

- (NSInteger)collectionView:(UICollectionView *)collectionView numberOfItemsInSection:(NSInteger)section {
    return (NSInteger)_layout.count;
}

- (UICollectionViewCell *)collectionView:(UICollectionView *)collectionView cellForItemAtIndexPath:(NSIndexPath *)indexPath {
    PasscodeKeyCell *cell = [collectionView dequeueReusableCellWithReuseIdentifier:kCellId forIndexPath:indexPath];
    NSString *keyId = _layout[indexPath.item];
    if (keyId.length == 0) {
        // empty slot — return blank cell
        cell.contentView.backgroundColor = UIColor.clearColor;
        cell.digitLabel.text = @"";
        cell.imageView.hidden = YES;
        cell.selectedLabel.hidden = YES;
        return cell;
    }
    cell.contentView.backgroundColor = [UIColor colorWithDynamicProvider:^UIColor *(UITraitCollection *t) {
        return t.userInterfaceStyle == UIUserInterfaceStyleDark
            ? [UIColor colorWithWhite:0.2 alpha:1]
            : [UIColor colorWithWhite:0.88 alpha:1];
    }];
    PasscodeKey *key = _keyMap[keyId];
    NSData *imgData = _selectedImages[keyId];
    [cell configureWithKey:key imageData:imgData];
    return cell;
}

- (void)collectionView:(UICollectionView *)collectionView didSelectItemAtIndexPath:(NSIndexPath *)indexPath {
    NSString *keyId = _layout[indexPath.item];
    if (keyId.length == 0) return;
    _pendingPickKeyId = keyId;
    [self presentImagePickerForKeyId:keyId];
}

#pragma mark - Image Picker

- (void)presentImagePickerForKeyId:(NSString *)keyId {
    PHPickerConfiguration *config = [[PHPickerConfiguration alloc] init];
    config.filter = [PHPickerFilter imagesFilter];
    config.selectionLimit = 1;
    PHPickerViewController *picker = [[PHPickerViewController alloc] initWithConfiguration:config];
    picker.delegate = self;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)picker:(PHPickerViewController *)picker didFinishPicking:(NSArray<PHPickerResult *> *)results {
    [picker dismissViewControllerAnimated:YES completion:nil];
    PHPickerResult *result = results.firstObject;
    if (!result) return;

    NSString *keyId = _pendingPickKeyId;
    [result.itemProvider loadObjectOfClass:[UIImage class] completionHandler:^(id<NSItemProviderReading> obj, NSError *err) {
        UIImage *image = (UIImage *)obj;
        if (!image) return;
        UIImage *resized = [self resizeImage:image targetHeight:202];
        NSData *data = UIImagePNGRepresentation(resized);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (data && keyId) {
                self->_selectedImages[keyId] = data;
                [self->_collectionView reloadData];
            }
        });
    }];
}

- (UIImage *)resizeImage:(UIImage *)image targetHeight:(CGFloat)targetHeight {
    CGFloat scale = targetHeight / image.size.height;
    CGSize newSize = CGSizeMake(image.size.width * scale, targetHeight);
    UIGraphicsBeginImageContextWithOptions(newSize, NO, 0);
    [image drawInRect:CGRectMake(0, 0, newSize.width, newSize.height)];
    UIImage *result = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return result ?: image;
}

#pragma mark - Import Theme (.passthm / .zip)

- (void)importTheme {
    UIDocumentPickerViewController *picker;
    if (@available(iOS 14.0, *)) {
        UTType *zip = [UTType typeWithFilenameExtension:@"zip"];
        UTType *passthm = [UTType typeWithFilenameExtension:@"passthm"] ?: zip;
        picker = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[zip, passthm] asCopy:YES];
    } else {
        picker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.zip-archive"] inMode:UIDocumentPickerModeImport];
    }
    picker.delegate = self;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (!url) return;
    [self importFromURL:url];
}

- (void)importFromURL:(NSURL *)url {
    [self setStatus:@"Importing theme…" color:UIColor.secondaryLabelColor];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *err;
        // Unzip to temp dir
        NSString *tempDir = [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
        [[NSFileManager defaultManager] createDirectoryAtPath:tempDir
                                  withIntermediateDirectories:YES attributes:nil error:nil];

        // Use minizip / coordination; since ZIPFoundation is a Swift package we cannot use it here.
        // Instead copy the zip to temp and unzip using the system's NSFileManager + a mini unzip call.
        // We use a workaround: run /usr/bin/unzip from posix_spawn.
        NSString *zipPath = [tempDir stringByAppendingPathComponent:@"theme.zip"];
        NSData *data = [NSData dataWithContentsOfURL:url options:0 error:&err];
        if (!data) {
            [self setStatus:[NSString stringWithFormat:@"Error: %@", err.localizedDescription] color:UIColor.systemRedColor];
            return;
        }
        [data writeToFile:zipPath atomically:YES];

        // Unzip via posix_spawn (NSTask is macOS-only)
        NSString *unzipDir = [tempDir stringByAppendingPathComponent:@"extracted"];
        [[NSFileManager defaultManager] createDirectoryAtPath:unzipDir withIntermediateDirectories:YES attributes:nil error:nil];
        {
            const char *args[] = {
                "/usr/bin/unzip", "-o",
                zipPath.UTF8String,
                "-d", unzipDir.UTF8String,
                NULL
            };
            pid_t pid;
            posix_spawn(&pid, "/usr/bin/unzip", NULL, NULL, (char *const *)args, NULL);
            int status; waitpid(pid, &status, 0);
        }

        // Scan extracted files for key images
        NSMutableDictionary *found = [NSMutableDictionary dictionary];
        NSDirectoryEnumerator *en = [[NSFileManager defaultManager] enumeratorAtPath:unzipDir];
        NSString *rel;
        while ((rel = [en nextObject])) {
            NSString *fullPath = [unzipDir stringByAppendingPathComponent:rel];
            NSString *ext = fullPath.pathExtension.lowercaseString;
            if (![@[@"png",@"jpg",@"jpeg"] containsObject:ext]) continue;
            NSString *keyId = [self matchFilenameToKeyId:fullPath.lastPathComponent.lowercaseString]
                           ?: [self matchFilenameToKeyId:fullPath.lowercaseString];
            if (keyId && !found[keyId]) {
                NSData *imgData = [NSData dataWithContentsOfFile:fullPath];
                if (imgData) found[keyId] = imgData;
            }
        }

        // Cleanup
        [[NSFileManager defaultManager] removeItemAtPath:tempDir error:nil];

        dispatch_async(dispatch_get_main_queue(), ^{
            NSUInteger count = found.count;
            [found enumerateKeysAndObjectsUsingBlock:^(NSString *k, NSData *v, BOOL *stop) {
                self->_selectedImages[k] = v;
            }];
            [self->_collectionView reloadData];
            [self setStatus:[NSString stringWithFormat:@"Imported %lu key(s)", (unsigned long)count]
                      color:UIColor.systemGreenColor];
        });
    });
}

- (NSString * _Nullable)matchFilenameToKeyId:(NSString *)filename {
    for (NSInteger i = 0; i <= 9; i++) {
        NSString *d = [@(i) stringValue];
        // Check common patterns like other-2-0--dark, -0-, /0.png, _0_, etc.
        NSArray *patterns = @[
            [NSString stringWithFormat:@"other-2-%@--dark", d],
            [NSString stringWithFormat:@"-%@-", d],
            [NSString stringWithFormat:@"_%@_", d],
            [NSString stringWithFormat:@"/%@.png", d],
            [NSString stringWithFormat:@"/%@.jpg", d],
        ];
        for (NSString *p in patterns) {
            if ([filename containsString:p]) return d;
        }
    }
    return nil;
}

#pragma mark - Apply Theme

- (void)applyTheme {
    if (_selectedImages.count == 0) {
        [self setStatus:@"No keys selected." color:UIColor.systemOrangeColor];
        return;
    }
    if (![LaraManager shared].sbxReady) {
        [self setStatus:@"SBX not ready." color:UIColor.systemRedColor];
        return;
    }

    _applyBtn.enabled = NO;
    [self setStatus:@"Applying theme…" color:UIColor.secondaryLabelColor];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSString *basePath = [self resolveTelephonyBasePath];
        if (!basePath) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self->_applyBtn.enabled = YES;
                [self setStatus:@"Error: TelephonyUI cache not found." color:UIColor.systemRedColor];
            });
            return;
        }

        __block NSUInteger success = 0, fail = 0;
        [self->_selectedImages enumerateKeysAndObjectsUsingBlock:^(NSString *keyId, NSData *imgData, BOOL *stop) {
            NSString *filename = [NSString stringWithFormat:@"other-2-%@--dark.png", keyId];
            NSString *destPath = [basePath stringByAppendingPathComponent:filename];
            NSError *err;
            BOOL ok = [imgData writeToFile:destPath options:NSDataWritingAtomic error:&err];
            if (ok) {
                success++;
                [[Logger shared] log:[NSString stringWithFormat:@"[passcode] applied %@ -> %@", keyId, destPath]];
            } else {
                fail++;
                [[Logger shared] log:[NSString stringWithFormat:@"[passcode] failed %@: %@", keyId, err.localizedDescription]];
            }
        }];

        dispatch_async(dispatch_get_main_queue(), ^{
            self->_applyBtn.enabled = YES;
            NSString *msg = fail == 0
                ? [NSString stringWithFormat:@"Applied %lu key(s)", (unsigned long)success]
                : [NSString stringWithFormat:@"Applied %lu, failed %lu", (unsigned long)success, (unsigned long)fail];
            UIColor *color = fail == 0 ? UIColor.systemGreenColor : UIColor.systemOrangeColor;
            [self setStatus:msg color:color];
        });
    });
}

- (NSString * _Nullable)resolveTelephonyBasePath {
    NSMutableArray *candidates = [NSMutableArray array];
    for (NSString *v in _telephonyVersions) {
        [candidates addObject:[NSString stringWithFormat:@"/var/mobile/Library/Caches/%@", v]];
        [candidates addObject:[NSString stringWithFormat:@"/var/mobile/Library/Caches/com.apple.%@", v]];
        [candidates addObject:[NSString stringWithFormat:@"/var/mobile/Library/Caches/com.apple.%@", v.lowercaseString]];
        [candidates addObject:[NSString stringWithFormat:@"/var/mobile/Library/Caches/com.apple.TelephonyUI/%@", v]];
        [candidates addObject:[NSString stringWithFormat:@"/var/mobile/Library/Caches/com.apple.telephonyui/%@", v]];
    }
    for (NSString *path in candidates) {
        BOOL isDir;
        if ([[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDir] && isDir) {
            [[Logger shared] log:[NSString stringWithFormat:@"[passcode] TelephonyUI cache: %@", path]];
            return path;
        }
    }
    [[Logger shared] log:@"[passcode] TelephonyUI cache not found"];
    return nil;
}

#pragma mark - Clear

- (void)clearAll {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Clear All Keys?"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Clear" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
        [self->_selectedImages removeAllObjects];
        [self->_collectionView reloadData];
        [self setStatus:@"Cleared." color:UIColor.secondaryLabelColor];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

#pragma mark - Helpers

- (void)setStatus:(NSString *)msg color:(UIColor *)color {
    dispatch_async(dispatch_get_main_queue(), ^{
        self->_statusLabel.text = msg;
        self->_statusLabel.textColor = color;
    });
}

@end
