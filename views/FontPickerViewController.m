//
//  FontPickerViewController.m
//  lara
//
//  Rewritten in Objective-C (was FontPicker.swift)
//

#import "FontPickerViewController.h"
#import "../LaraManager.h"
#import "../Logger.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

// Imported font model  
@interface ImportedFont : NSObject <NSCoding>
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy) NSString *path;
- (instancetype)initWithName:(NSString *)name path:(NSString *)path;
@end

@implementation ImportedFont

- (instancetype)initWithName:(NSString *)name path:(NSString *)path {
    self = [super init];
    _name = [name copy];
    _path = [path copy];
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    _name = [coder decodeObjectForKey:@"name"];
    _path = [coder decodeObjectForKey:@"path"];
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:_name forKey:@"name"];
    [coder encodeObject:_path forKey:@"path"];
}

@end

static NSString *const kCustomFontsKey = @"customFonts";

static NSArray<ImportedFont *> *loadFonts(void) {
    NSData *data = [[NSUserDefaults standardUserDefaults] dataForKey:kCustomFontsKey];
    if (!data) return @[];
    NSError *err;
    NSArray *arr = [NSKeyedUnarchiver unarchivedArrayOfObjectsOfClass:[ImportedFont class]
                                                             fromData:data
                                                               error:&err];
    return arr ?: @[];
}

static void saveFonts(NSArray<ImportedFont *> *fonts) {
    NSError *err;
    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:fonts requiringSecureCoding:NO error:&err];
    if (data) [[NSUserDefaults standardUserDefaults] setObject:data forKey:kCustomFontsKey];
}

@interface FontPickerViewController () <UIDocumentPickerDelegate>
@property (nonatomic, strong) LaraManager *mgr;
@property (nonatomic, strong) NSMutableArray<ImportedFont *> *customFonts;
@end

@implementation FontPickerViewController

- (instancetype)initWithMgr:(LaraManager *)mgr {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _mgr = mgr;
        _customFonts = [loadFonts() mutableCopy];
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Font Overwrite";
}

#pragma mark - Table View

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 2; // Custom fonts, Log
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == 0) return self.customFonts.count + 1; // fonts + import button
    return 1; // log
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return section == 0 ? @"Custom Fonts" : @"Log";
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == 0) {
        return @"Some custom fonts may not work for app icons and other UI elements.";
    }
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];

    if (indexPath.section == 1) {
        cell.textLabel.text = [[Logger shared] logs].lastObject ?: @"No logs yet.";
        cell.textLabel.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
        cell.textLabel.numberOfLines = 0;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }

    if (indexPath.row < (NSInteger)self.customFonts.count) {
        ImportedFont *font = self.customFonts[indexPath.row];
        cell.textLabel.text = font.name;
    } else {
        cell.textLabel.text = @"Import Font";
    }
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    if (indexPath.section == 1) return;

    if (indexPath.row < (NSInteger)self.customFonts.count) {
        ImportedFont *font = self.customFonts[indexPath.row];
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:font.path]) {
            [self.mgr logMessage:[NSString stringWithFormat:@"custom font missing: %@", font.name]];
            [self.customFonts removeObjectAtIndex:indexPath.row];
            saveFonts(self.customFonts);
            [tableView reloadData];
            return;
        }
        BOOL ok = [self.mgr vfsOverwriteFromLocalPath:[LaraManager fontPath] source:font.path];
        [self.mgr logMessage:ok
            ? [NSString stringWithFormat:@"font changed to %@", font.name]
            : @"failed to change font"];
    } else {
        [self importFont];
    }
}

- (void)importFont {
    UIDocumentPickerViewController *picker;
    if (@available(iOS 14.0, *)) {
        picker = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeFont] asCopy:YES];
    } else {
        picker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.font"] inMode:UIDocumentPickerModeImport];
    }
    picker.delegate = self;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (!url) return;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dir  = [docs stringByAppendingPathComponent:@"Custom"];
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];

    NSString *dest = [dir stringByAppendingPathComponent:url.lastPathComponent];
    NSError *err;
    if (![fm fileExistsAtPath:dest]) {
        [fm copyItemAtURL:url toURL:[NSURL fileURLWithPath:dest] error:&err];
    }

    if (err) {
        NSLog(@"font import failed: %@", err);
        return;
    }

    NSString *name = url.URLByDeletingPathExtension.lastPathComponent;
    BOOL exists = NO;
    for (ImportedFont *f in self.customFonts) {
        if ([f.name isEqualToString:name]) { exists = YES; break; }
    }
    if (!exists) {
        ImportedFont *font = [[ImportedFont alloc] initWithName:name path:dest];
        [self.customFonts addObject:font];
        saveFonts(self.customFonts);
    }
    [self.tableView reloadData];
}

@end
