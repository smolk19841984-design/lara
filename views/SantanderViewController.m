//
//  SantanderViewController.m
//  lara
//
//  Rewritten in Objective-C (was SantanderView.swift + SantanderPathListViewController)
//

#import "SantanderViewController.h"
#import "../LaraManager.h"
#import <MobileCoreServices/MobileCoreServices.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

// ─── File entry model ────────────────────────────────────────────────────────
@interface SantanderEntry : NSObject
@property (nonatomic, copy) NSString *path;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, assign) BOOL isDirectory;
+ (instancetype)entryWithPath:(NSString *)path isDirectory:(BOOL)isDir;
@end

@implementation SantanderEntry
+ (instancetype)entryWithPath:(NSString *)path isDirectory:(BOOL)isDir {
    SantanderEntry *e = [[SantanderEntry alloc] init];
    e.path = path;
    e.name = (path.length == 1 && [path isEqualToString:@"/"]) ? @"/" : path.lastPathComponent;
    e.isDirectory = isDir;
    return e;
}
@end

// ─── Clipboard ───────────────────────────────────────────────────────────────
@interface SantanderClipboard : NSObject
@property (nonatomic, copy) NSString *path;
@property (nonatomic, assign) BOOL isDirectory;
@property (nonatomic, copy) NSString *name;
@end

@implementation SantanderClipboard @end

// ─── Simple text viewer ──────────────────────────────────────────────────────
@interface SantanderTextViewController : UIViewController
- (instancetype)initWithPath:(NSString *)path readSBX:(BOOL)sbx writeVFS:(BOOL)vfs;
@end

@implementation SantanderTextViewController {
    NSString *_path;
    BOOL _readSBX, _writeVFS;
    UITextView *_textView;
}

- (instancetype)initWithPath:(NSString *)path readSBX:(BOOL)sbx writeVFS:(BOOL)vfs {
    self = [super init];
    _path = path;
    _readSBX = sbx;
    _writeVFS = vfs;
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = _path.lastPathComponent;
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    _textView = [[UITextView alloc] initWithFrame:self.view.bounds];
    _textView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    _textView.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    _textView.editable = _writeVFS;
    [self.view addSubview:_textView];

    // Load content
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSData *data = nil;
        if (self->_readSBX) {
            data = [NSData dataWithContentsOfFile:self->_path];
        } else {
            data = [[LaraManager shared] vfsRead:self->_path maxSize:512 * 1024];
        }
        NSString *text = data ? ([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"<binary data>") : @"<failed to read>";
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_textView.text = text;
        });
    });

    if (_writeVFS) {
        UIBarButtonItem *save = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemSave
                                                                             target:self
                                                                             action:@selector(saveFile)];
        self.navigationItem.rightBarButtonItem = save;
    }
}

- (void)saveFile {
    NSData *data = [_textView.text dataUsingEncoding:NSUTF8StringEncoding];
    if (!data) return;
    BOOL ok = [[LaraManager shared] vfsWrite:_path data:data];
    NSString *msg = ok ? @"Saved!" : @"Save failed.";
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:nil message:msg preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end

// ─── Main file browser ────────────────────────────────────────────────────────
@interface SantanderPathListViewController ()
@property (nonatomic, copy)   NSString *currentPath;
@property (nonatomic, assign) BOOL readUsesSBX;
@property (nonatomic, assign) BOOL useVFSOverwrite;
@property (nonatomic, strong) NSArray<SantanderEntry *> *allEntries;
@property (nonatomic, strong) NSArray<SantanderEntry *> *filteredEntries;
@property (nonatomic, assign) BOOL isSearching;
@property (nonatomic, assign) BOOL displayHidden;
@end

static SantanderClipboard *s_clipboard = nil;

@implementation SantanderPathListViewController

- (instancetype)initWithPath:(NSString *)path readUsesSBX:(BOOL)readSBX useVFSOverwrite:(BOOL)vfsOverwrite {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _currentPath = path ?: @"/";
        _readUsesSBX = readSBX;
        _useVFSOverwrite = vfsOverwrite;
        _displayHidden = YES;
        _allEntries = @[];
        _filteredEntries = @[];
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = [_currentPath isEqualToString:@"/"] ? @"/" : _currentPath.lastPathComponent;
    self.navigationController.navigationBar.prefersLargeTitles = YES;
    self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeAlways;

    // Search
    UISearchController *search = [[UISearchController alloc] initWithSearchResultsController:nil];
    search.searchResultsUpdater = self;
    search.searchBar.delegate = self;
    search.obscuresBackgroundDuringPresentation = NO;
    self.navigationItem.searchController = search;
    self.navigationItem.hidesSearchBarWhenScrolling = NO;
    self.definesPresentationContext = YES;

    // Right bar buttons
    [self setupRightBarButtons];

    // Load directory
    [self loadDirectory];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    self.title = [_currentPath isEqualToString:@"/"] ? @"/" : _currentPath.lastPathComponent;
}

#pragma mark - Directory Loading

- (void)loadDirectory {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSArray<SantanderEntry *> *entries = [self entriesForPath:self.currentPath];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.allEntries = entries;
            [self applyFilters:@""];
        });
    });
}

- (NSArray<SantanderEntry *> *)entriesForPath:(NSString *)path {
    LaraManager *mgr = [LaraManager shared];
    NSMutableArray *result = [NSMutableArray array];

    if (self.readUsesSBX) {
        NSError *err;
        NSArray *names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:path error:&err];
        for (NSString *name in names) {
            NSString *full = [path isEqualToString:@"/"]
                ? [@"/" stringByAppendingString:name]
                : [path stringByAppendingPathComponent:name];
            BOOL isDir; [[NSFileManager defaultManager] fileExistsAtPath:full isDirectory:&isDir];
            [result addObject:[SantanderEntry entryWithPath:full isDirectory:isDir]];
        }
    } else {
        NSArray<NSDictionary *> *listing = [mgr vfsListDir:path];
        for (NSDictionary *entry in listing) {
            NSString *name = entry[@"name"];
            NSString *full = [path isEqualToString:@"/"]
                ? [@"/" stringByAppendingString:name]
                : [path stringByAppendingPathComponent:name];
            BOOL isDir = [entry[@"isDir"] boolValue];
            [result addObject:[SantanderEntry entryWithPath:full isDirectory:isDir]];
        }
    }

    [result sortUsingComparator:^NSComparisonResult(SantanderEntry *a, SantanderEntry *b) {
        return [a.name localizedCaseInsensitiveCompare:b.name];
    }];
    return result;
}

#pragma mark - Filtering

- (void)applyFilters:(NSString *)query {
    NSArray *base = self.allEntries;
    if (!self.displayHidden) {
        base = [base filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(SantanderEntry *e, id _) {
            return ![e.name hasPrefix:@"."];
        }]];
    }
    if (query.length > 0) {
        base = [base filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(SantanderEntry *e, id _) {
            return [e.name localizedCaseInsensitiveContainsString:query] ||
                   [e.path localizedCaseInsensitiveContainsString:query];
        }]];
    }
    self.filteredEntries = base;

    if (self.filteredEntries.count == 0) {
        UILabel *lbl = [[UILabel alloc] init];
        lbl.text = query.length > 0 ? @"No matching items." : @"Directory is empty.";
        lbl.textColor = UIColor.secondaryLabelColor;
        lbl.textAlignment = NSTextAlignmentCenter;
        lbl.numberOfLines = 0;
        self.tableView.backgroundView = lbl;
    } else {
        self.tableView.backgroundView = nil;
    }

    [self.tableView reloadData];
}

#pragma mark - UISearchResultsUpdating

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController {
    NSString *query = [searchController.searchBar.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    self.isSearching = query.length > 0;
    [self applyFilters:query];
}

- (void)searchBarCancelButtonClicked:(UISearchBar *)searchBar {
    self.isSearching = NO;
    [self applyFilters:@""];
}

#pragma mark - Table View

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 1; }

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return (NSInteger)self.filteredEntries.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    return @"This file manager may display inaccurate information.";
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    SantanderEntry *entry = self.filteredEntries[indexPath.row];

    cell.textLabel.text = entry.name;
    if (self.isSearching) {
        cell.detailTextLabel.text = entry.path;
        cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
    }

    NSString *imgName = entry.isDirectory ? @"folder.fill" : @"doc";
    cell.imageView.image = [UIImage systemImageNamed:imgName];
    cell.accessoryType = entry.isDirectory ? UITableViewCellAccessoryDisclosureIndicator : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    SantanderEntry *entry = self.filteredEntries[indexPath.row];

    if (entry.isDirectory) {
        SantanderPathListViewController *vc = [[SantanderPathListViewController alloc]
            initWithPath:entry.path readUsesSBX:self.readUsesSBX useVFSOverwrite:self.useVFSOverwrite];
        [self.navigationController pushViewController:vc animated:YES];
    } else {
        SantanderTextViewController *vc = [[SantanderTextViewController alloc]
            initWithPath:entry.path readSBX:self.readUsesSBX writeVFS:self.useVFSOverwrite];
        [self.navigationController pushViewController:vc animated:YES];
    }
}

- (UIContextMenuConfiguration *)tableView:(UITableView *)tableView
    contextMenuConfigurationForRowAtIndexPath:(NSIndexPath *)indexPath
                                        point:(CGPoint)point
API_AVAILABLE(ios(13.0)) {
    SantanderEntry *entry = self.filteredEntries[indexPath.row];
    __weak typeof(self) weakSelf = self;

    return [UIContextMenuConfiguration configurationWithIdentifier:nil
                                                   previewProvider:nil
                                                    actionProvider:^UIMenu *(NSArray *sugg) {
        UIAction *copy = [UIAction actionWithTitle:@"Copy"
                                            image:[UIImage systemImageNamed:@"doc.on.doc"]
                                       identifier:nil
                                          handler:^(UIAction *a) {
            SantanderClipboard *clip = [[SantanderClipboard alloc] init];
            clip.path = entry.path;
            clip.isDirectory = entry.isDirectory;
            clip.name = entry.name;
            s_clipboard = clip;
        }];

        BOOL canReplace = s_clipboard != nil && weakSelf.useVFSOverwrite;
        UIMenuElementAttributes repAttr = canReplace ? 0 : UIMenuElementAttributesDisabled;
        UIAction *replace = [UIAction actionWithTitle:@"Replace With Clipboard"
                                               image:[UIImage systemImageNamed:@"doc.on.clipboard"]
                                          identifier:nil
                                             handler:^(UIAction *a) {
            [weakSelf replaceEntry:entry withClipboard:s_clipboard];
        }];
        replace.attributes = repAttr;

        UIAction *del = [UIAction actionWithTitle:@"Delete"
                                           image:[UIImage systemImageNamed:@"trash"]
                                      identifier:nil
                                         handler:^(UIAction *a) {
            [weakSelf confirmDelete:entry];
        }];
        del.attributes = UIMenuElementAttributesDestructive;

        return [UIMenu menuWithTitle:@"" children:@[copy, replace, del]];
    }];
}

#pragma mark - File Operations

- (void)replaceEntry:(SantanderEntry *)target withClipboard:(SantanderClipboard *)clip {
    if (!clip) return;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *r = [[LaraManager shared] laraOverwriteFile:target.path source:clip.path];
        dispatch_async(dispatch_get_main_queue(), ^{
            [self showAlert:[r[@"ok"] boolValue] ? @"Replaced!" : r[@"message"]];
        });
    });
}

- (void)confirmDelete:(SantanderEntry *)entry {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Delete?"
                                                                   message:entry.path
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Delete" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
        NSError *err;
        [[NSFileManager defaultManager] removeItemAtPath:entry.path error:&err];
        [self loadDirectory];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

#pragma mark - Document Picker

- (void)presentUploadPicker {
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

    NSString *dest = [self.currentPath stringByAppendingPathComponent:url.lastPathComponent];
    NSError *err;
    [[NSFileManager defaultManager] copyItemAtURL:url toURL:[NSURL fileURLWithPath:dest] error:&err];
    if (err) [self showAlert:err.localizedDescription];
    [self loadDirectory];
}

#pragma mark - Right Bar Buttons

- (void)setupRightBarButtons API_AVAILABLE(ios(14.0)) {
    UIAction *upload = [UIAction actionWithTitle:@"Upload File"
                                          image:[UIImage systemImageNamed:@"square.and.arrow.down"]
                                     identifier:nil
                                        handler:^(UIAction *a) {
        [self presentUploadPicker];
    }];
    UIAction *sortAZ = [UIAction actionWithTitle:@"Sort A-Z"
                                          image:[UIImage systemImageNamed:@"textformat"]
                                     identifier:nil
                                        handler:^(UIAction *a) {
        self.allEntries = [self.allEntries sortedArrayUsingComparator:^NSComparisonResult(SantanderEntry *x, SantanderEntry *y) {
            return [x.name localizedCaseInsensitiveCompare:y.name];
        }];
        [self applyFilters:self.navigationItem.searchController.searchBar.text ?: @""];
    }];
    UIAction *sortZA = [UIAction actionWithTitle:@"Sort Z-A"
                                          image:[UIImage systemImageNamed:@"textformat"]
                                     identifier:nil
                                        handler:^(UIAction *a) {
        self.allEntries = [self.allEntries sortedArrayUsingComparator:^NSComparisonResult(SantanderEntry *x, SantanderEntry *y) {
            return [y.name localizedCaseInsensitiveCompare:x.name];
        }];
        [self applyFilters:self.navigationItem.searchController.searchBar.text ?: @""];
    }];
    UIAction *toggleHidden = [UIAction actionWithTitle:@"Toggle Hidden Files"
                                                image:[UIImage systemImageNamed:@"eye"]
                                           identifier:nil
                                              handler:^(UIAction *a) {
        self.displayHidden = !self.displayHidden;
        [self applyFilters:self.navigationItem.searchController.searchBar.text ?: @""];
    }];
    UIAction *goRoot = [UIAction actionWithTitle:@"Go to Root"
                                          image:[UIImage systemImageNamed:@"externaldrive"]
                                     identifier:nil
                                        handler:^(UIAction *a) {
        SantanderPathListViewController *vc = [[SantanderPathListViewController alloc]
            initWithPath:@"/" readUsesSBX:self.readUsesSBX useVFSOverwrite:self.useVFSOverwrite];
        [self.navigationController setViewControllers:@[vc] animated:YES];
    }];
    UIAction *goHome = [UIAction actionWithTitle:@"Go to Home"
                                          image:[UIImage systemImageNamed:@"house"]
                                     identifier:nil
                                        handler:^(UIAction *a) {
        SantanderPathListViewController *vc = [[SantanderPathListViewController alloc]
            initWithPath:NSHomeDirectory() readUsesSBX:self.readUsesSBX useVFSOverwrite:self.useVFSOverwrite];
        [self.navigationController setViewControllers:@[vc] animated:YES];
    }];

    UIMenu *sortMenu = [UIMenu menuWithTitle:@"Sort by…" image:[UIImage systemImageNamed:@"arrow.up.arrow.down"] identifier:nil options:0 children:@[sortAZ, sortZA]];
    UIMenu *viewMenu = [UIMenu menuWithTitle:@"View" image:[UIImage systemImageNamed:@"eye"] identifier:nil options:0 children:@[toggleHidden]];
    UIMenu *goMenu   = [UIMenu menuWithTitle:@"Go to…" image:[UIImage systemImageNamed:@"arrow.right"] identifier:nil options:0 children:@[goRoot, goHome]];
    UIMenu *menu     = [UIMenu menuWithTitle:@"" children:@[upload, sortMenu, viewMenu, goMenu]];

    UIBarButtonItem *btn = [[UIBarButtonItem alloc] initWithImage:[UIImage systemImageNamed:@"ellipsis.circle"]
                                                             menu:menu];
    self.navigationItem.rightBarButtonItem = btn;
}

#pragma mark - Helpers

- (void)showAlert:(NSString *)msg {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:nil message:msg preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
