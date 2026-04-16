//
//  EditorViewController.m
//  lara
//
//  Rewritten in Objective-C (was EditorView.swift)
//

#import "EditorViewController.h"
#import "../LaraManager.h"
#import "../Logger.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

static NSString *const kMobileGestaltPath =
    @"/var/containers/Shared/SystemGroup/"
    @"systemgroup.com.apple.mobilegestaltcache/Library/Caches/"
    @"com.apple.MobileGestalt.plist";

@interface EditorViewController ()
@end

@implementation EditorViewController {
    NSString   *_path;
    BOOL        _readSBX;
    BOOL        _writeVFS;

    UITextView      *_textView;
    UILabel         *_statusLabel;
    NSString        *_savedText;
    BOOL            _hasUnsavedChanges;
    BOOL            _isSearching;
    NSString        *_lastQuery;
    NSArray<NSValue *> *_searchRanges;
    NSInteger       _searchIndex;

    UIBarButtonItem *_saveBtn;
    UIBarButtonItem *_findBtn;
    UIBarButtonItem *_formatBtn;
    UIBarButtonItem *_lookupBtn;
}

#pragma mark - Init

- (instancetype)initWithPath:(NSString *)path readUsesSBX:(BOOL)useSBX writeUsesVFS:(BOOL)useVFS {
    self = [super init];
    _path      = path;
    _readSBX   = useSBX;
    _writeVFS  = useVFS;
    _searchRanges = @[];
    _searchIndex  = 0;
    return self;
}

+ (instancetype)mobileGestaltEditor {
    return [[EditorViewController alloc] initWithPath:kMobileGestaltPath readUsesSBX:NO writeUsesVFS:YES];
}

#pragma mark - View Lifecycle

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = _path.lastPathComponent;
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    [self buildTextView];
    [self buildStatusLabel];
    [self buildToolbar];
    [self setupKeyboardObservers];
    [self loadFile];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    if (_hasUnsavedChanges) {
        // Only warn if going back; if sheet dismiss that's fine
    }
}

#pragma mark - Layout

- (void)buildTextView {
    _textView = [[UITextView alloc] init];
    _textView.translatesAutoresizingMaskIntoConstraints = NO;
    _textView.font      = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    _textView.editable  = _writeVFS;
    _textView.scrollEnabled = YES;
    _textView.autocorrectionType = UITextAutocorrectionTypeNo;
    _textView.autocapitalizationType = UITextAutocapitalizationTypeNone;
    _textView.delegate  = (id<UITextViewDelegate>)self;
    [self.view addSubview:_textView];

    [NSLayoutConstraint activateConstraints:@[
        [_textView.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [_textView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [_textView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
    ]];
}

- (void)buildStatusLabel {
    _statusLabel = [[UILabel alloc] init];
    _statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _statusLabel.font = [UIFont systemFontOfSize:12];
    _statusLabel.textColor = UIColor.secondaryLabelColor;
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    _statusLabel.text = _path;
    _statusLabel.numberOfLines = 1;
    _statusLabel.lineBreakMode = NSLineBreakByTruncatingMiddle;
    [self.view addSubview:_statusLabel];

    [NSLayoutConstraint activateConstraints:@[
        [_statusLabel.topAnchor constraintEqualToAnchor:_textView.bottomAnchor],
        [_statusLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:8],
        [_statusLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-8],
        [_statusLabel.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-8],
        [_statusLabel.heightAnchor constraintEqualToConstant:24],
    ]];
}

- (void)buildToolbar {
    UIBarButtonItem *space = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:nil action:nil];

    _saveBtn   = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemSave
                                                               target:self action:@selector(save)];
    _findBtn   = [[UIBarButtonItem alloc] initWithImage:[UIImage systemImageNamed:@"magnifyingglass"]
                                                  style:UIBarButtonItemStylePlain target:self action:@selector(showFind)];
    _formatBtn = [[UIBarButtonItem alloc] initWithImage:[UIImage systemImageNamed:@"doc.text"]
                                                  style:UIBarButtonItemStylePlain target:self action:@selector(formatXML)];
    _lookupBtn = [[UIBarButtonItem alloc] initWithImage:[UIImage systemImageNamed:@"key.horizontal"]
                                                  style:UIBarButtonItemStylePlain target:self action:@selector(showKeyLookup)];

    if (!_writeVFS) _saveBtn.enabled = NO;

    self.navigationItem.rightBarButtonItems = @[_saveBtn, _findBtn, _lookupBtn, _formatBtn];
}

- (void)setupKeyboardObservers {
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserver:self selector:@selector(keyboardWillChangeFrame:)
               name:UIKeyboardWillChangeFrameNotification object:nil];
}

- (void)keyboardWillChangeFrame:(NSNotification *)n {
    CGRect kbFrame = [n.userInfo[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    CGRect converted = [self.view convertRect:kbFrame fromView:nil];
    CGFloat bottomInset = MAX(0, self.view.bounds.size.height - converted.origin.y);
    UIEdgeInsets insets = UIEdgeInsetsMake(0, 0, bottomInset, 0);
    _textView.contentInset = insets;
    _textView.scrollIndicatorInsets = insets;
}

#pragma mark - File Operations

- (void)loadFile {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSData *data = nil;
        if (self->_readSBX) {
            data = [NSData dataWithContentsOfFile:self->_path];
        } else {
            data = [[LaraManager shared] vfsRead:self->_path maxSize:1024 * 1024 * 4];
        }

        NSString *text = nil;
        if (data) {
            // Try reading as plist XML text
            text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            // If binary plist, convert to XML
            if (!text || [text hasPrefix:@"bplist"]) {
                id obj = [NSPropertyListSerialization propertyListWithData:data
                                                                   options:NSPropertyListImmutable
                                                                    format:nil
                                                                     error:nil];
                if (obj) {
                    NSData *xml = [NSPropertyListSerialization dataWithPropertyList:obj
                                                                             format:NSPropertyListXMLFormat_v1_0
                                                                            options:0
                                                                              error:nil];
                    text = xml ? [[NSString alloc] initWithData:xml encoding:NSUTF8StringEncoding] : @"<conversion failed>";
                } else {
                    text = @"<cannot parse plist>";
                }
            }
        } else {
            text = @"<failed to read file>";
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            self->_savedText = text;
            self->_textView.text = text;
            self->_hasUnsavedChanges = NO;
            [self updateTitle];
        });
    });
}

- (void)save {
    if (!_writeVFS) return;

    NSString *text = _textView.text ?: @"";

    // Validate XML property list before saving
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:nil error:&err];
    if (err) {
        NSString *msg = [NSString stringWithFormat:@"Warning: content may not be valid plist:\n%@\n\nSave anyway?", err.localizedDescription];
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Validation Warning"
                                                                       message:msg
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Save Anyway" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
            [self writeText:text];
        }]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }

    [self writeText:text];
}

- (void)writeText:(NSString *)text {
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    BOOL ok = [[LaraManager shared] vfsWrite:_path data:data];
    if (ok) {
        _savedText = text;
        _hasUnsavedChanges = NO;
        [self updateTitle];
        [[Logger shared] log:[NSString stringWithFormat:@"[editor] saved %@", _path]];
        [self showSnackbar:@"Saved!"];
    } else {
        [self showSnackbar:@"Save failed."];
    }
}

- (void)updateTitle {
    NSString *base = _path.lastPathComponent;
    self.title = _hasUnsavedChanges ? [base stringByAppendingString:@" •"] : base;
}

#pragma mark - UITextViewDelegate

- (void)textViewDidChange:(UITextView *)textView {
    _hasUnsavedChanges = ![textView.text isEqualToString:_savedText];
    [self updateTitle];
}

#pragma mark - Format XML

- (void)formatXML {
    NSString *text = _textView.text;
    if (!text.length) return;

    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    id obj = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListMutableContainersAndLeaves format:nil error:&err];
    if (!obj) {
        [self showSnackbar:[NSString stringWithFormat:@"Parse error: %@", err.localizedDescription]];
        return;
    }
    NSData *xml = [NSPropertyListSerialization dataWithPropertyList:obj
                                                             format:NSPropertyListXMLFormat_v1_0
                                                            options:0
                                                              error:nil];
    if (xml) {
        NSString *formatted = [[NSString alloc] initWithData:xml encoding:NSUTF8StringEncoding];
        _textView.text = formatted;
        _hasUnsavedChanges = ![formatted isEqualToString:_savedText];
        [self updateTitle];
    }
}

#pragma mark - Find

- (void)showFind {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Find"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *f) {
        f.placeholder = @"Search text…";
        f.text = self->_lastQuery;
        f.clearButtonMode = UITextFieldViewModeAlways;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Find Next" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSString *q = alert.textFields.firstObject.text;
        if (q.length == 0) return;
        [self searchNext:q];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)searchNext:(NSString *)query {
    NSString *text = _textView.text;
    if (!text.length || !query.length) return;

    if (![query isEqualToString:_lastQuery]) {
        _lastQuery = query;
        _searchIndex = 0;
        NSRange remaining = NSMakeRange(0, text.length);
        NSMutableArray *ranges = [NSMutableArray array];
        NSRange found;
        while (remaining.length > 0) {
            found = [text rangeOfString:query options:NSCaseInsensitiveSearch range:remaining];
            if (found.location == NSNotFound) break;
            [ranges addObject:[NSValue valueWithRange:found]];
            remaining = NSMakeRange(NSMaxRange(found), text.length - NSMaxRange(found));
        }
        _searchRanges = ranges;
    }

    if (_searchRanges.count == 0) {
        [self showSnackbar:@"Not found."];
        return;
    }

    NSRange r = [_searchRanges[_searchIndex % _searchRanges.count] rangeValue];
    _searchIndex++;

    _textView.selectedRange = r;
    [_textView scrollRangeToVisible:r];
    [self showSnackbar:[NSString stringWithFormat:@"%lu / %lu", (unsigned long)(_searchIndex), (unsigned long)_searchRanges.count]];
}

#pragma mark - Key Lookup

- (void)showKeyLookup {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Key Lookup"
                                                                   message:@"Enter a MobileGestalt key to find it in the plist."
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *f) {
        f.placeholder = @"e.g. ArtworkTraits";
        f.clearButtonMode = UITextFieldViewModeAlways;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Find" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSString *key = alert.textFields.firstObject.text;
        if (key.length > 0) [self searchNext:key];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

#pragma mark - Snackbar

- (void)showSnackbar:(NSString *)msg {
    _statusLabel.text = msg;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        self->_statusLabel.text = self->_path;
    });
}

@end
