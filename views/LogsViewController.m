//
//  LogsViewController.m
//  lara
//
//  Rewritten in Objective-C
//

#import "LogsViewController.h"
#import "../Logger.h"

@implementation LogsViewController {
    NSArray<NSString *> *_displayedLogs;
}

- (instancetype)init {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Logs";

    UIBarButtonItem *clearBtn = [[UIBarButtonItem alloc]
        initWithTitle:@"Clear"
                style:UIBarButtonItemStylePlain
               target:self
               action:@selector(clearLogs)];
    self.navigationItem.rightBarButtonItem = clearBtn;

    _displayedLogs = [[Logger shared] logs];

    // Observe logs changes  
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(reloadLogs)
                                                 name:@"LaraLogsUpdated"
                                               object:nil];

    // Poll for updates (Logger doesn't post notifications, so we poll)
    [NSTimer scheduledTimerWithTimeInterval:0.5
                                     target:self
                                   selector:@selector(reloadLogs)
                                   userInfo:nil
                                    repeats:YES];
}

- (void)reloadLogs {
    NSArray *newLogs = [[Logger shared] logs];
    if (newLogs.count != _displayedLogs.count) {
        _displayedLogs = newLogs;
        [self.tableView reloadData];
        if (_displayedLogs.count > 0) {
            [self.tableView scrollToRowAtIndexPath:[NSIndexPath indexPathForRow:_displayedLogs.count - 1 inSection:0]
                                 atScrollPosition:UITableViewScrollPositionBottom
                                         animated:NO];
        }
    }
}

- (void)clearLogs {
    [[Logger shared] clear];
    _displayedLogs = @[];
    [self.tableView reloadData];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 1; }

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return MAX(1, (NSInteger)_displayedLogs.count);
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    if (_displayedLogs.count == 0) {
        cell.textLabel.text = @"No logs yet.";
        cell.textLabel.textColor = UIColor.secondaryLabelColor;
    } else {
        cell.textLabel.text = _displayedLogs[indexPath.row];
        cell.textLabel.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
        cell.textLabel.numberOfLines = 0;
    }
    return cell;
}

@end
