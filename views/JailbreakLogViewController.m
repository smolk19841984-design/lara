//
//  JailbreakLogViewController.m
//  lara
//

#import "JailbreakLogViewController.h"
#import "../LaraManager.h"

@interface JailbreakLogViewController ()
@property (nonatomic, strong) UITextView *textView;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) NSTimer *pollTimer;
@property (nonatomic, assign) BOOL didLaunchPipeline;
@end

@implementation JailbreakLogViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    self.title = NSLocalizedString(@"Jailbreak", nil);

    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc]
        initWithTitle:NSLocalizedString(@"Close", nil)
                style:UIBarButtonItemStylePlain
               target:self
               action:@selector(closeTapped)];

    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithTitle:NSLocalizedString(@"Copy", nil)
                style:UIBarButtonItemStylePlain
               target:self
               action:@selector(copyTapped)];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
    self.statusLabel.textColor = [UIColor secondaryLabelColor];
    self.statusLabel.text = @"";

    self.textView = [[UITextView alloc] init];
    self.textView.translatesAutoresizingMaskIntoConstraints = NO;
    self.textView.editable = NO;
    self.textView.selectable = YES;
    self.textView.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    self.textView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    self.textView.layer.cornerRadius = 8;
    self.textView.clipsToBounds = YES;
    self.textView.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);

    [self.view addSubview:self.statusLabel];
    [self.view addSubview:self.textView];

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.statusLabel.topAnchor constraintEqualToAnchor:g.topAnchor constant:12],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],
        [self.textView.topAnchor constraintEqualToAnchor:self.statusLabel.bottomAnchor constant:8],
        [self.textView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:8],
        [self.textView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-8],
        [self.textView.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-8],
    ]];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    if (!self.didLaunchPipeline) {
        self.didLaunchPipeline = YES;
        [self startPipelineIfNeeded];
    }
    [self startPolling];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [self stopPolling];
}

- (void)startPipelineIfNeeded {
    LaraManager *mgr = [LaraManager shared];
    if (mgr.pipelineRunning) {
        self.statusLabel.text = NSLocalizedString(@"A jailbreak run is already in progress — log updates below.", nil);
        return;
    }
    self.statusLabel.text = NSLocalizedString(@"Running exploit and method steps…", nil);
    self.statusLabel.textColor = [UIColor labelColor];
    __weak typeof(self) weakSelf = self;
    [mgr runFullJailbreakPipelineWithCompletion:^(BOOL success, NSString *err) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) {
            return;
        }
        if (success) {
            self.statusLabel.text = NSLocalizedString(@"Finished successfully. See log below; check Files → lara.log for a file copy.", nil);
            self.statusLabel.textColor = [UIColor systemGreenColor];
        } else {
            self.statusLabel.text = [NSString stringWithFormat:@"%@: %@",
                                     NSLocalizedString(@"Stopped", nil),
                                     err ?: NSLocalizedString(@"unknown error", nil)];
            self.statusLabel.textColor = [UIColor systemRedColor];
        }
    }];
}

- (void)startPolling {
    [self stopPolling];
    __weak typeof(self) weakSelf = self;
    self.pollTimer = [NSTimer scheduledTimerWithTimeInterval:0.2 repeats:YES block:^(NSTimer *timer) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) {
            return;
        }
        LaraManager *m = [LaraManager shared];
        NSString *t = m.log;
        if (t.length == 0) {
            t = NSLocalizedString(@"(log will appear as steps run…)", nil);
        }
        if (![t isEqualToString:self.textView.text]) {
            self.textView.text = t;
            NSRange end = NSMakeRange(t.length, 0);
            [self.textView scrollRangeToVisible:end];
        }
    }];
    [[NSRunLoop mainRunLoop] addTimer:self.pollTimer forMode:NSRunLoopCommonModes];
}

- (void)stopPolling {
    [self.pollTimer invalidate];
    self.pollTimer = nil;
}

- (void)closeTapped {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)copyTapped {
    NSString *t = [LaraManager shared].log;
    if (t.length) {
        [UIPasteboard generalPasteboard].string = t;
    }
    self.statusLabel.text = NSLocalizedString(@"Log copied to the pasteboard.", nil);
    self.statusLabel.textColor = [UIColor labelColor];
}

@end
