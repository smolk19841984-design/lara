#import "TerminalViewController.h"
#import "../kexploit/term.h"

@interface TerminalViewController () <UITextFieldDelegate>
@property (nonatomic, strong) NSLayoutConstraint *inputBottomConstraint;
@end

@implementation TerminalViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:0.12 green:0.12 blue:0.18 alpha:1.0];
    self.title = @"Terminal";
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"Clear" style:UIBarButtonItemStylePlain target:self action:@selector(clearOutput)];
    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"?" style:UIBarButtonItemStylePlain target:self action:@selector(showHelp)];

    term_init();

    self.outputBuffer = [NSMutableString string];

    // Output view
    self.outputView = [[UITextView alloc] initWithFrame:CGRectZero];
    self.outputView.editable = NO;
    self.outputView.selectable = YES;
    self.outputView.backgroundColor = [UIColor clearColor];
    self.outputView.textColor = [UIColor colorWithRed:0.2 green:1.0 blue:0.2 alpha:1.0];
    self.outputView.font = [UIFont fontWithName:@"Menlo" size:13.0];
    if (!self.outputView.font) {
        self.outputView.font = [UIFont monospacedSystemFontOfSize:13.0 weight:UIFontWeightRegular];
    }
    self.outputView.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);
    [self.view addSubview:self.outputView];

    // Input field
    self.inputField = [[UITextField alloc] initWithFrame:CGRectZero];
    self.inputField.backgroundColor = [UIColor colorWithRed:0.15 green:0.15 blue:0.22 alpha:1.0];
    self.inputField.textColor = [UIColor colorWithRed:0.2 green:1.0 blue:0.2 alpha:1.0];
    self.inputField.font = [UIFont fontWithName:@"Menlo" size:14.0];
    if (!self.inputField.font) {
        self.inputField.font = [UIFont monospacedSystemFontOfSize:14.0 weight:UIFontWeightRegular];
    }
    self.inputField.attributedPlaceholder = [[NSAttributedString alloc] initWithString:@"Enter command..." attributes:@{NSForegroundColorAttributeName: [UIColor colorWithRed:0.4 green:0.6 blue:0.4 alpha:1.0]}];
    self.inputField.borderStyle = UITextBorderStyleRoundedRect;
    self.inputField.layer.borderColor = [UIColor colorWithRed:0.2 green:0.6 blue:0.2 alpha:0.5].CGColor;
    self.inputField.layer.borderWidth = 1.0;
    self.inputField.delegate = self;
    self.inputField.returnKeyType = UIReturnKeySend;
    self.inputField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.inputField.autocorrectionType = UITextAutocorrectionTypeNo;
    self.inputField.spellCheckingType = UITextSpellCheckingTypeNo;
    [self.view addSubview:self.inputField];

    // Layout using NSLayoutConstraints
    self.outputView.translatesAutoresizingMaskIntoConstraints = NO;
    UILayoutGuide *safeArea = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.outputView.topAnchor constraintEqualToAnchor:safeArea.topAnchor constant:8],
        [self.outputView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:8],
        [self.outputView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-8],
        [self.outputView.bottomAnchor constraintEqualToAnchor:self.inputField.topAnchor constant:-8],
    ]];

    self.inputField.translatesAutoresizingMaskIntoConstraints = NO;
    self.inputBottomConstraint = [self.inputField.bottomAnchor constraintEqualToAnchor:safeArea.bottomAnchor constant:-8];
    [NSLayoutConstraint activateConstraints:@[
        [self.inputField.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:8],
        [self.inputField.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-8],
        self.inputBottomConstraint,
        [self.inputField.heightAnchor constraintEqualToConstant:44],
    ]];

    // Keyboard notifications
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(keyboardWillShow:) name:UIKeyboardWillShowNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(keyboardWillHide:) name:UIKeyboardWillHideNotification object:nil];

    // Welcome message
    [self appendOutput:@"lara Terminal v1.0\n"];
    [self appendOutput:@"iOS 17.3.1 - Kernel R/W Backend\n"];
    [self appendOutput:@"Type 'help' or tap ? for available commands.\n\n"];
    [self appendPrompt];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)keyboardWillShow:(NSNotification *)note {
    NSDictionary *info = note.userInfo;
    CGRect kbFrame = [info[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    CGFloat kbHeight = kbFrame.size.height;
    
    [UIView animateWithDuration:[info[UIKeyboardAnimationDurationUserInfoKey] doubleValue]
                          delay:0
                        options:[info[UIKeyboardAnimationCurveUserInfoKey] integerValue] << 16
                     animations:^{
        self.inputBottomConstraint.constant = -kbHeight - 8;
        [self.view layoutIfNeeded];
    } completion:nil];
}

- (void)keyboardWillHide:(NSNotification *)note {
    NSDictionary *info = note.userInfo;
    
    [UIView animateWithDuration:[info[UIKeyboardAnimationDurationUserInfoKey] doubleValue]
                          delay:0
                        options:[info[UIKeyboardAnimationCurveUserInfoKey] integerValue] << 16
                     animations:^{
        self.inputBottomConstraint.constant = -8;
        [self.view layoutIfNeeded];
    } completion:nil];
}

- (void)appendPrompt {
    [self appendOutput:[NSString stringWithFormat:@"lara:/var/mobile$ "]];
}

- (void)appendOutput:(NSString *)text {
    [self.outputBuffer appendString:text];
    self.outputView.text = self.outputBuffer;
    // Scroll to bottom
    if (self.outputView.text.length > 0) {
        NSRange bottom = NSMakeRange(self.outputView.text.length - 1, 1);
        [self.outputView scrollRangeToVisible:bottom];
    }
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    NSString *cmd = textField.text;
    textField.text = @"";

    if (cmd.length > 0) {
        [self appendOutput:[NSString stringWithFormat:@"%@\n", cmd]];

        const char *cmdStr = [cmd UTF8String];
        size_t outLen = 0;
        char *result = term_exec(cmdStr, &outLen);
        if (result) {
            NSString *output = [[NSString alloc] initWithBytes:result length:outLen encoding:NSUTF8StringEncoding];
            if (output) {
                [self appendOutput:output];
            }
            free(result);
        }

        [self appendPrompt];
    }

    return YES;
}

- (void)clearOutput {
    [self.outputBuffer setString:@""];
    self.outputView.text = @"";
    [self appendPrompt];
}

- (void)showHelp {
    NSString *helpText = @"Available Commands:\n\n"
        "── File System ──\n"
        "ls [path]       List directory\n"
        "cd <path>       Change directory\n"
        "pwd             Print working directory\n"
        "cat <file>      Read file\n"
        "touch <file>    Create empty file\n"
        "rm <file>       Delete file\n"
        "mkdir <dir>     Create directory\n"
        "cp <src> <dst>  Copy file\n"
        "mv <src> <dst>  Move file\n"
        "chmod <mode> <f> Change permissions\n"
        "du [path]       Disk usage\n"
        "head <file>     First 10 lines\n"
        "tail <file>     Last 10 lines\n"
        "wc <file>       Word/line count\n"
        "file <path>     File type\n"
        "grep <pat> <f>  Search in file\n"
        "stat <file>     File info\n"
        "find <path> <n> Find files\n\n"
        "── System ──\n"
        "ps              List processes\n"
        "id              User info\n"
        "uname           System info\n"
        "uptime          System uptime\n"
        "date            Current date/time\n"
        "env             Environment vars\n"
        "free            Memory usage\n"
        "sysctl [key]    System parameters\n"
        "dmesg [n]       Kernel log\n"
        "mount           Mount list\n"
        "df              Disk free space\n\n"
        "── Network ──\n"
        "ifconfig        Network interfaces\n"
        "netstat         Network stats\n\n"
        "── Other ──\n"
        "help            Show this help\n"
        "clear           Clear terminal\n"
        "echo <text>     Print text\n"
        "whoami          Current user\n";

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Terminal Help" message:helpText preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
