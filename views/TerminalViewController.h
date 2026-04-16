#import <UIKit/UIKit.h>

@interface TerminalViewController : UIViewController

@property (nonatomic, strong) UITextView *outputView;
@property (nonatomic, strong) UITextField *inputField;
@property (nonatomic, strong) UIButton *sendButton;
@property (nonatomic, strong) NSMutableString *outputBuffer;

@end
