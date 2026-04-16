//
//  PasscodeViewController.h
//  lara
//
//  Rewritten in Objective-C (was PasscodeView.swift)
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

/// Displays a 10-key passcode grid (0–9) letting the user assign custom background images
/// to each digit key and apply or restore them.
@interface PasscodeViewController : UIViewController <UIDocumentPickerDelegate, UICollectionViewDelegate, UICollectionViewDataSource>
@end

NS_ASSUME_NONNULL_END
