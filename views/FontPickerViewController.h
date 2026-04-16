//
//  FontPickerViewController.h
//  lara
//
//  Rewritten in Objective-C (was FontPicker.swift)
//

#import <UIKit/UIKit.h>
@class LaraManager;

@interface FontPickerViewController : UITableViewController
- (instancetype)initWithMgr:(LaraManager *)mgr;
@end
