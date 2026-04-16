//
//  SettingsViewController.h
//  lara
//
//  Rewritten in Objective-C (was SettingsView.swift)
//

#import <UIKit/UIKit.h>

@interface SettingsViewController : UITableViewController
@property (nonatomic, copy) void (^onOffsetsChanged)(BOOL hasOffsets);
@end
