//
//  ZeroViewController.h
//  lara
//
//  Rewritten in Objective-C (was ZeroView.swift)
//

#import <UIKit/UIKit.h>
@class LaraManager;

@interface ZeroViewController : UITableViewController
- (instancetype)initWithMgr:(LaraManager *)mgr;
@end
