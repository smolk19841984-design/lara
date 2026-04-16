//
//  AppsViewController.h
//  lara
//
//  Rewritten in Objective-C (was AppsView.swift)
//

#import <UIKit/UIKit.h>
@class LaraManager;

@interface AppsViewController : UITableViewController
- (instancetype)initWithMgr:(LaraManager *)mgr;
@end
