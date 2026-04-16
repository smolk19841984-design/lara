//
//  CustomViewController.h
//  lara
//
//  Rewritten in Objective-C (was CustomView.swift)
//

#import <UIKit/UIKit.h>
@class LaraManager;

@interface CustomViewController : UITableViewController
- (instancetype)initWithMgr:(LaraManager *)mgr;
@end
