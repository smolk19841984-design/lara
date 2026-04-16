//
//  SantanderViewController.h
//  lara
//
//  Rewritten in Objective-C (was SantanderView.swift + SantanderPathListViewController)
//

#import <UIKit/UIKit.h>

@interface SantanderPathListViewController : UITableViewController <UISearchResultsUpdating, UISearchBarDelegate, UIDocumentPickerDelegate>
- (instancetype)initWithPath:(NSString *)path readUsesSBX:(BOOL)readSBX useVFSOverwrite:(BOOL)vfsOverwrite;
@end
