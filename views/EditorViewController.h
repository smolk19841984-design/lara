//
//  EditorViewController.h
//  lara
//
//  Rewritten in Objective-C (was EditorView.swift)
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface EditorViewController : UIViewController <UIDocumentPickerDelegate>

/// Designated initializer.
/// @param path    Filesystem path to the plist file to edit.
/// @param useSBX  If YES, read via NSFileManager; if NO, read via VFS.
/// @param useVFS  If YES, write via VFS overwrite; if NO, attempt NSFileManager.
- (instancetype)initWithPath:(NSString *)path readUsesSBX:(BOOL)useSBX writeUsesVFS:(BOOL)useVFS;

/// Convenience – opens the MobileGestalt plist directly.
+ (instancetype)mobileGestaltEditor;

@end

NS_ASSUME_NONNULL_END
