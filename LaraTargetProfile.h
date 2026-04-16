//
// Single-device defaults: iPad8,9 + iOS 17.3.x (incl. 17.3.1 build 21D61).
// Called at app launch before any exploit code runs.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Applies environment flags tuned for iPad8,9 on iOS 17.3.x. No-op on other devices.
void lara_apply_single_device_profile(void);

/// YES if hw.machine is iPad8,9 and OS is iOS 17.3.x.
BOOL lara_is_primary_target_device(void);

NS_ASSUME_NONNULL_END
