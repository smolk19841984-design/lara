//
// LaraTargetProfile.m — фиксированный профиль под одно устройство (ваш кейс).
//

#import "LaraTargetProfile.h"
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>

static BOOL _read_machine(char *buf, size_t bufsize) {
    size_t len = bufsize;
    if (sysctlbyname("hw.machine", buf, &len, NULL, 0) != 0) {
        buf[0] = '\0';
        return NO;
    }
    buf[bufsize - 1] = '\0';
    return YES;
}

BOOL lara_is_primary_target_device(void) {
    char machine[64];
    if (!_read_machine(machine, sizeof(machine))) {
        return NO;
    }
    if (strcmp(machine, "iPad8,9") != 0) {
        return NO;
    }
    NSOperatingSystemVersion v = [NSProcessInfo processInfo].operatingSystemVersion;
    if (v.majorVersion != 17 || v.minorVersion != 3) {
        return NO;
    }
    return YES;
}

void lara_apply_single_device_profile(void) {
    if (!lara_is_primary_target_device()) {
        char machine[64] = {0};
        _read_machine(machine, sizeof(machine));
        NSOperatingSystemVersion v = [NSProcessInfo processInfo].operatingSystemVersion;
        NSLog(@"[LaraTarget] Профиль 17.3.x/iPad8,9 не применён: machine=%s OS=%ld.%ld.%ld",
              machine, (long)v.majorVersion, (long)v.minorVersion, (long)v.patchVersion);
        return;
    }

    // Совпадает с рекомендациями для 21D61 arm64e: remote-call SBX отключён (паника copy_validate).
    setenv("LARA_ENABLE_REMOTE_CALL_SBX", "0", 1);
    // Не форсить сокетный kwrite в sandbox object — использовать PPL в sbx_bypass при наличии GPU/MMIO.
    unsetenv("LARA_FORCE_SBX_SOCKET_KWRITE");
    // Сильный escape по /var/tmp, не слабый по /var/mobile.
    unsetenv("LARA_WEAK_SBX_OK");

    NSLog(@"[LaraTarget] Профиль iPad8,9 + iOS 17.3.x активен: LARA_ENABLE_REMOTE_CALL_SBX=0, PPL-трансплант без force socket kwrite");
}
