//
//  LaraBootstrap.m
//  Lara Jailbreak - Main Entry Point with Panic Protection
//
//  Главная точка входа с интеграцией защиты от паники
//  iOS 17.3.1 rootless jailbreak
//

#import <UIKit/UIKit.h>
#import "LaraPanicGuard.h"
#import "darksword.h"
#import "shadow_pages.h"
#import "offset_finder.h"
#import "kernel_patcher.h"

@interface LaraAppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@property (assign, nonatomic) BOOL exploitSuccessful;
@end

@implementation LaraAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // Инициализация защиты от паники и логирования
    [self setupPanicProtection];
    
    // Создание окна
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    
    // Запуск процесса джейлбрейка
    [self runJailbreakProcess];
    
    // Простой UI для отображения статуса
    UIViewController *statusVC = [[UIViewController alloc] init];
    statusVC.view.backgroundColor = [UIColor blackColor];
    
    UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(20, 100, 300, 50)];
    label.textColor = [UIColor whiteColor];
    label.font = [UIFont systemFontOfSize:18];
    label.numberOfLines = 0;
    
    if (self.exploitSuccessful) {
        label.text = @"✅ Jailbreak Successful!\nRoot obtained, patches applied.";
    } else {
        label.text = @"❌ Jailbreak Failed.\nCheck logs for details.";
    }
    
    [statusVC.view addSubview:label];
    self.window.rootViewController = statusVC;
    [self.window makeKeyAndVisible];
    
    LARA_LOG_INFO(@"Application launched successfully");
    
    return YES;
}

- (void)setupPanicProtection {
    // Путь к логам в Documents
    NSString *documentsPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *logPath = [documentsPath stringByAppendingPathComponent:@"CrashLogs"];
    
    // Инициализация PanicGuard
    [[LaraPanicGuard sharedInstance] initializeWithLogPath:logPath panicHookEnabled:YES];
    
    LARA_LOG_INFO(@"Panic protection initialized at %@", logPath);
}

- (void)runJailbreakProcess {
    LARA_LOG_INFO(@"=== Starting Jailbreak Process ===");
    
    self.exploitSuccessful = NO;
    
    // Шаг 1: Инициализация эксплойта (Darksword)
    LARA_LOG_INFO(@"[Step 1/4] Initializing Darksword exploit...");
    if (!ds_init()) {
        LARA_LOG_CRITICAL(@"[FAIL] Darksword initialization failed!");
        return;
    }
    LARA_LOG_INFO(@"[OK] Darksword initialized, kernel base: 0x%llx", get_kernel_base());
    
    // Шаг 2: Инициализация Shadow Pages (обход PPL)
    LARA_LOG_INFO(@"[Step 2/4] Initializing Shadow Pages...");
    if (!shadow_pages_init()) {
        LARA_LOG_CRITICAL(@"[FAIL] Shadow Pages initialization failed!");
        ds_cleanup();
        return;
    }
    LARA_LOG_INFO(@"[OK] Shadow Pages ready");
    
    // Шаг 3: Поиск оффсетов
    LARA_LOG_INFO(@"[Step 3/4] Finding kernel offsets...");
    if (!find_kernel_offsets(get_kernel_base())) {
        LARA_LOG_CRITICAL(@"[FAIL] Offset finding failed!");
        shadow_cleanup();
        ds_cleanup();
        return;
    }
    LARA_LOG_INFO(@"[OK] Offsets found");
    
    // Шаг 4: Применение патчей ядра
    LARA_LOG_INFO(@"[Step 4/4] Applying kernel patches...");
    if (!apply_kernel_patches()) {
        LARA_LOG_CRITICAL(@"[FAIL] Kernel patching failed!");
        shadow_cleanup();
        ds_cleanup();
        return;
    }
    LARA_LOG_INFO(@"[OK] All patches applied");
    
    // Успех!
    self.exploitSuccessful = YES;
    LARA_LOG_INFO(@"=== Jailbreak Completed Successfully ===");
}

- (void)applicationWillResignActive:(UIApplication *)application {
    LARA_LOG_DEBUG(@"Application will resign active");
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    LARA_LOG_INFO(@"Application did enter background");
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    LARA_LOG_INFO(@"Application will enter foreground");
}

- (void)applicationWillTerminate:(UIApplication *)application {
    LARA_LOG_INFO(@"Application will terminate");
    // Очистка ресурсов
    shadow_cleanup();
    ds_cleanup();
}

@end

#pragma mark - Main Entry

int main(int argc, char * argv[]) {
    @autoreleasepool {
        // Ранняя инициализация логирования (до UIApplicationMain)
        NSString *documentsPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *logPath = [documentsPath stringByAppendingPathComponent:@"CrashLogs"];
        
        [[LaraPanicGuard sharedInstance] initializeWithLogPath:logPath panicHookEnabled:YES];
        
        LARA_LOG_INFO(@"=== Lara Jailbreak Starting ===");
        LARA_LOG_INFO(@"Device: %@", [[UIDevice currentDevice] model]);
        LARA_LOG_INFO(@"iOS Version: %@", [[UIDevice currentDevice] systemVersion]);
        
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([LaraAppDelegate class]));
    }
}
