//
//  LaraBootstrap.m
//  Lara Jailbreak - Main Entry Point with Panic Protection
//
//  Главная точка входа с интеграцией защиты от паники
//  iOS 17.3.1 rootless jailbreak
//

#import <UIKit/UIKit.h>
#import "LaraPanicGuard.h"
#import "LaraJailbreakCore.h"
#import "LaraViewController.h"

@interface LaraAppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@property (strong, nonatomic) LaraJailbreakCore *jailbreakCore;
@end

@implementation LaraAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // Инициализация защиты от паники и логирования
    [self setupPanicProtection];
    
    // Создание окна
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    
    // Инициализация ядра джейлбрейка
    self.jailbreakCore = [[LaraJailbreakCore alloc] init];
    
    // Главный контроллер
    LaraViewController *viewController = [[LaraViewController alloc] initWithJailbreakCore:self.jailbreakCore];
    UINavigationController *navController = [[UINavigationController alloc] initWithRootViewController:viewController];
    
    self.window.rootViewController = navController;
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
    
    // Регистрация callback перед паникой для сохранения состояния
    [[LaraPanicGuard sharedInstance] registerPrePanicCallback:^{
        LARA_LOG_CRITICAL(@"Pre-panic callback: Saving jailbreak state...");
        
        // Сохранение состояния эксплойта
        if (self.jailbreakCore) {
            [self.jailbreakCore saveStateBeforePanic];
        }
        
        // Принудительная синхронизация
        [[LaraPanicGuard sharedInstance] flushLogs];
    }];
    
    LARA_LOG_INFO(@"Panic protection initialized at %@", logPath);
}

- (void)applicationWillResignActive:(UIApplication *)application {
    LARA_LOG_DEBUG(@"Application will resign active");
    [self.jailbreakCore pauseOperations];
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    LARA_LOG_INFO(@"Application did enter background");
    [self.jailbreakCore saveState];
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    LARA_LOG_INFO(@"Application will enter foreground");
    [self.jailbreakCore resumeOperations];
}

- (void)applicationWillTerminate:(UIApplication *)application {
    LARA_LOG_INFO(@"Application will terminate");
    [self.jailbreakCore cleanup];
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
