//
//  bootstrap_download.m - Загрузка bootstrap.tar из интернета
//  Lara Jailbreak - iPad8,9 iOS 17.3.1
//

#import "bootstrap_download.h"
#import <Foundation/Foundation.h>
#if TARGET_OS_IPHONE
#import <UIKit/UIKit.h>
#endif

static void bs_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void bs_log(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    NSLog(@"[Bootstrap] %s", buf);
}

// URL для загрузки bootstrap.tar (заглушка - замените на реальный URL)
#define BOOTSTRAP_URL @"https://github.com/LaraJailbreak/bootstrap/releases/download/v1.0/bootstrap.tar"

// Путь для сохранения загруженного файла
static NSString* get_bootstrap_path(void) {
    NSString *documentsPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [documentsPath stringByAppendingPathComponent:@"bootstrap.tar"];
}

// Проверка наличия загруженного bootstrap
BOOL bootstrap_is_downloaded(void) {
    NSString *bootstrapPath = get_bootstrap_path();
    BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:bootstrapPath];
    
    if (exists) {
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:bootstrapPath error:nil];
        unsigned long long size = [attrs fileSize];
        bs_log("Найден существующий bootstrap.tar (%llu байт)", size);
        
        // Минимальный размер для валидного bootstrap.tar (~1MB)
        if (size < 1000000ULL) {
            bs_log("Предупреждение: файл слишком маленький, возможна повторная загрузка");
        }
    }
    
    return exists;
}

// Асинхронная загрузка bootstrap с прогрессом
void bootstrap_download_async(void (^completion)(BOOL success, NSError *error)) {
    bs_log("Начало загрузки bootstrap.tar из: %s", [BOOTSTRAP_URL UTF8String]);
    
    NSURL *url = [NSURL URLWithString:BOOTSTRAP_URL];
    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    config.timeoutIntervalForRequest = 300; // 5 минут
    config.timeoutIntervalForResource = 600; // 10 минут
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config
                                                          delegate:nil
                                                     delegateQueue:nil];
    
    NSURLSessionDownloadTask *downloadTask = [session downloadTaskWithRequest:request
                                                            completionHandler:^(NSURL *location,
                                                                               NSURLResponse *response,
                                                                               NSError *error) {
        if (error) {
            bs_log("Ошибка загрузки: %s", [error.localizedDescription UTF8String]);
            if (completion) completion(NO, error);
            return;
        }
        
        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        if (httpResponse.statusCode != 200) {
            NSString *errStr = [NSString stringWithFormat:@"HTTP ошибка: %ld", (long)httpResponse.statusCode];
            bs_log("%s", [errStr UTF8String]);
            NSError *httpError = [NSError errorWithDomain:@"BootstrapDownload"
                                                     code:httpResponse.statusCode
                                                 userInfo:@{NSLocalizedDescriptionKey: errStr}];
            if (completion) completion(NO, httpError);
            return;
        }
        
        // Перемещаем файл во временное хранилище
        NSString *bootstrapPath = get_bootstrap_path();
        
        // Удаляем старый файл если существует
        [[NSFileManager defaultManager] removeItemAtPath:bootstrapPath error:nil];
        
        NSError *moveError = nil;
        BOOL moved = [[NSFileManager defaultManager] moveItemAtURL:location
                                                           toURL:[NSURL fileURLWithPath:bootstrapPath]
                                                           error:&moveError];
        
        if (!moved) {
            bs_log("Ошибка перемещения файла: %s", [[moveError localizedDescription] UTF8String]);
            if (completion) completion(NO, moveError);
            return;
        }
        
        // Проверяем размер загруженного файла
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:bootstrapPath error:nil];
        unsigned long long size = [attrs fileSize];
        bs_log("✓ Bootstrap успешно загружен: %llu байт", size);
        
        if (completion) completion(YES, nil);
    }];
    
    // Настраиваем прогресс загрузки
    [downloadTask setTaskDescription:@"Загрузка bootstrap.tar"];
    [downloadTask resume];
    
    bs_log("Загрузка запущена...");
}

// Синхронная загрузка (блокирующая, использовать только в тестах)
BOOL bootstrap_download_sync(NSError **outError) {
    __block BOOL success = NO;
    __block NSError *error = nil;
    
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    bootstrap_download_async(^(BOOL suc, NSError *err) {
        success = suc;
        error = err;
        dispatch_semaphore_signal(sema);
    });
    
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    
    if (outError) *outError = error;
    return success;
}

// Распаковка bootstrap.tar в директорию назначения
BOOL bootstrap_extract_to(NSString *destinationPath) {
    NSString *bootstrapPath = get_bootstrap_path();
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:bootstrapPath]) {
        bs_log("Ошибка: bootstrap.tar не найден");
        return NO;
    }
    
    bs_log("Распаковка bootstrap.tar в: %s", [destinationPath UTF8String]);
    
    // Создаем директорию назначения если не существует
    NSError *dirError = nil;
    if (![[NSFileManager defaultManager] fileExistsAtPath:destinationPath]) {
        if (![[NSFileManager defaultManager] createDirectoryAtPath:destinationPath
                                       withIntermediateDirectories:YES
                                                         attributes:nil
                                                              error:&dirError]) {
            bs_log("Ошибка создания директории: %s", [[dirError localizedDescription] UTF8String]);
            return NO;
        }
    }
    
    // Используем tar через posix_spawn (NSTask недоступен на iOS)
    NSString *tarPath = @"/usr/bin/tar";
    if (![[NSFileManager defaultManager] fileExistsAtPath:tarPath]) {
        tarPath = @"/bin/tar";
    }
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:tarPath]) {
        bs_log("Ошибка: tar не найден в системе");
        // Пытаемся распаковать через BSDArchive или другую библиотеку
        bs_log("Попытка альтернативной распаковки...");
        // Здесь должна быть реализация распаковки без внешнего tar
        return NO; // Заглушка - нужна реализация распаковки
    }
    
    #include <spawn.h>
    #include <sys/wait.h>
    extern char **environ;

    pid_t pid = 0;
    const char *argv[] = {
        [tarPath UTF8String],
        "-xf",
        [bootstrapPath UTF8String],
        "-C",
        [destinationPath UTF8String],
        NULL,
    };

    int rc = posix_spawn(&pid, argv[0], NULL, NULL, (char *const *)argv, environ);
    if (rc != 0) {
        bs_log("Ошибка запуска tar (posix_spawn rc=%d)", rc);
        return NO;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        bs_log("Ошибка waitpid для tar");
        return NO;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        bs_log("✓ Bootstrap успешно распакован");
        return YES;
    }

    bs_log("Ошибка распаковки (status=%d)", status);
    return NO;
}

// Главная функция инициализации bootstrap
BOOL bootstrap_init(NSString *jbRootPath) {
    bs_log("Инициализация bootstrap...");
    
    // Проверяем наличие загруженного bootstrap
    if (!bootstrap_is_downloaded()) {
        bs_log("Bootstrap не найден, требуется загрузка");
        // В реальном приложении здесь должен быть UI для запуска загрузки
        return NO;
    }
    
    // Распаковываем в root джейлбрейка
    if (!bootstrap_extract_to(jbRootPath)) {
        bs_log("Ошибка распаковки bootstrap");
        return NO;
    }
    
    bs_log("✓ Bootstrap готов к использованию");
    return YES;
}

// Удаление загруженного bootstrap (для очистки)
void bootstrap_cleanup(void) {
    NSString *bootstrapPath = get_bootstrap_path();
    NSError *error = nil;
    
    if ([[NSFileManager defaultManager] removeItemAtPath:bootstrapPath error:&error]) {
        bs_log("Bootstrap очищен");
    } else {
        bs_log("Ошибка очистки: %s", [[error localizedDescription] UTF8String]);
    }
}
