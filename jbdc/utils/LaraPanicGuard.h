//
//  LaraPanicGuard.h
//  Lara Jailbreak - Panic Protection & Logging
//
//  Защита от kernel panic с аварийным сохранением логов
//  Совместимо с iOS 17.3.1 (rootless)
//

#import <Foundation/Foundation.h>
#import <os/log.h>

NS_ASSUME_NONNULL_BEGIN

/// Уровень важности лога
typedef NS_ENUM(NSInteger, LaraLogLevel) {
    LaraLogLevelDebug = 0,
    LaraLogLevelInfo = 1,
    LaraLogLevelWarning = 2,
    LaraLogLevelError = 3,
    LaraLogLevelCritical = 4,
    LaraLogLevelPanic = 5
};

/// Контекст паники для сохранения
typedef struct {
    uint64_t timestamp;
    uint32_t cpu_id;
    uint64_t exception_type;
    uint64_t exception_code;
    uint64_t lr;  // Link Register
    uint64_t pc;  // Program Counter
    uint64_t sp;  // Stack Pointer
    uint64_t x[29];  // General purpose registers
    char message[256];
    char backtrace[1024];
} LaraPanicContext;

/// Менеджер защиты от паники и логирования
@interface LaraPanicGuard : NSObject

/// Singleton instance
+ (instancetype)sharedInstance;

/// Инициализация системы логирования
/// @param logPath Путь к директории логов (обычно Documents/CrashLogs)
/// @param enablePanicHook Включить перехват паник
- (void)initializeWithLogPath:(NSString *)logPath panicHookEnabled:(BOOL)enablePanicHook;

/// Запись лога с уровнем важности
/// @param level Уровень важности
/// @param format Формат сообщения
- (void)logLevel:(LaraLogLevel)level format:(NSString *)format, ... NS_FORMAT_FUNCTION(2,3);

/// Запись лога с меткой времени и потоком
- (void)logVerbose:(NSString *)tag message:(NSString *)message;

/// Принудительная синхронизация логов на диск
/// Вызывать перед критическими операциями
- (void)flushLogs;

/// Сохранение контекста паники в NAND
/// @param context Контекст паники
- (void)savePanicContext:(const LaraPanicContext *)context;

/// Проверка наличия сохранённых паник после перезагрузки
- (NSArray<LaraPanicContext *> *)loadSavedPanics;

/// Очистка старых логов (старше 7 дней)
- (void)cleanupOldLogs;

/// Получение пути к текущему лог-файлу
- (NSString *)currentLogFilePath;

/// Включение режима "чёрного ящика" (кольцевой буфер в RAM)
- (void)enableBlackBoxMode;

/// Извлечение данных из чёрного ящика после паники
- (NSData *)extractBlackBoxData;

/// Регистрация callback перед паникой
typedef void (^LaraPrePanicCallback)(void);
- (void)registerPrePanicCallback:(LaraPrePanicCallback)callback;

/// Генерация отчёта о панике для отправки разработчику
- (NSDictionary *)generatePanicReport;

@end

/// Макросы для удобного логирования
#define LARA_LOG_DEBUG(fmt, ...) [[LaraPanicGuard sharedInstance] logLevel:LaraLogLevelDebug format:@fmt, ##__VA_ARGS__]
#define LARA_LOG_INFO(fmt, ...) [[LaraPanicGuard sharedInstance] logLevel:LaraLogLevelInfo format:@fmt, ##__VA_ARGS__]
#define LARA_LOG_WARN(fmt, ...) [[LaraPanicGuard sharedInstance] logLevel:LaraLogLevelWarning format:@fmt, ##__VA_ARGS__]
#define LARA_LOG_ERROR(fmt, ...) [[LaraPanicGuard sharedInstance] logLevel:LaraLogLevelError format:@fmt, ##__VA_ARGS__]
#define LARA_LOG_CRITICAL(fmt, ...) [[LaraPanicGuard sharedInstance] logLevel:LaraLogLevelCritical format:@fmt, ##__VA_ARGS__]
#define LARA_LOG_PANIC(fmt, ...) [[LaraPanicGuard sharedInstance] logLevel:LaraLogLevelPanic format:@fmt, ##__VA_ARGS__]

/// Макрос для автоматической записи входа/выхода из функции
#define LARA_TRACE() \
    __attribute__((cleanup(cleanupTrace))) \
    const char *_trace_##__LINE__ = lara_trace_enter(__FUNCTION__); \
    static void cleanupTrace(const char **func) { \
        if (*func) LARA_LOG_DEBUG(@"[TRACE] Exit: %s", *func); \
    }

const char* lara_trace_enter(const char *function);

NS_ASSUME_NONNULL_END
