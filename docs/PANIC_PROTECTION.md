# Lara Jailbreak - Panic Protection & Logging

## Обзор

Модуль защиты от kernel panic с полным логированием для rootless джейлбрейка iOS 17.3.1.

## Компоненты

### LaraPanicGuard.h/m
- **Перехват сигналов**: SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGTRAP
- **Сохранение контекста**: Регистры, backtrace, timestamp
- **Чёрный ящик**: Кольцевой буфер 64KB в RAM (persist через panic)
- **Логирование**: 
  - Файловые логи в Documents/CrashLogs
  - os_log integration
  - Уровни: Debug, Info, Warning, Error, Critical, Panic
- **Pre-panic callbacks**: Сохранение состояния перед паникой
- **Отчёты**: JSON + binary format для отладки

### LaraBootstrap.m
- Точка входа приложения
- Ранняя инициализация PanicGuard
- Интеграция с LaraJailbreakCore
- Lifecycle callbacks с логированием

## Использование

### Инициализация
```objc
NSString *logPath = [documentsPath stringByAppendingPathComponent:@"CrashLogs"];
[[LaraPanicGuard sharedInstance] initializeWithLogPath:logPath panicHookEnabled:YES];
```

### Логирование
```objc
LARA_LOG_INFO(@"Exploit started");
LARA_LOG_ERROR(@"Kernel read failed at 0x%llx", address);
LARA_LOG_CRITICAL(@"Panic imminent!");
```

### Trace функций
```objc
- (void)criticalFunction {
    LARA_TRACE();
    // ... код будет автоматически залогирован при входе/выходе
}
```

### Pre-panic callback
```objc
[[LaraPanicGuard sharedInstance] registerPrePanicCallback:^{
    // Сохранить состояние эксплойта
    [self.jailbreakCore saveStateBeforePanic];
    [[LaraPanicGuard sharedInstance] flushLogs];
}];
```

### Извлечение логов после паники
```objc
// Проверка сохранённых паник
NSArray *panics = [[LaraPanicGuard sharedInstance] loadSavedPanics];
if (panics.count > 0) {
    LaraPanicContext context;
    [panics.firstObject getValue:&context];
    NSLog(@"Last panic at PC: 0x%llx", context.pc);
}

// Чёрный ящик
NSData *blackBox = [[LaraPanicGuard sharedInstance] extractBlackBoxData];

// Полный отчёт
NSDictionary *report = [[LaraPanicGuard sharedInstance] generatePanicReport];
```

## Структура логов

### Формат строки
```
[YYYY-MM-DD HH:mm:ss.SSS] [THREAD_ID] [LEVEL] MESSAGE
```

### Пример
```
[2025-01-15 14:23:45.123] [0x684c3a000] [INFO] Darksword exploit starting
[2025-01-15 14:23:45.456] [0x684c3a000] [DEBUG] IOSurface initialized
[2025-01-15 14:23:45.789] [0x684c3a000] [ERROR] Kernel write failed: permission denied
```

### Panic Context (JSON)
```json
{
  "timestamp": 1737024225,
  "cpu_id": 2,
  "exception_type": 11,
  "exception_code": 1,
  "pc": "0xfffffff007384abc",
  "lr": "0xfffffff007384d00",
  "sp": "0xfffffff1e3c07b40",
  "message": "Signal 11 at PC: 0xfffffff007384abc",
  "backtrace": "...",
  "registers": ["x0: 0x...", "x1: 0x...", ...]
}
```

## Сборка через WSL

```bash
# Из PowerShell
wsl bash scripts/build_ipa_wsl.sh

# Или напрямую в WSL
bash scripts/build_ipa_wsl.sh
```

Скрипт:
1. Компилирует все .m файлы из jbdc/
2. Включает LaraPanicGuard автоматически
3. Подписывает ldid с entitlements
4. Генерирует TrustCache для helper binaries
5. Упаковывает в IPA

## Особенности

- **Атомарная запись**: fflush + fsync для гарантированной записи на NAND
- **Потокобезопасность**: pthread_mutex для concurrent logging
- **Авто-ротация**: Хранит последние 10 логов
- **Очистка**: Удаляет логи старше 7 дней
- **Black Box**: Данные сохраняются даже при kernel panic
- **Trace макрос**: Автоматическое логирование входа/выхода из функций

## Интеграция с джейлбрейком

1. Добавить `#import "LaraPanicGuard.h"` во все модули
2. Использовать макросы LARA_LOG_* вместо NSLog
3. Вызывать `flushLogs()` перед критическими операциями
4. Register pre-panic callback для сохранения state

## Отладка паник

После kernel panic:
1. Перезагрузить устройство
2. Открыть приложение
3. Проверить Documents/CrashLogs/panic_*.json
4. Извлечь black box data
5. Отправить отчёт разработчику

## Лицензия

MIT License - Lara Jailbreak Project
