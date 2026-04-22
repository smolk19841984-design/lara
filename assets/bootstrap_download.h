#ifndef BOOTSTRAP_DOWNLOAD_H
#define BOOTSTRAP_DOWNLOAD_H

#import <Foundation/Foundation.h>

// Проверка наличия загруженного bootstrap
BOOL bootstrap_is_downloaded(void);

// Асинхронная загрузка bootstrap с completion handler
void bootstrap_download_async(void (^completion)(BOOL success, NSError *error));

// Синхронная загрузка (блокирующая)
BOOL bootstrap_download_sync(NSError **outError);

// Распаковка bootstrap в указанную директорию
BOOL bootstrap_extract_to(NSString *destinationPath);

// Инициализация bootstrap (загрузка + распаковка если нужно)
BOOL bootstrap_init(NSString *jbRootPath);

// Очистка загруженного bootstrap
void bootstrap_cleanup(void);

#endif /* BOOTSTRAP_DOWNLOAD_H */
