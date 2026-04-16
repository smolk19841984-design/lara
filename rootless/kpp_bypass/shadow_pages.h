//
//  shadow_pages.h
//  Lara Rootless Jailbreak - KPP/KTRR Bypass via Shadow Pages
//

#ifndef shadow_pages_h
#define shadow_pages_h

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define PAGE_SIZE 0x4000
#define PAGE_MASK 0x3FFF

// Биты атрибутов PTE для ARM64
#define PTE_ATTRIBUTES_MASK 0xFF00000000000000ULL

// Типы функций для чтения/записи ядра
typedef bool (*kernel_read_func_t)(uint64_t addr, void *buf, size_t size);
typedef bool (*kernel_write_func_t)(uint64_t addr, const void *buf, size_t size);

// Структура теневой страницы (opaque type)
typedef struct shadow_page shadow_page_t;

// Инициализация менеджера теневых страниц
bool shadow_pages_init(uint64_t kernel_base, uint64_t kernel_slide);

// Создание теневой страницы для физического адреса
shadow_page_t* shadow_page_create(uint64_t physical_addr);

// Копирование содержимого оригинальной страницы в теневую
bool shadow_page_populate(shadow_page_t *page, kernel_read_func_t kread);

// Патчинг данных в теневой странице
bool shadow_page_patch(shadow_page_t *page, uint64_t offset, const void *data, size_t size);

// Активация теневой страницы (подмена PTE)
bool shadow_page_activate(shadow_page_t *page, kernel_write_func_t kwrite_pte);

// Деактивация теневой страницы (восстановление оригинала)
bool shadow_page_deactivate(shadow_page_t *page, kernel_write_func_t kwrite_pte);

// Освобождение теневой страницы
void shadow_page_destroy(shadow_page_t *page);

// Поиск символа в ядре
uint64_t shadow_find_symbol(const char *symbol_name);

// Безопасный патчинг функции ядра
bool shadow_patch_function(uint64_t func_addr, const void *patch_data, size_t patch_size,
                          kernel_read_func_t kread, kernel_write_func_t kwrite);

// Проверка целостности KPP
bool verify_kpp_integrity(void);

// Информация о теневой странице
void shadow_page_info(shadow_page_t *page);

// Очистка всех ресурсов
void shadow_pages_cleanup(void);

// Вспомогательная функция для поиска PTE (должна быть реализована отдельно)
uint64_t find_pte_for_pa(uint64_t physical_addr);

#endif /* shadow_pages_h */
