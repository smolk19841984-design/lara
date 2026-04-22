# Инструкция по сборке и интеграции TrustCache helper

1. Сборка helper:

cd tools
xcrun --sdk iphoneos clang -isysroot $(xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -O2 -Wl,-dead_strip -Wl,-pie -o create_var_jb_helper create_var_jb_helper.c

2. Подпись и TrustCache:
- Подпишите бинарник (ldid, jtool, codesign или через кастомный trustcache pipeline).
- Добавьте хеш бинарника в свой кастомный TrustCache.

3. Копирование на устройство:
- Поместите create_var_jb_helper в доступное место (например, /var/containers/Bundle/ или /private/var/tmp/).
- Проверьте права: chmod 755 create_var_jb_helper

4. Вызов из приложения:
- В методе handleCreateVarJB_TrustCache замените заглушку на вызов:
  system("/var/containers/Bundle/create_var_jb_helper");
  // или NSTask/posix_spawn, если требуется.

5. Проверка:
- После нажатия кнопки TrustCache метод — /var/jb должен появиться, если pipeline работает.

---

Если нужна автоматизация подписи или интеграция с TrustCache pipeline — сообщите.
