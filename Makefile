# Lara Jailbreak - Makefile для сборки через Theos
# Поддержка rootless архитектуры для iPad8,9 iOS 17.3.1

export TARGET = iphone:clang:17.0:arm64
export ARCHS = arm64
export SDK = iphoneos

# Путь к Theos (для WSL)
export THEOS = /theos
export THEOS_DEVICE_IP = 192.168.1.100
export THEOS_DEVICE_PORT = 22

# Имя проекта
INSTALL_TARGET_PROCESSES = LaraJailbreak

# Включаем все исходные файлы
LaraJailbreak_INSTALL_PATH = /Applications
LaraJailbreak_FILES = \
    LaraJailbreak/main.m \
    LaraJailbreak/LaraAppDelegate.m \
    LaraJailbreak/UI/LaraViewController.m \
    LaraJailbreak/UI/LaraUIManager.m \
    kexploit/darksword.m \
    kexploit/sandbox_patches.m \
    kexploit/ppl_bypass.m \
    kexploit/vfs.m \
    kexploit/trustcache_inject.c \
    kexploit/bootstrap_downloader.m \
    kexploit/lara_jailbreak.m \
    jbdc/third_party_bridge/dsfun_all_bridge.m

# Флаги компиляции
LaraJailbreak_CFLAGS = \
    -fobjc-arc \
    -Wno-deprecated-declarations \
    -Wno-unused-function \
    -Wno-incompatible-pointer-types \
    -I$(THEOS_PROJECT_DIR)/kexploit \
    -I$(THEOS_PROJECT_DIR)/jbdc \
    -I$(THEOS_PROJECT_DIR)/LaraJailbreak/UI

# Флаги линковки
LaraJailbreak_LDFLAGS = \
    -e _UIApplicationMain \
    -framework UIKit \
    -framework Foundation \
    -framework CoreGraphics \
    -framework MobileCoreServices \
    -framework CFNetwork \
    -lz

# Entitlements
LaraJailbreak_CODESIGN_FLAGS = -SLaraJailbreak.entitlements

# Bootstrap URL (заглушка, заменить на реальный)
BOOTSTRAP_URL = https://github.com/LaraJB/bootstrap/releases/download/v1.0/bootstrap.tar
BOOTSTRAP_SHA256 = REPLACE_WITH_REAL_SHA256

# Задачи
all:: internal-all
	@echo "✓ Сборка завершена успешно"
	@echo "✓ IPA файл: .theos/obj/release/LaraJailbreak.ipa"

clean:: internal-clean
	@echo "✓ Очистка завершена"

install:: internal-install
	@echo "✓ Установка на устройство: $(THEOS_DEVICE_IP)"

# Дополнительные утилиты
bootstrap-download:
	@echo "Загрузка bootstrap.tar..."
	curl -L -o bootstrap.tar "$(BOOTSTRAP_URL)"
	@echo "Проверка SHA256..."
	@echo "$(BOOTSTRAP_SHA256)  bootstrap.tar" | sha256sum -c || (echo "❌ SHA256 не совпадает!" && exit 1)
	@echo "✓ Bootstrap загружен и проверен"

offsets-update:
	@echo "Обновление оффсетов из анализа ядра..."
	python3 iPad8,9_Analysis/Sandbox_Profiles/validate_sandbox_and_find_cs.py
	cp iPad8,9_Analysis/Sandbox_Profiles/sandbox_verified_offsets.h kexploit/
	@echo "✓ Оффсеты обновлены"

# Анализ ядра
kernel-analyze:
	@echo "Анализ kernelcache..."
	python3 iPad8,9_Analysis/Sandbox_Profiles/decode_sandbox_kext.py iPad8,9_Analysis/Sandbox_Profiles/com.apple.security.sandbox.kext
	python3 iPad8,9_Analysis/Sandbox_Profiles/validate_sandbox_and_find_cs.py
	@echo "✓ Анализ завершен"

.PHONY: all clean install bootstrap-download offsets-update kernel-analyze
