# Проверка релиза 4.3.0

Дата: 2026-10-02. Компилятор: rustc 1.99.0, x86_64 GNU host,
release target aarch64-unknown-linux-musl, bundled rust-lld.

Результат:

- kernel patch: git apply --check проходит на исходном stone_defconfig из
  cf37445a0aa9abcce4b40174ef0a6efdc8225be7; проверены наличие sch_cake.c,
  Kconfig NET_SCH_CAKE и включённые NET_SCHED/NF_CONNTRACK. Полная сборка ядра
  и загрузка на устройстве не выполнены.
- CAKE ABI: тесты проверяют kbit/s → bytes/s, netlink attributes, неверные
  длины, владение полным набором параметров, сохранение внешних изменений,
  защиту дочернего qdisc, изменение скорости, повторный sync и восстановление
  после прерванной установки. Backend в этих тестах заменён симулятором.
- Реальная NETLINK_ROUTE операция в этой среде запрещена (EPERM). Применение
  qdisc в настоящем ядре Android, счётчики CAKE и пинг/скорость не проверены.
- cargo fmt: исходники отформатированы.
- cargo clippy --all-targets -- -D warnings: без предупреждений.
- cargo test: 14 тестов прошли. Проверяются checksum IPv4 для IHL 5–15 и
  исходных TTL 1–255, ошибки пакетов/NFQUEUE, truncate-safe вердикт, конфиги,
  IPv6/CLAT, отдельная зависшая очередь и большой stdout/stderr.
- tests/integration.py: сценарии Android/netd прошли — IPv4+IPv6, zero workers
  в kernel mode, дубль daemon, очистка payload/hook, повторный FORWARD jump,
  смена upstream на IPv6-only USB, исчезновение интерфейсов, pause/start,
  изменение config, защита от неверных значений и восстановление offload.
- tests/installer.py: сохранение старых значений, новые defaults, permissions,
  отказ от установки при неверном конфиге — прошли.
- tests/webui-dom.cjs: snapshot, сохранение редактируемого поля при refresh,
  валидация чисел, configure, start/stop, вывод журнала как текста, doctor,
  отсутствие KSU bridge, поля CAKE и отбрасывание shell-символов — прошли.
- sh -n: shell-скрипты и update-binary проходят синтаксическую проверку.
- ELF release: AArch64, static, stripped, без PT_INTERP.

Chromium renderer не запустился: среда запрещает создание нужных сокетов.
Визуальная проверка в браузере и проверка настоящего Android WebView не выполнены;
Playwright-проверка включена в исходники для запуска вне этой среды.

Физическое устройство недоступно. Скорость, battery drain, IPA/BPF forwarding,
Wi-Fi/Bluetooth coexistence, работа root manager/SELinux на телефоне не измерены.
Тесты с fake Android-командами не являются live тестом ядра или оператора.
