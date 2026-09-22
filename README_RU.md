# Nfqttl Eclipse Rust 4.0.0

Rust-переписывание Nfqttl v3 для Xiaomi `stone`, RisingOS 9 и Eclipse Kernel 5.4.

## Что переписано

- `service.sh` supervisor -> `nfqttl daemon` на Rust.
- C `nfqttl-lite` -> встроенный Rust `nfqttl worker` с raw `NETLINK_NETFILTER`, без `libnetfilter_queue`.
- `control.sh` -> Rust CLI (`status/start/stop/restart`), shell-файл теперь только совместимый launcher.
- Route/link recovery получает события напрямую через `NETLINK_ROUTE`; раз в секунду остаётся watchdog для NFQUEUE health/stall.
- Multi-NFQUEUE сохранён: очереди начинаются с `6464`, `WORKERS=4` использует `--queue-balance` при поддержке iptables.
- GSO + fail-open сохранены: `NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN`, queue maxlen `1024`, receive buffer `4 MiB`.
- IPv4 worker изменяет только TTL и пересчитывает IPv4 header checksum.
- Kernel backend `TTL --ttl-set` остаётся приоритетным и не переписывается на Rust: Eclipse 5.4 не имеет Rust-for-Linux инфраструктуры.
- IPv6 поведение исправлено: `block` теперь всегда block; `normalize` всегда требует `HL`; `auto` выбирает normalize или block.
- Android tether offload отключается с сохранением предыдущего значения и восстанавливается при штатной остановке.

## Сборка arm64

Нужны Rust (`cargo`, `rustup`) и rust-lld. rust-lld уже использовался в v3 для musl worker.

```sh
./src/build.sh
```

Результат:

```text
libs/arm64-v8a/nfqttl
```

Это статический `aarch64-unknown-linux-musl` бинарник, чтобы не зависеть от Android userspace libc. После сборки упакуй содержимое каталога модуля в ZIP.

## Установка

После сборки бинарника:

```sh
zip -r9 nfqttl_v4.0.0_rust.zip . -x 'target/*' '.git/*'
```

Установить ZIP через Magisk/KernelSU, перезагрузить телефон и перед тестом перезапустить hotspot.

Проверка:

```sh
su -c '/data/adb/modules/nfqttl/nfqttl status'
```

Совместимая команда тоже работает:

```sh
su -c 'sh /data/adb/modules/nfqttl/control.sh status'
```

## Конфигурация

Формат `config.conf` сохранён от v3:

```sh
TTL=64
BACKEND=auto
WORKERS=4
DOWNSTREAMS=""
UPSTREAMS=""
DISABLE_OFFLOAD=1
IPV6_MODE=auto
IPV6_HL=64
MAX_FAILURES=6
COOLDOWN=3
MAX_BACKLOG=768
STALL_LIMIT=3
```

`BACKEND=auto`: сначала пробует kernel TTL target, иначе Rust NFQUEUE. `kernel` требует TTL target, `nfqueue` принудительно использует Rust worker.

## Важное

В этом исходном пакете `libs/arm64-v8a/nfqttl` появляется только после `./src/build.sh`. Не прошивай ZIP без бинарника: installer специально остановится с `Missing Rust arm64 binary`.

## Автоматическая упаковка

`./src/build.sh` теперь после успешной ARM64 release-сборки автоматически создаёт установочный ZIP:

```text
dist/nfqttl-v4.0.0-rust.zip
```

ZIP валидируется перед завершением сборки: `module.prop` должен находиться в корне, а `customize.sh`, `service.sh`, CLI/diagnostic scripts, config и `libs/arm64-v8a/nfqttl` обязаны присутствовать. Рядом создаётся файл `.sha256`.

`post-fs-data.sh` этой версии не требуется: daemon запускается через `service.sh` на late_start service stage.
