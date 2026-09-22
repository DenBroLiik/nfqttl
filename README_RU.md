# Nfqttl Eclipse Speed + Stability 3.0.0

Специальная сборка Magisk-модуля для `xiaomi_stone` (POCO X5 5G / Redmi Note 12 5G), RisingOS + Eclipse Kernel.
Цель: убрать узкое место старого NFQUEUE fallback, уменьшить потери/скачки задержки при раздаче и не оставлять очевидную IPv4 TTL/IPv6 hop-limit утечку при нескольких клиентах.

## Что изменено

- NFQUEUE worker на arm64: `NFQA_CFG_F_GSO` включён, queue maxlen увеличен `64 -> 1024`, socket receive buffer `1 MiB -> 4 MiB`.
- До 4 NFQUEUE workers через `--queue-balance` вместо одного процесса. Если iptables не поддерживает balance, автоматический fallback на одну очередь.
- Watchdog больше не выключает TTL из-за одного изменения drop-счётчика. Drops логируются; recovery выполняется при смерти worker/queue или реальном stall.
- Переход между uplink-интерфейсами делается через постоянную hook-цепочку и атомарную замену leaf-rule, без краткого двойного прохождения NFQUEUE.
- Интерфейсы проверяются каждую секунду, поэтому переключения `rmnet_data*` во время звонка/смены сети отрабатываются быстрее. Автоопределение uplink также учитывает `tun/tap/wg/tailscale/zt` для VPN-маршрутов.
- IPv6: `IPV6_MODE=auto` пытается использовать `HL --hl-set 64`. На текущем Eclipse target HL отсутствует, поэтому auto блокирует forwarded IPv6 от tether-клиентов, чтобы он не обходил IPv4 TTL-нормализацию. Если `ip6tables` вообще отсутствует в ROM, модуль явно пишет `pass-no-ip6tables` и предупреждение вместо ложного статуса «block». `IPV6_MODE=pass` отключает защиту IPv6.
- Добавлен патч Eclipse defconfig для нативных IPv4 TTL + IPv6 HL targets. После сборки ядра с этим патчем модуль сможет уйти с userspace NFQUEUE на самый быстрый kernel backend.

## Установка

1. Установить ZIP через Magisk поверх старого `nfqttl` (`id=nfqttl` сохранён).
2. Перезагрузить телефон.
3. Выключить и снова включить точку доступа.
4. Проверить состояние:

```sh
su -c 'sh /data/adb/modules/nfqttl/control.sh status'
```

На текущем Eclipse без дополнительного kernel-патча ожидается `Backend: nfqueue` и обычно `NFQUEUE workers: 4`. Скорость выше старых ~7 МБ/с является целью этой версии, но реальный предел зависит от модема, Wi‑Fi, CPU и ROM и должен проверяться на телефоне.

## Проверка скорости и потерь

На подключённом устройстве одновременно проверь download и ping. Во время теста можно снять диагностику:

```sh
su -c 'sh /data/adb/modules/nfqttl/diagnose.sh during'
```

Файл появится в `/sdcard/Download/`.

Если `Queue` постоянно имеет большой backlog или растут drops, попробуй `WORKERS=6` либо `WORKERS=8` в `config.conf`. Если CPU/нагрев растут без прироста — верни `4`.

## IPv6 и обнаружение раздачи

TTL/HL — только один из признаков tethering. Модуль нормализует IPv4 TTL и в `auto` не позволяет IPv6 тихо обходить эту схему, однако оператор всё равно может использовать APN/DUN policy, DPI, характер трафика и другие серверные признаки. Полностью гарантировать «не обнаружит раздачу» на стороне оператора нельзя.

Если нужен IPv6 любой ценой:

```sh
IPV6_MODE=pass
```

Если соберёшь Eclipse с патчем из `kernel/0001-stone-enable-ipv4-ipv6-hoplimit.patch`, оставляй `IPV6_MODE=auto`: будет нативный HL rewrite вместо блокировки.

## Основные настройки

```sh
TTL=64
BACKEND=auto
WORKERS=4
DISABLE_OFFLOAD=1
IPV6_MODE=auto
IPV6_HL=64
```

`DISABLE_OFFLOAD=1` оставлен специально: Android/Qualcomm tether offload может обходить обычные netfilter hooks. Для корректной TTL-нормализации лучше software forwarding; NFQUEUE v3 компенсирует его стоимость GSO + multi-queue.
