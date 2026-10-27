# Совместимость Eclipse / RisingOS 9

Проверено 2026-10-01. Источники прочитаны из default-веток seventeen; это не проверка установленной прошивки.

| Файл | Git blob SHA |
|---|---|
| [stone_defconfig](https://github.com/DenBroLiik/eclipse_kernel_xiaomi_stone/blob/seventeen/arch/arm64/configs/stone_defconfig) | `ebb90faf453a14892ac497ccaf9408b1f61ef934` |
| [xt_HL.c](https://github.com/DenBroLiik/eclipse_kernel_xiaomi_stone/blob/seventeen/net/netfilter/xt_HL.c) | `7873b834c30045661a76bbffe9c8e2f71a5c500b` |
| [nfnetlink_queue.c](https://github.com/DenBroLiik/eclipse_kernel_xiaomi_stone/blob/seventeen/net/netfilter/nfnetlink_queue.c) | `c4005a42a78bad7c6ad11e7f299a0ca5c0f69c6f` |
| [BoardConfig.mk](https://github.com/bittencourtjulival/android_device_xiaomi_stone/blob/seventeen/BoardConfig.mk) | `d8a170bb6975b9a2e358a0e26f1bcb5e43646f52` |
| [device.mk](https://github.com/bittencourtjulival/android_device_xiaomi_stone/blob/seventeen/device.mk) | `a8b95598f5ad865b6079fe6cd8d4c6b189e03be7` |
| [stone-vendor.mk](https://github.com/bittencourtjulival/android_vendor_xiaomi_stone/blob/seventeen/stone-vendor.mk) | `5a90fcd334f491f0b851c71851bdf85ad881d9bb` |

stone_defconfig включает TTL/HL, NFQUEUE и mangle обеих семей. BoardConfig задаёт arm64-v8a, stone_defconfig и версию ядра 5.4. device.mk включает ipacm; vendor.mk содержит IPA firmware.

Названия Android-интерфейсов и поведение offload должны подтверждаться на работающем устройстве. Наличие отдельных blob/config файлов не доказывает причину RF/Bluetooth/USB проблем.

WebUI использует native exec API, проверенный по [KernelSU js/index.js](https://github.com/tiann/KernelSU/blob/main/js/index.js), blob `d0d700a1201f7f4f269e854996586d9a65ef19ad`.
