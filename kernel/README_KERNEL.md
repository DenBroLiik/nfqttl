# Eclipse / stone kernel integration

For optional CAKE SQM in v4.3, apply 0001-stone-enable-cake-sqm.patch.
It targets seventeen, commit cf37445a0aa9abcce4b40174ef0a6efdc8225be7 (Linux 5.4).
The patch enables an existing in-tree scheduler; it does not change the default
qdisc or enable shaping by itself. Rebuild with the patched stone_defconfig.
Instructions, limitations and module settings: ../docs/NETWORK_RU.md.

The supplied Eclipse repository default branch is seventeen (5.4). Its
stone_defconfig already includes NETFILTER, NETFILTER_ADVANCED,
NETFILTER_XT_TARGET_HL, NETFILTER_XT_TARGET_NFQUEUE, IP_NF_MANGLE and
IP6_NF_MANGLE. `xt_HL.c` registers IPv4 TTL and IPv6 HL in the mangle table.
The historical 0001 patch is retained as reference; do not apply it blindly
when those lines are already present. No kernel source modification is needed
for the module's normal kernel TTL/HL path on this configuration.

On the installed phone, `nfqttl doctor` probes the actual Android userspace
iptables extensions and kernel targets rather than trusting a source defconfig.
Source config does not prove the flashed kernel matches that source revision.

Hardware IPA and Android BPF offload can bypass netfilter. The module disables
settings, but this does not patch IPA, unpin BPF programs or restart tethering.
Restart the hotspot and inspect payload counters during traffic. Do not stop
ipacm or disable SELinux globally as a workaround.

Adding a toggle to the native RisingOS Settings/XiaomiParts APK is a separate
ROM change; KernelSU WebUI and the module Action provide controls without it.
