# 4.1 → 4.2

Install the new runtime ZIP and reboot. Existing config.conf values and persistent
pause are preserved; missing defaults are appended. The installer validates the
result. Explicitly set WORKERS=1 if you want the new NFQUEUE default on an old
configuration. Kernel mode ignores worker count and reports 0 active workers.

Use KernelSU WebUI or `nfqttl configure KEY=VALUE ...` for validated edits.
`nfqttl check` detects malformed/duplicate/unknown settings. Removing the module
runs stop and attempts to restore owned offload settings. Persistent logs and
state remain under /data/adb/nfqttl-state for diagnosis. To resume a paused module,
run start; a reboot alone does not clear pause.
