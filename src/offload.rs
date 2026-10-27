use crate::util;
use std::fs;

fn read(key: &str) -> Option<String> {
    match key {
        "hw" => util::text("settings", &["get", "global", "tether_offload_disabled"]),
        "bpf_tethering" => util::text(
            "device_config",
            &["get", "tethering", "tether_enable_bpf_offload"],
        ),
        "bpf" => util::text(
            "device_config",
            &["get", "connectivity", "tether_enable_bpf_offload"],
        ),
        _ => None,
    }
}
fn write(key: &str, value: &str) -> bool {
    match (key, value) {
        ("hw", "null") => util::ok("settings", &["delete", "global", "tether_offload_disabled"]),
        ("hw", v) => util::ok("settings", &["put", "global", "tether_offload_disabled", v]),
        ("bpf_tethering", "null") => util::ok(
            "device_config",
            &["delete", "tethering", "tether_enable_bpf_offload"],
        ),
        ("bpf_tethering", v) => util::ok(
            "device_config",
            &["put", "tethering", "tether_enable_bpf_offload", v],
        ),
        ("bpf", "null") => util::ok(
            "device_config",
            &["delete", "connectivity", "tether_enable_bpf_offload"],
        ),
        ("bpf", v) => util::ok(
            "device_config",
            &["put", "connectivity", "tether_enable_bpf_offload", v],
        ),
        _ => false,
    }
}
fn valid(key: &str, v: &str) -> bool {
    matches!(
        (key, v),
        ("hw", "0" | "1" | "null") | ("bpf" | "bpf_tethering", "true" | "false" | "null")
    )
}

pub fn apply(enabled: bool) {
    if !enabled {
        return;
    }
    let s = util::state_dir();
    for key in ["hw", "bpf", "bpf_tethering"] {
        let Some(old) = read(key) else {
            continue;
        };
        if !valid(key, &old) {
            continue;
        }
        let before = s.join(format!("offload.{key}.before"));
        let owned = s.join(format!("offload.{key}.owned"));
        let new = if key == "hw" { "1" } else { "false" };
        if old == new {
            continue;
        }
        // Journal ownership before writing the setting to cover daemon crashes.
        if !owned.exists() && fs::write(&before, &old).is_err() {
            continue;
        }
        if fs::write(&owned, new).is_err() {
            continue;
        }
        if !(write(key, new) && read(key).as_deref() == Some(new)) {
            util::log(&format!("WARNING: cannot disable {key} offload"));
        }
    }
}

pub fn restore() {
    let s = util::state_dir();
    for key in ["hw", "bpf", "bpf_tethering"] {
        let owned = s.join(format!("offload.{key}.owned"));
        let before = s.join(format!("offload.{key}.before"));
        let Some(ours) = util::read_trim(&owned) else {
            continue;
        };
        let Some(now) = read(key) else {
            continue;
        };
        if now == ours {
            if let Some(old) = util::read_trim(&before) {
                if !(write(key, &old) && read(key).as_deref() == Some(old.as_str())) {
                    continue;
                }
            }
        }
        let _ = fs::remove_file(owned);
        let _ = fs::remove_file(before);
    }
}
