//! Client platform keys used by connection admission policy.

/// 把设备平台的各种写法归一成 CONNECT 词汇：`web`、`h5`、`pc`、`android`、`ios`、`harmonyos`。
///
/// 别名与 flare-core 的 `DevicePlatform::from_str` 一致（`desktop`→`pc`，`mobile_web`→`h5`，
/// `iphone`/`ipad`→`ios`，`harmony`/`openharmony`→`harmonyos`），另外把桌面操作系统名
/// `windows`、`macos`、`linux` 也当作 `pc`。Core 的 CONNECT 门禁和 Social 的 HTTP 门禁都先过这一步，
/// 同一个客户端无论在哪边报哪种写法，判定都一样。认不出的返回 `None`。
pub fn normalize_device_platform(device_platform: &str) -> Option<&'static str> {
    let platform = device_platform.trim().to_ascii_lowercase();
    Some(match platform.as_str() {
        "web" => "web",
        "h5" | "mobile_web" => "h5",
        "pc" | "desktop" | "windows" | "macos" | "linux" => "pc",
        "android" => "android",
        "ios" | "iphone" | "ipad" => "ios",
        "harmonyos" | "harmony" | "openharmony" => "harmonyos",
        _ => return None,
    })
}

/// CONNECT 设备平台 → 发布清单平台段（Core 门禁、Social 门禁、引擎查更新共用这一处）。
///
/// 设备平台先经 [`normalize_device_platform`] 归一。`flutter-` 分发标识将 Flutter 移动应用
/// 与原生平台分开；桌面分发标识区分 Flutter Windows、Flutter macOS 和已有的桌面外壳。
/// 没有发布清单的平台或未知桌面外壳返回 `None`，不设版本门禁，也不查发布清单。
pub fn release_platform(device_platform: &str, distribution: Option<&str>) -> Option<&'static str> {
    let distribution = distribution.map(|value| value.trim().to_ascii_lowercase());
    let distribution = distribution.as_deref().unwrap_or_default();
    match normalize_device_platform(device_platform)? {
        "web" | "h5" => Some("web"),
        "android" if distribution.starts_with("flutter-") => Some("flutter-android"),
        "ios" if distribution.starts_with("flutter-") => Some("flutter-ios"),
        "android" => Some("android"),
        "ios" => Some("ios"),
        "pc" => match distribution {
            "tauri" => Some("tauri"),
            "electron" => Some("electron"),
            "flutter-windows" => Some("flutter-windows"),
            "flutter-macos" => Some("flutter-macos"),
            value if value.starts_with("flutter-windows-") => Some("flutter-windows"),
            value if value.starts_with("flutter-macos-") => Some("flutter-macos"),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_platforms_map_to_release_platform_segments() {
        for (device, distribution, expected) in [
            ("web", None, Some("web")),
            ("h5", None, Some("web")),
            ("mobile_web", None, Some("web")),
            ("android", Some("play"), Some("android")),
            ("android", Some("flutter-direct"), Some("flutter-android")),
            ("ios", Some("appstore"), Some("ios")),
            ("ios", Some("flutter-appstore"), Some("flutter-ios")),
            ("IOS", None, Some("ios")),
            ("iphone", None, Some("ios")),
            ("iPad", Some("appstore"), Some("ios")),
            ("pc", None, None),
            ("pc", Some("direct"), None),
            ("pc", Some("tauri"), Some("tauri")),
            ("pc", Some(" Tauri "), Some("tauri")),
            ("pc", Some("electron"), Some("electron")),
            ("pc", Some("flutter-windows"), Some("flutter-windows")),
            ("pc", Some("flutter-macos-download"), Some("flutter-macos")),
            ("desktop", Some("Electron"), Some("electron")),
            ("desktop", Some("tauri"), Some("tauri")),
            ("windows", Some("direct"), None),
            ("macos", Some("electron"), Some("electron")),
            ("linux", None, None),
            ("harmonyos", Some("appgallery"), None),
            ("harmony", None, None),
            ("openharmony", None, None),
            ("", None, None),
            ("other", None, None),
        ] {
            assert_eq!(
                release_platform(device, distribution),
                expected,
                "{device} / {distribution:?}"
            );
        }
        for (raw, normalized) in [
            ("desktop", Some("pc")),
            ("Windows", Some("pc")),
            ("mobile_web", Some("h5")),
            ("iphone", Some("ios")),
            ("ipad", Some("ios")),
            ("harmony", Some("harmonyos")),
            ("OpenHarmony", Some("harmonyos")),
            (" web ", Some("web")),
            ("fridge", None),
        ] {
            assert_eq!(normalize_device_platform(raw), normalized, "{raw}");
        }
    }
}
