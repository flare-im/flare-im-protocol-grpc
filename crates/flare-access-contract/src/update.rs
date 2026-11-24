//! Wire payloads for an optional update provider.

use serde::{Deserialize, Serialize};

/// 跨端稳定的错误码。
pub mod codes {
    pub const MANIFEST_UNAVAILABLE: &str = "update.manifestUnavailable";
    pub const MANIFEST_REJECTED: &str = "update.manifestRejected";
    pub const NO_ARTIFACT: &str = "update.noArtifact";
    pub const METERED_CONFIRMATION_REQUIRED: &str = "update.meteredConfirmationRequired";
    pub const INSUFFICIENT_SPACE: &str = "update.insufficientSpace";
    pub const DOWNLOAD_FAILED: &str = "update.downloadFailed";
    pub const HASH_MISMATCH: &str = "update.hashMismatch";
    pub const INSTALL_FAILED: &str = "update.installFailed";
    pub const SIGNATURE_MISMATCH: &str = "update.signatureMismatch";
    pub const DOWNGRADE_REJECTED: &str = "update.downgradeRejected";
    pub const NOT_SKIPPABLE: &str = "update.notSkippable";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UpdateState {
    Idle,
    Checking,
    UpToDate,
    Available,
    Required,
    Downloading,
    Verifying,
    ReadyToInstall,
    Installing,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReleaseKind {
    Store,
    Package,
    WebBundle,
    Desktop,
}

/// `update://state` 的 `current`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentApp {
    pub version: Option<String>,
    pub build: Option<u64>,
    pub channel: String,
    pub distribution: Option<String>,
}

/// `update://state` 的 `release`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseSummary {
    pub release_id: String,
    pub version: String,
    pub build: u64,
    /// 已按语言选好。
    pub notes: Vec<String>,
    /// 商店跳转时为 null。
    pub size_bytes: Option<u64>,
    pub mandatory: bool,
    pub recommended: bool,
    pub kind: ReleaseKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProgress {
    pub received: u64,
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateError {
    pub code: String,
    pub retryable: bool,
    pub fallback_url: Option<String>,
}

/// `update.*` 的返回值，也是 `update://state` 的载荷。每个字段都会出现，没有值时为 null。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    pub state: UpdateState,
    pub current: CurrentApp,
    pub release: Option<ReleaseSummary>,
    pub progress: Option<UpdateProgress>,
    pub prompt: UpdatePrompt,
    pub block_ui: bool,
    pub read_only: bool,
    /// Unix 毫秒，从未检查过为 null。
    pub last_checked_at: Option<i64>,
    pub error: Option<UpdateError>,
    /// 当前构建命中 `blockedBuilds` 时的原因，已按语言选好。
    pub block_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UpdatePrompt {
    None,
    Badge,
    Sheet,
    Modal,
    Fullscreen,
}

impl UpdatePrompt {
    pub fn as_str(self) -> &'static str {
        match self {
            UpdatePrompt::None => "none",
            UpdatePrompt::Badge => "badge",
            UpdatePrompt::Sheet => "sheet",
            UpdatePrompt::Modal => "modal",
            UpdatePrompt::Fullscreen => "fullscreen",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(UpdatePrompt::None),
            "badge" => Some(UpdatePrompt::Badge),
            "sheet" => Some(UpdatePrompt::Sheet),
            "modal" => Some(UpdatePrompt::Modal),
            "fullscreen" => Some(UpdatePrompt::Fullscreen),
            _ => None,
        }
    }
}

/// `kind` 判别的安装计划。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum UpdateInstallPlan {
    OpenStore {
        /// `play`、`appstore`、`testflight`、`appgallery` 或国内商店渠道名。
        store: String,
        url: Option<String>,
        package_name: Option<String>,
        app_id: Option<String>,
        /// Play 上强制更新走 immediate，其余走 flexible。
        immediate: bool,
    },
    InstallPackage(PackagePlan),
    ActivateWebBundle {
        build_id: String,
        asset_manifest_urls: Vec<String>,
        asset_manifest_sha256: String,
        mandatory: bool,
        block_ui: bool,
    },
    DesktopUpdater {
        version: String,
        target: String,
        sha256: Option<String>,
    },
}

/// 已校验的安装包。字段只在 crate 内可写：这份计划只能从下载模块的 `VerifiedArtifact` 产生。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackagePlan {
    pub path: String,
    pub sha256: String,
    pub signing_cert_sha256: Option<String>,
    pub build: u64,
    pub size_bytes: u64,
}

impl PackagePlan {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn build(&self) -> u64 {
        self.build
    }
}

/// `update.get_resources` 里的一个包。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateResourcePack {
    pub id: String,
    pub kind: String,
    pub pack_version: u64,
    /// 包文件原文。以字符串穿过绑定，由 Kit 和宿主解析。
    pub content_json: String,
}

/// `update.get_resources` 的返回值，按 `id` 排序。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UpdateResources {
    pub packs: Vec<UpdateResourcePack>,
}
