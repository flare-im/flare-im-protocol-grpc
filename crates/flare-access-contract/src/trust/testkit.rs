//! 单元测试用的确定性密钥与签名清单。
use ed25519_dalek::SigningKey;

use super::sign::{Signer, issue_key_cert, sign_access_manifest};
use super::*;

pub const ROOT_ID: &str = "root-a";
pub const ONLINE_ID: &str = "ok-2026h2-01";
pub const BOOTSTRAP_ID: &str = "b7f3c9a1e2d4b6a8";
/// 2026-11-04T08:00:00Z
pub const NOW_MS: i64 = 1_793_779_200_000;

pub fn root_key() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

pub fn online_key() -> SigningKey {
    SigningKey::from_bytes(&[0x33; 32])
}

pub fn roots() -> TrustRoots {
    TrustRoots::from_keys([(ROOT_ID.to_owned(), root_key().verifying_key().to_bytes())]).unwrap()
}

pub fn trust() -> TrustStore {
    TrustStore::new(roots(), BOOTSTRAP_ID).unwrap()
}

pub fn cert() -> KeyCert {
    KeyCert {
        schema: "flare.keycert.v1".into(),
        key_id: ONLINE_ID.into(),
        public_key: sign::encode_public_key(&online_key().verifying_key()),
        usages: vec!["access".into(), "release".into()],
        scope: KeyScope {
            bootstrap_ids: vec!["*".into()],
        },
        not_before: "2026-07-01T00:00:00Z".into(),
        not_after: "2026-12-28T00:00:00Z".into(),
        root_key_id: ROOT_ID.into(),
    }
}

pub fn issued_cert(cert: &KeyCert) -> String {
    let root = root_key();
    issue_key_cert(
        &Signer {
            key_id: ROOT_ID,
            key: &root,
        },
        cert,
    )
}

/// 用默认证书签一份清单载荷。
pub fn signed_manifest(payload: &serde_json::Value) -> Vec<u8> {
    let online = online_key();
    sign_access_manifest(
        &serde_json::to_vec(payload).unwrap(),
        &Signer {
            key_id: ONLINE_ID,
            key: &online,
        },
        &[issued_cert(&cert())],
    )
}

/// 用默认证书签一份发布清单载荷。只有客户端部分的测试在用。
pub fn signed_release(payload: &serde_json::Value) -> Vec<u8> {
    let online = online_key();
    super::sign::sign_release_manifest(
        &serde_json::to_vec(payload).unwrap(),
        &Signer {
            key_id: ONLINE_ID,
            key: &online,
        },
        &[issued_cert(&cert())],
    )
}

pub fn manifest_with_serial(serial: u64) -> serde_json::Value {
    let mut value = sample_manifest_json();
    value["serial"] = serial.into();
    value
}

/// 设计文档 §4.1 的示例清单（载荷）。
pub fn sample_manifest_json() -> serde_json::Value {
    serde_json::json!({
        "schema": "flare.access.v1",
        "bootstrapId": "b7f3c9a1e2d4b6a8",
        "appId": "app_01J9ZK3X",
        "serial": 1042,
        "issuedAt": "2026-11-04T08:00:00Z",
        "expiresAt": "2026-12-04T08:00:00Z",
        "regions": [{
            "id": "cn-east",
            "displayName": { "zh-CN": "华东", "en": "East China" },
            "cells": [{
                "id": "cell-cne-1",
                "accessPoints": [{
                    "id": "ap-cne1-ct",
                    "host": "im-ct.example.com",
                    "ipHints": ["203.0.113.10", "203.0.113.11"],
                    "spkiPins": [],
                    "weight": 100,
                    "priority": 0,
                    "status": "active",
                    "tags": ["isp:ct"],
                    "services": {
                        "imWs": { "path": "/ws" },
                        "imQuic": { "port": 443 },
                        "coreApi": { "path": "/api" },
                        "socialApi": { "path": "/social-api" },
                        "media": { "path": "/flare-media" },
                        "ping": { "path": "/.well-known/flare/ping" }
                    }
                }]
            }]
        }],
        "placement": { "homeCell": "cell-cne-1", "allowedRegions": ["cn-east"] },
        "bootstrap": {
            "sources": [
                { "kind": "https", "url": "https://cfg-a.example-cdn.com/flare/v1/b7f3c9a1e2d4b6a8/" },
                { "kind": "https", "url": "https://cfg-b.other-cloud.net/flare/v1/b7f3c9a1e2d4b6a8/" },
                { "kind": "wellKnown" },
                { "kind": "dohTxt", "name": "_flare.b7f3c9a1e2d4b6a8.example-boot.org",
                  "resolvers": ["https://1.1.1.1/dns-query", "https://223.5.5.5/dns-query"] }
            ],
            "refreshIntervalSec": 21600
        },
        "clientPolicy": { "raceStaggerMs": 300, "breaker": { "failureThreshold": 3 } },
        "release": { "channels": ["stable", "beta"] }
    })
}
