//! 回放共享签名契约的验签、客户端策略和 URL 向量。
//! 设置 `FLARE_ACCESS_CONTRACT_WRITE_VECTORS=1` 可重新生成。

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use flare_access_contract::manifest::{ClientPolicy, POLICY_BOUNDS};
use flare_access_contract::parsed_url::ParsedUrl;
use flare_access_contract::trust::sign::{
    Signer, encode_public_key, issue_key_cert, sign_envelope, sign_keystate,
};
use flare_access_contract::trust::{
    Envelope, KeyCert, KeyScope, KeyState, SerialCheck, TrustRoots, TrustStore, check_serial,
};

const VECTOR_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors");
const FLOAT_TOLERANCE: f64 = 1e-9;

fn write_mode() -> bool {
    std::env::var_os("FLARE_ACCESS_CONTRACT_WRITE_VECTORS").is_some()
}

fn vector_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(VECTOR_DIR).join(name)
}

fn load(name: &str) -> Value {
    let path = vector_path(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing {}; run with FLARE_ACCESS_CONTRACT_WRITE_VECTORS=1",
            path.display()
        )
    });
    serde_json::from_str(&text).unwrap()
}

/// 写模式下落盘；否则要求磁盘上的文件与重新生成的一致。
fn ensure_current(name: &str, generated: &Value) {
    let path = vector_path(name);
    if write_mode() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(generated).unwrap() + "\n",
        )
        .unwrap();
        return;
    }
    assert!(
        approx_eq(&load(name), generated),
        "{name} is out of date; regenerate with FLARE_ACCESS_CONTRACT_WRITE_VECTORS=1 and review the diff"
    );
}

/// JSON 比较，浮点按容差。
fn approx_eq(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => match (a.as_f64(), b.as_f64()) {
            (Some(a), Some(b)) => (a - b).abs() <= FLOAT_TOLERANCE * a.abs().max(1.0),
            _ => a == b,
        },
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| approx_eq(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, value)| b.get(key).is_some_and(|other| approx_eq(value, other)))
        }
        _ => left == right,
    }
}

fn replay(name: &str, evaluate: impl Fn(&Value) -> Value) {
    let file = load(name);
    for case in file["cases"].as_array().unwrap() {
        let actual = evaluate(&case["input"]);
        assert!(
            approx_eq(&actual, &case["expected"]),
            "{name} / {}: expected {}, got {}",
            case["name"],
            case["expected"],
            actual
        );
    }
}

fn cases(evaluate: impl Fn(&Value) -> Value, inputs: Vec<(&str, Value)>) -> Vec<Value> {
    inputs
        .into_iter()
        .map(|(name, input)| {
            let expected = evaluate(&input);
            json!({ "name": name, "input": input, "expected": expected })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// clientPolicy 夹紧
// ---------------------------------------------------------------------------

fn eval_policy(input: &Value) -> Value {
    serde_json::to_value(ClientPolicy::resolve(input)).unwrap()
}

fn policy_vectors() -> Value {
    let bounds: Vec<Value> = POLICY_BOUNDS
        .iter()
        .map(|(path, bound)| json!({ "path": path, "min": bound.min, "default": bound.default, "max": bound.max }))
        .collect();
    json!({
        "description": "clientPolicy resolution: missing or non-numeric fields take the default, numbers clamp to [min, max] and round half away from zero to integers where the field is integral. Cross-field rules: heartbeat.timeoutSec >= 2 x intervalSec (capped at its max), backgroundIntervalSec >= intervalSec, cooldownMaxSec >= cooldownBaseSec, capForegroundMs >= baseMs, capBackgroundMs >= capForegroundMs. protocolOrder keeps known values in order without duplicates, falling back to [quic, ws] when empty.",
        "bounds": bounds,
        "cases": cases(eval_policy, vec![
            ("empty", json!({})),
            ("null", Value::Null),
            ("design sample", json!({ "raceStaggerMs": 300, "breaker": { "failureThreshold": 3 } })),
            ("below minimums", json!({
                "raceStaggerMs": 0, "connectTimeoutMs": 1,
                "heartbeat": { "intervalSec": 1, "timeoutSec": 1, "backgroundIntervalSec": 1 },
                "probeWakeTimeoutMs": 0,
                "breaker": { "failureThreshold": 0, "failureRatio": 0, "cooldownBaseSec": 0, "cooldownMaxSec": 0 },
                "backoff": { "baseMs": 0, "capForegroundMs": 0, "capBackgroundMs": 0 },
                "probe": { "budgetPerHour": -5, "backgroundIntervalMin": 0 },
                "failback": { "minHealthySpanSec": 0, "minImprovementRatio": 0, "minIntervalSec": 0 },
                "udpBlockedTtlHours": 0, "pinTtlHours": 0
            })),
            ("above maximums", json!({
                "raceStaggerMs": 1e9, "connectTimeoutMs": 1e9,
                "heartbeat": { "intervalSec": 1e9, "timeoutSec": 1e9, "backgroundIntervalSec": 1e9 },
                "probeWakeTimeoutMs": 1e9,
                "breaker": { "failureThreshold": 1e9, "failureRatio": 7, "cooldownBaseSec": 1e9, "cooldownMaxSec": 1e9 },
                "backoff": { "baseMs": 1e9, "capForegroundMs": 1e9, "capBackgroundMs": 1e9 },
                "probe": { "budgetPerHour": 100000, "backgroundIntervalMin": 1e9 },
                "failback": { "minHealthySpanSec": 1e9, "minImprovementRatio": 5, "minIntervalSec": 1e9 },
                "udpBlockedTtlHours": 1e9, "pinTtlHours": 1e9
            })),
            ("cross-field repair", json!({
                "heartbeat": { "intervalSec": 200, "timeoutSec": 30, "backgroundIntervalSec": 60 },
                "breaker": { "cooldownBaseSec": 300, "cooldownMaxSec": 60 },
                "backoff": { "baseMs": 10000, "capForegroundMs": 5000, "capBackgroundMs": 30000 }
            })),
            ("wrong types fall back to defaults", json!({
                "raceStaggerMs": "fast", "connectTimeoutMs": null, "heartbeat": [1, 2],
                "breaker": { "failureRatio": "half" }, "probe": true, "protocolOrder": "quic"
            })),
            ("fractions round", json!({ "raceStaggerMs": 300.6, "breaker": { "failureThreshold": 2.5, "failureRatio": 0.333 } })),
            ("protocol order ws only", json!({ "protocolOrder": ["ws"] })),
            ("protocol order dedupes and drops unknown", json!({ "protocolOrder": ["tcp", "ws", "quic", "ws"] })),
            ("protocol order all unknown", json!({ "protocolOrder": ["tcp", 3] })),
        ]),
    })
}

#[test]
fn client_policy_clamp_vectors() {
    ensure_current("client_policy_clamp.json", &policy_vectors());
    replay("client_policy_clamp.json", eval_policy);
}

// ---------------------------------------------------------------------------
// 清单验签
// ---------------------------------------------------------------------------

const BOOTSTRAP_ID: &str = "b7f3c9a1e2d4b6a8";
const NOW_MS: i64 = 1_793_779_200_000; // 2026-11-04T08:00:00Z
const DAY_MS: i64 = 86_400_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

struct Keys {
    root_a: SigningKey,
    root_b: SigningKey,
    root_x: SigningKey,
    online: SigningKey,
    online_2: SigningKey,
}

fn keys() -> Keys {
    Keys {
        root_a: key(0x11),
        root_b: key(0x22),
        root_x: key(0x55),
        online: key(0x33),
        online_2: key(0x44),
    }
}

fn manifest_payload(serial: u64) -> Value {
    json!({
        "schema": "flare.access.v1",
        "bootstrapId": BOOTSTRAP_ID,
        "appId": "app_01J9ZK3X",
        "serial": serial,
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
                    "ipHints": ["203.0.113.10"],
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
        "bootstrap": { "sources": [
            { "kind": "https", "url": "https://cfg-a.example-cdn.com/flare/v1/b7f3c9a1e2d4b6a8/" },
            { "kind": "https", "url": "https://cfg-b.other-cloud.net/flare/v1/b7f3c9a1e2d4b6a8/" }
        ], "refreshIntervalSec": 21600 },
        "clientPolicy": { "raceStaggerMs": 300 }
    })
}

fn cert(key_id: &str, online: &SigningKey, root_id: &str) -> KeyCert {
    KeyCert {
        schema: "flare.keycert.v1".into(),
        key_id: key_id.into(),
        public_key: encode_public_key(&online.verifying_key()),
        usages: vec!["access".into(), "release".into()],
        scope: KeyScope {
            bootstrap_ids: vec!["*".into()],
        },
        not_before: "2026-07-01T00:00:00Z".into(),
        not_after: "2026-12-28T00:00:00Z".into(),
        root_key_id: root_id.into(),
    }
}

fn issue(root_id: &str, root: &SigningKey, cert: &KeyCert) -> String {
    issue_key_cert(
        &Signer {
            key_id: root_id,
            key: root,
        },
        cert,
    )
}

fn sign_payload(
    payload: &[u8],
    payload_type: &str,
    signers: &[(&str, &SigningKey)],
    certs: &[String],
) -> String {
    let signers: Vec<Signer<'_>> = signers
        .iter()
        .map(|(key_id, key)| Signer { key_id, key })
        .collect();
    String::from_utf8(sign_envelope(payload_type, payload, &signers, certs).to_json_bytes())
        .unwrap()
}

const ACCESS_TYPE: &str = "application/vnd.flare.access.v1+json";

fn signed(payload: &Value, keys: &Keys, certs: &[String]) -> String {
    sign_payload(
        &serde_json::to_vec(payload).unwrap(),
        ACCESS_TYPE,
        &[("ok-2026h2-01", &keys.online)],
        certs,
    )
}

fn tamper_payload(envelope: &str) -> String {
    let mut parsed: Envelope = serde_json::from_str(envelope).unwrap();
    let mut payload = URL_SAFE_NO_PAD.decode(&parsed.payload).unwrap();
    let position = payload
        .windows(5)
        .position(|window| window == b"im-ct")
        .unwrap();
    payload[position] = b'x';
    parsed.payload = URL_SAFE_NO_PAD.encode(&payload);
    String::from_utf8(parsed.to_json_bytes()).unwrap()
}

fn tamper_cert(encoded: &str) -> String {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
    let mut parsed: Envelope = serde_json::from_slice(&bytes).unwrap();
    let mut payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parsed.payload).unwrap()).unwrap();
    payload["notAfter"] = "2030-01-01T00:00:00Z".into();
    parsed.payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    URL_SAFE_NO_PAD.encode(parsed.to_json_bytes())
}

fn keystate(serial: u64, revoked: &[&str], certificates: Vec<String>) -> KeyState {
    KeyState {
        schema: "flare.keystate.v1".into(),
        serial,
        issued_at: "2026-11-01T00:00:00Z".into(),
        certificates,
        revoked_key_ids: revoked.iter().map(|id| id.to_string()).collect(),
    }
}

fn trust_roots_json(keys: &Keys) -> Value {
    json!([
        { "keyId": "root-a", "publicKey": encode_public_key(&keys.root_a.verifying_key()) },
        { "keyId": "root-b", "publicKey": encode_public_key(&keys.root_b.verifying_key()) },
    ])
}

fn eval_verify(input: &Value) -> Value {
    let roots: Vec<flare_access_contract::trust::TrustRootConfig> =
        serde_json::from_value(input["trustRoots"].clone()).unwrap();
    let mut trust = TrustStore::new(
        TrustRoots::from_config(&roots).unwrap(),
        input["bootstrapId"].as_str().unwrap(),
    )
    .unwrap();
    let now = input["nowMs"].as_i64().unwrap();
    if let Some(keystate) = input["keystate"].as_str() {
        let verified = trust.verify_keystate(keystate.as_bytes(), now).unwrap();
        trust = trust.with_keystate(&verified);
    }
    let bytes: Vec<u8> = match &input["envelope"] {
        Value::String(text) => text.as_bytes().to_vec(),
        other => vec![b' '; other["oversizeBytes"].as_u64().unwrap() as usize],
    };
    let max_serial = input["maxSerial"].as_u64();
    let error = |error: flare_access_contract::trust::TrustError| json!({ "error": { "code": error.code(), "kind": error.kind().as_str() } });
    let serial_check = |serial: u64| match check_serial(serial, max_serial) {
        Ok(SerialCheck::Newer) => Ok("newer"),
        Ok(SerialCheck::Same) => Ok("same"),
        Err(rollback) => Err(rollback),
    };
    match input["docType"].as_str().unwrap_or("access") {
        "keystate" => match trust.verify_keystate(&bytes, now) {
            Ok(verified) => match serial_check(verified.serial) {
                Ok(check) => json!({ "ok": {
                    "serial": verified.serial,
                    "signedBy": verified.signed_by,
                    "revoked": verified.revoked.iter().collect::<Vec<_>>(),
                    "serialCheck": check,
                }}),
                Err(rollback) => error(rollback),
            },
            Err(failure) => error(failure),
        },
        _ => match trust.verify_access(&bytes, now) {
            Ok(verified) => match serial_check(verified.serial) {
                Ok(check) => json!({ "ok": {
                    "serial": verified.serial,
                    "keyId": verified.key_id,
                    "stale": verified.is_stale(now),
                    "serialCheck": check,
                }}),
                Err(rollback) => error(rollback),
            },
            Err(failure) => error(failure),
        },
    }
}

fn verify_vectors() -> Value {
    let k = keys();
    let good_cert = issue(
        "root-a",
        &k.root_a,
        &cert("ok-2026h2-01", &k.online, "root-a"),
    );
    let good = signed(
        &manifest_payload(1042),
        &k,
        std::slice::from_ref(&good_cert),
    );
    let roots = trust_roots_json(&k);
    let base = |envelope: Value| json!({ "docType": "access", "trustRoots": roots, "bootstrapId": BOOTSTRAP_ID, "nowMs": NOW_MS, "envelope": envelope });
    let vary = |envelope: Value, patch: Value| {
        let mut input = base(envelope);
        for (key, value) in patch.as_object().unwrap() {
            input[key] = value.clone();
        }
        input
    };
    let with_cert = |cert: KeyCert, root_id: &str, root: &SigningKey| {
        signed(&manifest_payload(1042), &k, &[issue(root_id, root, &cert)])
    };
    let mut usage_cert = cert("ok-2026h2-01", &k.online, "root-a");
    usage_cert.usages = vec!["release".into()];
    let mut scoped_out = cert("ok-2026h2-01", &k.online, "root-a");
    scoped_out.scope.bootstrap_ids = vec!["0000000000000000".into()];
    let mut scoped_in = cert("ok-2026h2-01", &k.online, "root-a");
    scoped_in.scope.bootstrap_ids = vec![BOOTSTRAP_ID.into()];
    // 由 root-a 签发却声称 rootKeyId = root-b。
    let liar_cert = cert("ok-2026h2-01", &k.online, "root-b");
    let revoked_keystate = String::from_utf8(sign_keystate(
        &keystate(3, &["ok-2026h2-01"], vec![]),
        &Signer {
            key_id: "root-a",
            key: &k.root_a,
        },
    ))
    .unwrap();
    let cert_supplying_keystate = String::from_utf8(sign_keystate(
        &keystate(
            4,
            &[],
            vec![issue(
                "root-b",
                &k.root_b,
                &cert("ok-2026h2-02", &k.online_2, "root-b"),
            )],
        ),
        &Signer {
            key_id: "root-b",
            key: &k.root_b,
        },
    ))
    .unwrap();
    let rotated = sign_payload(
        &serde_json::to_vec(&manifest_payload(1043)).unwrap(),
        ACCESS_TYPE,
        &[("ok-2026h2-02", &k.online_2)],
        &[],
    );
    let two_signatures = sign_payload(
        &serde_json::to_vec(&manifest_payload(1042)).unwrap(),
        ACCESS_TYPE,
        &[("ok-unknown", &k.online_2), ("ok-2026h2-01", &k.online)],
        std::slice::from_ref(&good_cert),
    );
    let mut wrong_bootstrap = manifest_payload(1042);
    wrong_bootstrap["bootstrapId"] = "c0ffee0000000000".into();
    let mut v2 = manifest_payload(1042);
    v2["schema"] = "flare.access.v2".into();
    let mut ip_host = manifest_payload(1042);
    ip_host["regions"][0]["cells"][0]["accessPoints"][0]["host"] = "203.0.113.10".into();

    let keystate_ok = String::from_utf8(sign_keystate(
        &keystate(7, &["ok-2026h1-01"], vec![]),
        &Signer {
            key_id: "root-a",
            key: &k.root_a,
        },
    ))
    .unwrap();
    let keystate_by_online = String::from_utf8(sign_keystate(
        &keystate(7, &[], vec![]),
        &Signer {
            key_id: "ok-2026h2-01",
            key: &k.online,
        },
    ))
    .unwrap();

    json!({
        "description": "Access manifest and keystate verification. Steps: size <= 65536 bytes; DSSE envelope; payloadType; for access documents every keyCerts entry (plus certificates from the installed keystate) is checked against the built-in roots (root signature, rootKeyId, notBefore <= now + 24h, notAfter >= now - 24h, usage, scope, not revoked) and at least one signature must verify with a valid certificate; keystate documents must be signed directly by a root. Then payload schema, structure and bootstrapId. Expired access manifests are accepted with stale = true. Finally serial is compared with maxSerial (absent = never accepted). On failure the first signature's failure is reported. Signing keys are test-only Ed25519 keys derived from fixed 32-byte seeds.",
        "testKeys": {
            "root-a": "seed 0x11 x 32", "root-b": "seed 0x22 x 32", "root-x (not trusted)": "seed 0x55 x 32",
            "ok-2026h2-01": "seed 0x33 x 32", "ok-2026h2-02": "seed 0x44 x 32"
        },
        "cases": cases(eval_verify, vec![
            ("valid", base(good.clone().into())),
            ("valid but expired is stale", vary(good.clone().into(), json!({ "nowMs": NOW_MS + 31 * DAY_MS }))),
            ("certificate within clock skew", vary(good.clone().into(), json!({ "nowMs": 1_798_416_000_000i64 + 23 * 3_600_000 }))),
            ("same serial", vary(good.clone().into(), json!({ "maxSerial": 1042 }))),
            ("rollback", vary(good.clone().into(), json!({ "maxSerial": 1043 }))),
            ("tampered payload", base(tamper_payload(&good).into())),
            ("tampered certificate", base(signed(&manifest_payload(1042), &k, &[tamper_cert(&good_cert)]).into())),
            ("certificate from untrusted root", base(with_cert(cert("ok-2026h2-01", &k.online, "root-x"), "root-x", &k.root_x).into())),
            ("certificate rootKeyId mismatch", base(with_cert(liar_cert, "root-a", &k.root_a).into())),
            ("certificate expired", vary(good.clone().into(), json!({ "nowMs": 1_798_416_000_000i64 + DAY_MS + 1 }))),
            ("certificate not yet valid", vary(good.clone().into(), json!({ "nowMs": 1_782_864_000_000i64 - DAY_MS - 1 }))),
            ("certificate usage excludes access", base(with_cert(usage_cert, "root-a", &k.root_a).into())),
            ("certificate scope excludes app", base(with_cert(scoped_out, "root-a", &k.root_a).into())),
            ("certificate scope names app", base(with_cert(scoped_in, "root-a", &k.root_a).into())),
            ("signing key revoked", vary(good.clone().into(), json!({ "keystate": revoked_keystate }))),
            ("no certificate for key", base(signed(&manifest_payload(1042), &k, &[]).into())),
            ("root must not sign manifests directly", base(sign_payload(&serde_json::to_vec(&manifest_payload(1042)).unwrap(), ACCESS_TYPE, &[("root-a", &k.root_a)], &[]).into())),
            ("second signature verifies", base(two_signatures.into())),
            ("certificate supplied by keystate (root-b)", vary(rotated.into(), json!({ "keystate": cert_supplying_keystate }))),
            ("wrong payloadType", base(sign_payload(&serde_json::to_vec(&manifest_payload(1042)).unwrap(), "application/vnd.flare.release.v1+json", &[("ok-2026h2-01", &k.online)], std::slice::from_ref(&good_cert)).into())),
            ("wrong bootstrapId", base(signed(&wrong_bootstrap, &k, std::slice::from_ref(&good_cert)).into())),
            ("unsupported schema", base(signed(&v2, &k, std::slice::from_ref(&good_cert)).into())),
            ("structurally invalid payload", base(signed(&ip_host, &k, std::slice::from_ref(&good_cert)).into())),
            ("oversize", base(json!({ "oversizeBytes": 65_537 }))),
            ("not an envelope", base("{\"hello\":1}".into())),
            ("keystate valid", vary(keystate_ok.clone().into(), json!({ "docType": "keystate" }))),
            ("keystate rollback", vary(keystate_ok.clone().into(), json!({ "docType": "keystate", "maxSerial": 8 }))),
            ("keystate signed by online key", vary(keystate_by_online.into(), json!({ "docType": "keystate" }))),
            ("keystate tampered", vary(tamper_keystate(&keystate_ok).into(), json!({ "docType": "keystate" }))),
            ("keystate with access payloadType", vary(good.into(), json!({ "docType": "keystate" }))),
        ]),
    })
}

fn tamper_keystate(envelope: &str) -> String {
    let mut parsed: Envelope = serde_json::from_str(envelope).unwrap();
    let mut payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parsed.payload).unwrap()).unwrap();
    payload["revokedKeyIds"] = json!([]);
    parsed.payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    String::from_utf8(parsed.to_json_bytes()).unwrap()
}

#[test]
fn manifest_verify_vectors() {
    ensure_current("manifest_verify.json", &verify_vectors());
    replay("manifest_verify.json", eval_verify);
}

// ---------------------------------------------------------------------------
// URL 解析：与 `url` crate 对照
// ---------------------------------------------------------------------------

const REPAIRED: &str = "url 删掉或改写后放行，这里拒绝";
const NO_AUTHORITY: &str = "没有 // 权限段，调用点都要主机";
const OTHER_SCHEME: &str = "file、ftp 不是这批调用点的协议";
const USERINFO: &str = "userinfo 没有正当用途，还能伪装主机";
const HOST_CHARS: &str = "主机只收 [A-Za-z0-9._-]，不带 IDNA";
const UNCHECKED_ACE: &str = "比 url 宽：xn-- 标签按普通 ASCII 处理，不校验 Punycode";
const EMPTY_HOST: &str = "空主机：url 跳过多余的斜杠或留空，这里拒绝";
const EMPTY_LABEL: &str = "空标签不是可解析的主机名";
const LOOSE_IPV4: &str = "只收规范的四段十进制 IPv4";
const EMPTY_PORT: &str = "空端口多半是拼接错误";
const DOT_SEGMENT: &str = "路径穿越：url 折叠后放行，这里直接拒绝";

fn eval_url(input: &Value) -> Value {
    match ParsedUrl::parse(input["url"].as_str().unwrap()) {
        Ok(url) => json!({
            "scheme": url.scheme(),
            "host": url.host_str(),
            "ip": url.ip().map(|ip| ip.to_string()),
            "port": url.port(),
            "path": url.path(),
            "query": url.query(),
            "fragment": url.fragment(),
            "queryPairs": url.query_pairs().collect::<Vec<_>>(),
            "serialized": url.to_string(),
        }),
        Err(error) => json!({ "rejected": format!("{error:?}") }),
    }
}

#[rustfmt::skip]
fn url_vectors() -> Value {
    // （名称，输入，与 `url` 判定不同时的理由）。理由为空表示两者判定相同。
    let inputs: &[(&str, &str, Option<&str>)] = &[
        // 正常地址
        ("mirror", "https://cdn.example.com/access.json", None),
        ("all parts", "https://cdn.example.com:8443/a/b?x=1&y=2#frag", None),
        ("no path", "https://cdn.example.com", None),
        ("query without path", "https://cdn.example.com?x=1", None),
        ("fragment without path", "https://cdn.example.com#x", None),
        ("empty query and fragment", "https://cdn.example.com/?#", None),
        ("doh resolver", "https://dns.google/dns-query", None),
        ("dev http", "http://localhost:8080/", None),
        ("dev ws", "ws://127.0.0.1:60051/ws", None),
        ("wss", "wss://im.example.com/ws", None),
        ("quic", "quic://im.example.com:60052", None),
        ("quic ipv4", "quic://127.0.0.1:60052", None),
        ("recovery link", "flare-recover://v1?p=abc&k=root-1&s=sig", None),
        ("recovery link with slash", "flare-recover://v1/?p=abc", None),
        ("underscore host", "http://flare_gateway:8080/", None),
        ("single label host", "http://gateway/", None),
        ("trailing dot host", "https://example.com./", None),
        ("edge hyphens", "https://-a-.example/", None),
        ("double hyphen", "https://ab--cd.example/", None),
        ("double slash in path", "https://a.example//b//c", None),
        // 大小写
        ("upper scheme and host", "HTTPS://CDN.EXAMPLE.COM/Path", None),
        ("non-special host keeps case", "QUIC://EXAMPLE.com:1", None),
        ("recovery host keeps case", "flare-recover://V1?p=a", None),
        // 端口边界
        ("https default port", "https://a.example:443/", None),
        ("http default port", "http://a.example:80/", None),
        ("ws default port", "ws://a.example:80/", None),
        ("wss default port", "wss://a.example:443/", None),
        ("cross default port", "https://a.example:80/", None),
        ("non-special keeps 443", "quic://a.example:443", None),
        ("port zero", "https://a.example:0/", None),
        ("port max", "https://a.example:65535/", None),
        ("port too large", "https://a.example:65536/", None),
        ("port leading zeros", "https://a.example:00443/", None),
        ("port plus sign", "https://a.example:+80/", None),
        ("port letters", "https://a.example:80a/", None),
        ("port twice", "https://a.example:80:80/", None),
        ("port empty", "https://a.example:/", Some(EMPTY_PORT)),
        // IPv4
        ("ipv4", "https://203.0.113.10/", None),
        ("ipv4 max", "https://255.255.255.255/", None),
        ("ipv4 octet too large", "https://1.2.3.256/", None),
        ("ipv4 short", "https://127.1/", Some(LOOSE_IPV4)),
        ("ipv4 hex", "https://0x7f.0.0.1/", Some(LOOSE_IPV4)),
        ("ipv4 octal", "https://0177.0.0.1/", Some(LOOSE_IPV4)),
        ("ipv4 integer", "https://2130706433/", Some(LOOSE_IPV4)),
        ("ipv4 octal integer", "https://017700000001/", Some(LOOSE_IPV4)),
        ("ipv4 trailing dot", "https://1.2.3.4./", Some(LOOSE_IPV4)),
        ("numeric last label", "https://foo.1/", None),
        ("hex last label", "https://foo.0x1/", None),
        ("non-special numeric host", "quic://1.2.3.256:1", None),
        // IPv6
        ("ipv6 loopback", "https://[::1]/", None),
        ("ipv6 port", "https://[::1]:8443/", None),
        ("ipv6 upper", "https://[2001:DB8::1]/", None),
        ("ipv6 full", "https://[1:2:3:4:5:6:7:8]/", None),
        ("ipv6 mapped", "https://[::ffff:1.2.3.4]/", None),
        ("ipv6 non-special", "quic://[::1]:9000", None),
        ("ipv6 unclosed", "https://[::1/", None),
        ("ipv6 bad digit", "https://[::g]/", None),
        ("ipv6 zone", "https://[fe80::1%25en0]/", None),
        ("ipv6 tail", "https://[::1]x/", None),
        ("ipv4 in brackets", "https://[127.0.0.1]/", None),
        // 空主机
        ("scheme only", "https://", None),
        ("empty host with port", "https://:443/", None),
        ("empty host with query", "https://?x", None),
        ("empty host with path", "https:///a.example/", Some(EMPTY_HOST)),
        ("non-special empty host", "quic://", Some(EMPTY_HOST)),
        ("non-special empty host with path", "quic:///a", Some(EMPTY_HOST)),
        // userinfo
        ("user and password", "https://user:pass@a.example/", Some(USERINFO)),
        ("empty userinfo", "https://@a.example/", Some(USERINFO)),
        ("host as userinfo", "https://good.example@evil.example/", Some(USERINFO)),
        ("port as userinfo", "https://good.example:443@evil.example/", Some(USERINFO)),
        ("encoded slash in userinfo", "https://evil.example%2f@good.example/", Some(USERINFO)),
        ("at sign in path", "https://a.example/@b", None),
        ("at sign in query", "https://good.example?@evil.example/", None),
        ("at sign in fragment", "https://good.example#@evil.example/", None),
        // 反斜杠
        ("backslash path", "https://a.example\\b", Some(REPAIRED)),
        ("backslash authority", "https:\\\\a.example\\", Some(REPAIRED)),
        ("backslash before userinfo", "https://evil.example\\@good.example/", Some(REPAIRED)),
        ("backslash in query", "https://a.example/?a=\\b", Some(REPAIRED)),
        ("backslash in non-special host", "quic://a\\b", None),
        ("backslash in non-special path", "quic://a/b\\c", Some(REPAIRED)),
        // 缺斜杠或多斜杠
        ("no slashes", "https:a.example/", Some(NO_AUTHORITY)),
        ("one slash", "https:/a.example/", Some(NO_AUTHORITY)),
        ("four slashes", "https:////a.example/", Some(EMPTY_HOST)),
        ("non-special no authority", "quic:a", Some(NO_AUTHORITY)),
        ("host and port read as scheme", "example.com:80", Some(NO_AUTHORITY)),
        ("mailto", "mailto:a@example.com", Some(NO_AUTHORITY)),
        ("data", "data:text/plain,x", Some(NO_AUTHORITY)),
        ("javascript", "javascript:alert(1)", Some(NO_AUTHORITY)),
        ("protocol relative", "//a.example/", None),
        ("bare host", "a.example", None),
        ("empty", "", None),
        ("colon", ":", None),
        ("digit scheme", "1https://a.example/", None),
        ("space in scheme", "ht tp://a.example/", None),
        // 不支持的 special scheme
        ("ftp", "ftp://a.example/", Some(OTHER_SCHEME)),
        ("file", "file:///etc/passwd", Some(OTHER_SCHEME)),
        // 控制字符与空白
        ("leading space", " https://a.example/", Some(REPAIRED)),
        ("trailing newline", "https://a.example/\n", Some(REPAIRED)),
        ("tab in host", "https://a.ex\tample/", Some(REPAIRED)),
        ("newline in host", "https://a.ex\nample/", Some(REPAIRED)),
        ("newline in path", "https://a.example/a\nb", Some(REPAIRED)),
        ("carriage return in query", "https://a.example/?a\rb", Some(REPAIRED)),
        ("tab in scheme", "ht\ttps://a.example/", Some(REPAIRED)),
        ("nul in host", "https://a\u{0}b.example/", None),
        ("nul in path", "https://a.example/a\u{0}b", Some(REPAIRED)),
        ("del in path", "https://a.example/a\u{7f}b", Some(REPAIRED)),
        ("unit separator in path", "https://a.example/a\u{1f}b", Some(REPAIRED)),
        ("space in path", "https://a.example/a b", Some(REPAIRED)),
        ("space in query", "https://a.example/?a b", Some(REPAIRED)),
        ("space in host", "https://a b.example/", None),
        // 百分号编码
        ("encoded letter in host", "https://ex%61mple.com/", Some(HOST_CHARS)),
        ("encoded slash in host", "https://a%2fb.example/", None),
        ("encoded nul in host", "https://a%00b.example/", None),
        ("encoded percent in non-special host", "quic://a%41b", Some(HOST_CHARS)),
        ("encoded slash in path", "https://a.example/a%2fb", None),
        ("encoded backslash in path", "https://a.example/a%5cb", None),
        ("encoded nul in path", "https://a.example/a%00b", None),
        ("bad escape in path", "https://a.example/%zz", None),
        ("bare percent in path", "https://a.example/100%", None),
        ("bare percent in query", "https://a.example/?a=100%", None),
        ("escapes in query pairs", "https://a.example/?a=%E4%BD%A0+b&c=%2B&d", None),
        // 路径穿越
        ("parent segment", "https://a.example/a/../b", Some(DOT_SEGMENT)),
        ("current segment", "https://a.example/a/./b", Some(DOT_SEGMENT)),
        ("parent at root", "https://a.example/..", Some(DOT_SEGMENT)),
        ("parent at end", "https://a.example/a/..", Some(DOT_SEGMENT)),
        ("encoded parent", "https://a.example/%2e%2e/etc/passwd", Some(DOT_SEGMENT)),
        ("upper encoded parent", "https://a.example/%2E%2E/b", Some(DOT_SEGMENT)),
        ("half encoded parent", "https://a.example/.%2e/b", Some(DOT_SEGMENT)),
        ("encoded current", "https://a.example/%2e/b", Some(DOT_SEGMENT)),
        ("non-special parent", "quic://a.example/a/../b", Some(DOT_SEGMENT)),
        ("dots inside a segment", "https://a.example/a..b/...", None),
        ("dot-dot in query", "https://a.example/?x=../..", None),
        ("dot-dot in fragment", "https://a.example/#../..", None),
        ("double encoded parent", "https://a.example/%252e%252e/b", None),
        ("encoded slash after dots", "https://a.example/%2e%2e%2fb", None),
        // 按 `url` 的编码集转义
        ("path punctuation", "https://a.example/\"<>`{}|^[]'!$&()*+,;=:@~", None),
        ("special query punctuation", "https://a.example/?\"<>'`{}|^[]", None),
        ("non-special query punctuation", "quic://a.example/?\"<>'", None),
        ("fragment punctuation", "https://a.example/#\"<>`'{}|^", None),
        ("question mark in query", "https://a.example/?a?b", None),
        ("hash in fragment", "https://a.example/#a#b", None),
        // 非 ASCII
        ("non-ascii path", "https://a.example/你好", None),
        ("non-ascii query", "https://a.example/?q=你好", None),
        ("non-ascii fragment", "https://a.example/#你好", None),
        ("ideographic space in path", "https://a.example/a\u{3000}b", None),
        ("non-ascii host", "https://例子.cn/", Some(HOST_CHARS)),
        ("non-ascii non-special host", "quic://例子.cn:1", Some(HOST_CHARS)),
        ("full-width host", "https://ＥＸＡＭＰＬＥ.com/", Some(HOST_CHARS)),
        ("ideographic full stop", "https://a。example/", Some(HOST_CHARS)),
        ("ace label", "https://xn--fiqs8s.example/", None),
        ("upper ace label", "https://XN--fiqs8s.example/", None),
        ("bad ace label", "https://xn--a.example/", Some(UNCHECKED_ACE)),
        ("ace prefix only", "https://xn--.example/", Some(UNCHECKED_ACE)),
        ("ace label in non-special host", "quic://xn--a.example:1", None),
        // 主机字符
        ("exclamation in host", "https://a!b.example/", Some(HOST_CHARS)),
        ("tilde in host", "https://a~b.example/", Some(HOST_CHARS)),
        ("dollar in host", "https://a$b.example/", Some(HOST_CHARS)),
        ("empty label", "https://a..b.example/", Some(EMPTY_LABEL)),
        ("leading dot", "https://.a.example/", Some(EMPTY_LABEL)),
        ("only a dot", "https://./", Some(EMPTY_LABEL)),
        ("angle bracket in host", "https://a<b.example/", None),
        ("pipe in host", "https://a|b.example/", None),
        ("caret in host", "https://a^b.example/", None),
    ];
    let inputs = inputs
        .iter()
        .map(|(name, url, differs)| (*name, json!({ "url": url, "differs": differs })))
        .collect();
    json!({
        "description": "ParsedUrl 的判定与解析结果。input.differs 非空：与 url crate 判定不同，值是理由。除 xn-- 一类外都是 url 接受而 ParsedUrl 有意拒绝。",
        "cases": cases(eval_url, inputs),
    })
}

#[test]
fn url_parse_vectors() {
    let generated = url_vectors();
    ensure_current("url_parse.json", &generated);
    replay("url_parse.json", eval_url);
    for case in generated["cases"].as_array().unwrap() {
        let name = &case["name"];
        let input = case["input"]["url"].as_str().unwrap();
        let differs = case["input"]["differs"].as_str();
        match (ParsedUrl::parse(input), url::Url::parse(input)) {
            (Ok(ours), Ok(theirs)) => {
                assert_eq!(
                    differs, None,
                    "{name}: both accept, but marked as different"
                );
                assert_eq!(ours.scheme(), theirs.scheme(), "{name}");
                assert_eq!(Some(ours.host_str()), theirs.host_str(), "{name}");
                assert_eq!(ours.port(), theirs.port(), "{name}");
                assert_eq!(ours.path(), theirs.path(), "{name}");
                assert_eq!(ours.query(), theirs.query(), "{name}");
                assert_eq!(ours.fragment(), theirs.fragment(), "{name}");
                assert_eq!(ours.to_string(), theirs.as_str(), "{name}");
                let pairs: Vec<_> = theirs.query_pairs().into_owned().collect();
                assert_eq!(ours.query_pairs().collect::<Vec<_>>(), pairs, "{name}");
            }
            // 比 `url` 宽的只允许 `xn--` 这一类。
            (Ok(_), Err(error)) => {
                assert_eq!(differs, Some(UNCHECKED_ACE), "{name}: url says {error}")
            }
            (Err(_), Ok(_)) => assert!(
                differs.is_some_and(|reason| reason != UNCHECKED_ACE),
                "{name}: tightened without a reason"
            ),
            (Err(_), Err(_)) => assert_eq!(differs, None, "{name}: url rejects this too"),
        }
    }
}
