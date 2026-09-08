use std::fs;
use tempfile::tempdir;

pub(crate) fn owned_dispatcher() -> (
    tempfile::TempDir,
    std::sync::Arc<std::sync::Mutex<nelomai_contracts::dispatcher::ProcessDispatcher>>,
) {
    owned_dispatcher_with_slots(false)
}

pub(crate) fn owned_dispatcher_with_slots(
    two_slots: bool,
) -> (
    tempfile::TempDir,
    std::sync::Arc<std::sync::Mutex<nelomai_contracts::dispatcher::ProcessDispatcher>>,
) {
    use ed25519_dalek::{Signer, SigningKey};
    use nelomai_contracts::dispatcher as d;
    use serde_json::json;
    let target = tempdir().unwrap();
    let source = tempdir().unwrap();
    let engine = source
        .path()
        .join("engines/latest/0.2.16/nelomai-unix-service");
    fs::create_dir_all(engine.parent().unwrap()).unwrap();
    let engine_bytes = br#"#!/usr/bin/python3
import json,struct,sys,fcntl,os
lease=open(sys.argv[2]+'/engine-owner.lock','a')
fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
while True:
    size=sys.stdin.buffer.read(4)
    if not size: break
    value=json.loads(sys.stdin.buffer.read(struct.unpack('<I',size)[0]))
    if value.get('dispatcher_control')=='ready': reply={'engine_ready':True}
    elif value.get('dispatcher_control')=='stop': reply={'engine_stopped':True}
    else: reply={'protocolVersion':5,'ok':True,'state':'running','serviceVersion':os.path.basename(os.path.dirname(sys.argv[0]))}
    data=json.dumps(reply).encode()
    sys.stdout.buffer.write(struct.pack('<I',len(data))+data); sys.stdout.buffer.flush()
"#;
    fs::write(engine, engine_bytes).unwrap();
    let manifest = serde_json::to_vec(&json!({"format_version":1,"container_version":"0.2.16","release_set_id":"owned-test","minimum_runtime_contract":1,"maximum_runtime_contract":1,"slots":[{"slot":"latest","manifest":{"format_version":1,"runtime_version":"0.2.16","source_commit":"0123456789abcdef0123456789abcdef01234567","platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,"contract_version":1,"files":[{"path":"nelomai-unix-service","role":"executable","size_bytes":engine_bytes.len(),"sha256":d::digest(engine_bytes)}]}}]})).unwrap();
    let manifest = if two_slots {
        let mut value: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        let mut stable = value["slots"][0].clone();
        stable["slot"] = json!("stable");
        value["slots"][0]["manifest"]["runtime_version"] = json!("0.2.17");
        value["slots"].as_array_mut().unwrap().push(stable);
        value["stable_release_set_sha256"] = json!("b".repeat(64));
        value["stable_platform_manifest_sha256"] = json!("c".repeat(64));
        fs::rename(
            source.path().join("engines/latest/0.2.16"),
            source.path().join("engines/latest/0.2.17"),
        )
        .unwrap();
        let stable = source.path().join("engines/stable/0.2.16");
        fs::create_dir_all(&stable).unwrap();
        fs::write(stable.join("nelomai-unix-service"), engine_bytes).unwrap();
        serde_json::to_vec(&value).unwrap()
    } else {
        manifest
    };
    let key = SigningKey::from_bytes(&[82; 32]);
    let mut signed = nelomai_contracts::CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
    signed.extend(&manifest);
    fs::write(source.path().join(d::MANIFEST_NAME), manifest).unwrap();
    fs::write(
        source.path().join(d::SIGNATURE_NAME),
        key.sign(&signed).to_bytes(),
    )
    .unwrap();
    let uid = unsafe { libc::geteuid() };
    let installation = d::Installation::for_owner(
        target.path(),
        key.verifying_key().to_bytes(),
        std::env::consts::OS,
        std::env::consts::ARCH,
        uid,
    );
    installation
        .install(
            source.path(),
            &std::env::current_exe().unwrap(),
            &uid.to_string(),
            &d::RealInstallIo,
        )
        .unwrap();
    let dispatcher = d::ProcessDispatcher::new(installation).unwrap();
    (
        target,
        std::sync::Arc::new(std::sync::Mutex::new(dispatcher)),
    )
}
