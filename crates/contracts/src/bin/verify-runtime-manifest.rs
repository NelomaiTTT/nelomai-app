//! Command-line adapter for the runtime's own authenticated manifest contracts.
use nelomai_contracts::{
    verify_container_manifest, verify_runtime_artifact_manifest,
    verify_runtime_release_set_manifest,
};
use std::{env, fs, io, path::Path};

fn bounded(path: &str, maximum: u64) -> io::Result<Vec<u8>> {
    let path = Path::new(path);
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(io::Error::other("invalid or oversized manifest input"));
    }
    fs::read(path)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 7 {
        return Err("usage: verify-runtime-manifest artifact|container|release-set JSON SIG PUBLIC_KEY PLATFORM|ROOT_SHA256 ARCHITECTURE|-".into());
    }
    let raw = bounded(&args[2], 1024 * 1024)?;
    let signature = bounded(&args[3], 64)?;
    let key = bounded(&args[4], 32)?;
    match args[1].as_str() {
        "artifact" => {
            let verified =
                verify_runtime_artifact_manifest(&raw, &signature, &key, &args[5], &args[6])?;
            println!("{}", serde_json::to_string(verified.manifest())?);
        }
        "container" => {
            let verified = verify_container_manifest(&raw, &signature, &key, &args[5], &args[6])?;
            println!("{}", serde_json::to_string(verified.manifest())?);
        }
        "release-set" if args[6] == "-" => {
            let verified = verify_runtime_release_set_manifest(&raw, &signature, &key, &args[5])?;
            println!("{}", serde_json::to_string(verified.manifest())?);
        }
        _ => return Err("unknown manifest contract".into()),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("runtime manifest rejected: {error}");
        std::process::exit(1);
    }
}
