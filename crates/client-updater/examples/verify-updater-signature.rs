//! Build-time adapter for the exact verifier used by tauri-plugin-updater.
//! No private keys, runtime bypass, network, installation, or new wire format.
use base64::{engine::general_purpose::STANDARD, Engine};
use minisign_verify::{PublicKey, Signature};
use std::{fs, io, path::Path};

fn bounded(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(io::Error::other("invalid updater verification input"));
    }
    fs::read(path)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 3 {
        return Err("usage: verify-updater-signature FINAL_PACKAGE SIGNATURE_BASE64_FILE PUBLIC_KEY_BASE64_FILE".into());
    }
    let data = bounded(Path::new(&arguments[0]), 2 * 1024 * 1024 * 1024)?;
    let signature = bounded(Path::new(&arguments[1]), 16 * 1024)?;
    let public_key = bounded(Path::new(&arguments[2]), 16 * 1024)?;
    // Same STANDARD base64 → UTF8 → minisign decode → verify(data, true)
    // sequence as tauri-plugin-updater 2.10.1 updater.rs::verify_signature.
    let signature = STANDARD.decode(std::str::from_utf8(&signature)?.trim())?;
    let public_key = STANDARD.decode(std::str::from_utf8(&public_key)?.trim())?;
    let signature = Signature::decode(std::str::from_utf8(&signature)?)?;
    let public_key = PublicKey::decode(std::str::from_utf8(&public_key)?)?;
    public_key.verify(&data, &signature, true)?;
    println!("OK: final updater signature matches the explicit public pin");
    Ok(())
}
