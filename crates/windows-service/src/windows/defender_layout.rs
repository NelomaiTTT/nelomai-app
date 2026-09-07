//! Exact destination classification for the platform copy hook.
use std::{
    io,
    path::{Component, Path, PathBuf},
};

pub(crate) fn copy_exclusion_paths(
    root: &Path,
    destination: &Path,
) -> io::Result<Option<(PathBuf, PathBuf)>> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid managed engine destination",
        )
    };
    if destination.file_name().and_then(|name| name.to_str()) != Some("amneziawg-tunnel.dll") {
        return Ok(None);
    }
    let relative = destination.strip_prefix(root).map_err(|_| invalid())?;
    let parts: Vec<&str> = relative
        .components()
        .map(|part| match part {
            Component::Normal(value) => value.to_str().ok_or_else(invalid),
            _ => Err(invalid()),
        })
        .collect::<io::Result<_>>()?;
    if parts.len() != 6
        || parts[0] != "releases"
        || parts[2] != "engines"
        || !matches!(parts[3], "latest" | "stable")
    {
        return Err(invalid());
    }
    let generation = parts[1].strip_prefix(".stage-").ok_or_else(invalid)?;
    let (digest, nonce) = generation.split_once('-').ok_or_else(invalid)?;
    let hex = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if digest.len() != 64 || !hex(digest) || nonce.is_empty() || nonce.len() > 31 || !hex(nonce) {
        return Err(invalid());
    }
    let version = parts[4];
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
        || !version.as_bytes()[0].is_ascii_digit()
    {
        return Err(invalid());
    }
    let final_path = root
        .join("releases")
        .join(generation)
        .join("engines")
        .join(parts[3])
        .join(version)
        .join(parts[5]);
    Ok(Some((destination.to_owned(), final_path)))
}
