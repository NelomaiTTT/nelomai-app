//! Root-private diagnostics survive the versioned engine, but not a reboot
//! (/run is intentionally volatile). Reading a report never starts the engine.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub(super) const EVENTS_FILE: &str = "helper-events.log";
pub(super) const MAX_EVENTS_BYTES: usize = 24 * 1024;

fn trusted_directory(directory: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::other("untrusted diagnostic directory"));
    }
    Ok(())
}

fn private_regular(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::other("untrusted diagnostic file"));
    }
    Ok(())
}

pub(super) fn read_tail(directory: &Path, name: &str, limit: usize) -> io::Result<String> {
    trusted_directory(directory)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.join(name))?;
    private_regular(&file)?;
    let offset = file.metadata()?.len().saturating_sub(limit as u64);
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    file.take(limit as u64).read_to_end(&mut bytes)?;
    let mut text = String::from_utf8_lossy(&bytes).replace('\0', "");
    if offset > 0 {
        if let Some(newline) = text.find('\n') {
            text.drain(..=newline);
        }
    }
    // Lossy UTF-8 conversion can expand input bytes.
    let mut start = text.len().saturating_sub(limit);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text.drain(..start);
    if !text.is_empty() && !text.ends_with('\n') {
        if text.len() == limit {
            text.pop();
        }
        text.push('\n');
    }
    Ok(text)
}

pub(super) fn persist_events(directory: &Path, text: &str) -> io::Result<()> {
    trusted_directory(directory)?;
    let temporary = directory.join("helper-events.log.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&temporary)?;
    private_regular(&file)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.set_len(0)?;
    let mut offset = text.len().saturating_sub(MAX_EVENTS_BYTES);
    while !text.is_char_boundary(offset) {
        offset += 1;
    }
    let retained = &text[offset..];
    let retained = if offset > 0 {
        retained.split_once('\n').map_or("", |(_, tail)| tail)
    } else {
        retained
    };
    file.write_all(retained.as_bytes())?;
    // Atomic replacement prevents reports from observing a partial journal.
    fs::rename(temporary, directory.join(EVENTS_FILE))
}
