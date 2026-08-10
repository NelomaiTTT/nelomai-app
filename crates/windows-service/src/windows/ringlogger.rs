use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MAGIC: u32 = 0x0bad_babe;
const HEADER_BYTES: usize = 8;
const LINE_BYTES: usize = 8 + 512;
const MAX_LINES: usize = 2048;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

pub(crate) fn read_amneziawg_ringlogger() -> io::Result<String> {
    let program_data = std::env::var_os("ProgramData")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ProgramData is unavailable"))?;
    read_ringlogger(&amneziawg_ringlogger_path(&PathBuf::from(program_data)))
}

fn amneziawg_ringlogger_path(program_data: &Path) -> PathBuf {
    program_data
        .join("Nelomai")
        .join("AmneziaWG")
        .join("Data")
        .join("log.bin")
}

fn read_ringlogger(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    decode_ringlogger(&bytes)
}

fn decode_ringlogger(bytes: &[u8]) -> io::Result<String> {
    let expected = HEADER_BYTES + LINE_BYTES * MAX_LINES;
    if bytes.len() < expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "AmneziaWG ringlogger is truncated",
        ));
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("fixed magic field"));
    if magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "AmneziaWG ringlogger has invalid magic",
        ));
    }
    let next_index =
        u32::from_le_bytes(bytes[4..8].try_into().expect("fixed next-index field")) as usize;
    let mut output = String::new();
    for offset in 0..MAX_LINES {
        let index = (next_index + offset) % MAX_LINES;
        let start = HEADER_BYTES + index * LINE_BYTES;
        let timestamp_ns = i64::from_le_bytes(
            bytes[start..start + 8]
                .try_into()
                .expect("fixed timestamp field"),
        );
        if timestamp_ns == 0 {
            continue;
        }
        let line = &bytes[start + 8..start + LINE_BYTES];
        let length = line
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(line.len());
        if length == 0 {
            continue;
        }
        let message = String::from_utf8_lossy(&line[..length]).replace(['\r', '\n'], " ");
        output.push_str("time_ns=");
        output.push_str(&timestamp_ns.to_string());
        output.push(' ');
        output.push_str(&message);
        output.push('\n');
    }
    Ok(tail_string(output, MAX_OUTPUT_BYTES))
}

fn tail_string(value: String, maximum: usize) -> String {
    if value.len() <= maximum {
        return value;
    }
    let mut start = value.len() - maximum;
    while start < value.len() && !value.is_char_boundary(start) {
        start += 1;
    }
    value[start..].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring(next_index: u32, entries: &[(usize, i64, &str)]) -> Vec<u8> {
        let mut bytes = vec![0_u8; HEADER_BYTES + LINE_BYTES * MAX_LINES];
        bytes[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        bytes[4..8].copy_from_slice(&next_index.to_le_bytes());
        for (index, timestamp, message) in entries {
            let start = HEADER_BYTES + index * LINE_BYTES;
            bytes[start..start + 8].copy_from_slice(&timestamp.to_le_bytes());
            bytes[start + 8..start + 8 + message.len()].copy_from_slice(message.as_bytes());
        }
        bytes
    }

    #[test]
    fn decodes_lines_in_ring_order() {
        let bytes = ring(2, &[(0, 10, "[TUN] first"), (1, 20, "[TUN] second")]);

        let decoded = decode_ringlogger(&bytes).unwrap();

        assert_eq!(decoded, "time_ns=10 [TUN] first\ntime_ns=20 [TUN] second\n");
    }

    #[test]
    fn decodes_wrapped_lines_oldest_first() {
        let bytes = ring(
            (MAX_LINES as u32) + 1,
            &[(MAX_LINES - 1, 10, "old"), (0, 20, "new")],
        );

        let decoded = decode_ringlogger(&bytes).unwrap();

        assert_eq!(decoded, "time_ns=10 old\ntime_ns=20 new\n");
    }

    #[test]
    fn rejects_unknown_format() {
        let bytes = vec![0_u8; HEADER_BYTES + LINE_BYTES * MAX_LINES];
        assert_eq!(
            decode_ringlogger(&bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn uses_nelomai_specific_ringlogger_directory() {
        assert_eq!(
            amneziawg_ringlogger_path(Path::new(r"C:\ProgramData")),
            PathBuf::from(r"C:\ProgramData")
                .join("Nelomai")
                .join("AmneziaWG")
                .join("Data")
                .join("log.bin")
        );
    }
}
