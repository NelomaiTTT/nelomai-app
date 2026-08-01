use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::process::{Command, Stdio};
use std::time::Instant;

fn probe_latency(target: IpAddr) -> Option<u32> {
    let started = Instant::now();
    let mut command = ping_command(target);
    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_latency(&output.stdout)
        .or_else(|| Some(started.elapsed().as_millis().clamp(1, u32::MAX as u128) as u32))
}

pub fn probe_host(target: &str) -> Option<u32> {
    let address = target.parse::<IpAddr>().ok().or_else(|| {
        (target, 0)
            .to_socket_addrs()
            .ok()?
            .next()
            .map(|address| address.ip())
    })?;
    probe_latency(address)
}

#[cfg(windows)]
fn ping_command(target: IpAddr) -> Command {
    let mut command = Command::new("ping.exe");
    command.args(["-n", "1", "-w", "1000", &target.to_string()]);
    command
}

#[cfg(target_os = "macos")]
fn ping_command(target: IpAddr) -> Command {
    let mut command = Command::new("/sbin/ping");
    command
        .env("LC_ALL", "C")
        .args(["-n", "-c", "1", "-W", "1000", &target.to_string()]);
    command
}

#[cfg(all(unix, not(target_os = "macos"), not(target_os = "android")))]
fn ping_command(target: IpAddr) -> Command {
    let mut command = Command::new("/bin/ping");
    command
        .env("LC_ALL", "C")
        .args(["-n", "-c", "1", "-W", "1", &target.to_string()]);
    command
}

#[cfg(target_os = "android")]
fn ping_command(target: IpAddr) -> Command {
    let mut command = Command::new("/system/bin/ping");
    command.args(["-n", "-c", "1", "-W", "1", &target.to_string()]);
    command
}

#[cfg(not(any(windows, unix)))]
fn ping_command(target: IpAddr) -> Command {
    let mut command = Command::new("ping");
    command.arg(target.to_string());
    command
}

fn parse_latency(output: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(output).to_ascii_lowercase();
    for marker in ["time=", "time<"] {
        if let Some(value) = number_after_marker(&text, marker) {
            return Some(value.ceil().clamp(1.0, u32::MAX as f64) as u32);
        }
    }

    // Windows localizes the word "time". The latency is the final numeric
    // value before TTL on a successful reply line.
    text.lines().find_map(|line| {
        let ttl = line.find("ttl=")?;
        let prefix = &line[..ttl];
        let marker = prefix.rfind(['=', '<'])?;
        parse_number(&prefix[marker + 1..])
            .map(|value| value.ceil().clamp(1.0, u32::MAX as f64) as u32)
    })
}

fn number_after_marker(text: &str, marker: &str) -> Option<f64> {
    let value = text.split_once(marker)?.1;
    parse_number(value)
}

fn parse_number(value: &str) -> Option<f64> {
    let number = value
        .trim_start()
        .chars()
        .take_while(|character| character.is_ascii_digit() || matches!(character, '.' | ','))
        .collect::<String>();
    (!number.is_empty())
        .then(|| number.replace(',', ".").parse().ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::parse_latency;

    #[test]
    fn parses_unix_and_localized_windows_latency() {
        assert_eq!(parse_latency(b"64 bytes: ttl=57 time=12.4 ms"), Some(13));
        assert_eq!(
            parse_latency("Ответ: число байт=32 время=7мс TTL=57".as_bytes()),
            Some(7)
        );
    }
}
