//! Compare a requested PnP description with the separately captured MIB row.
//! A match is not native creation/ownership authority. Never normalize the
//! captured row: its full original description remains a continuity field.
#![allow(dead_code)] // Native carrier factory remains gated.

pub(crate) fn matches_requested(requested: &str, observed: &str) -> bool {
    if requested.is_empty()
        || requested.encode_utf16().count() > 256
        || observed.encode_utf16().count() > 256
        || requested.chars().any(char::is_control)
        || observed.chars().any(char::is_control)
    {
        return false;
    }
    if requested == observed {
        return true;
    }
    // Windows disambiguates equal device descriptions in the MIB view. Accept
    // only that numeric suffix, not arbitrary prefix matches or trimmed aliases.
    observed
        .strip_prefix(requested)
        .and_then(|suffix| suffix.strip_prefix(" #"))
        .is_some_and(|number| {
            !number.is_empty()
                && number.len() <= 10
                && !number.starts_with('0')
                && number.bytes().all(|byte| byte.is_ascii_digit())
                && number.parse::<u32>().is_ok_and(|number| number >= 2)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observed_windows_duplicate_description_is_not_the_requested_pnp_description() {
        // Actual two-original-adapter read, 01Oct02:32UTC; B adds precisely #2.
        assert!(matches_requested(
            "Nelomai PnP proof Tunnel",
            "Nelomai PnP proof Tunnel #2"
        ));
    }
    #[test]
    fn unrequested_suffix_and_ambiguous_description_are_not_repaired() {
        for actual in [
            "Nelomai PnP proof TunnelX",
            "Nelomai PnP proof Tunnel #1",
            "Nelomai PnP proof Tunnel #02",
            "Nelomai PnP proof Tunnel #0",
            "Nelomai PnP proof Tunnel #2X",
            "Nelomai PnP proof Tunnel #2 ",
            "Nelomai PnP proof Tunnel #4294967296",
            "nelomai PnP proof Tunnel",
            "Nelomai PnP proof Tunnel #",
            "Nelomai PnP proof Tunnel #٢",
        ] {
            assert!(
                !matches_requested("Nelomai PnP proof Tunnel", actual),
                "{actual}"
            );
        }
        assert!(!matches_requested("", ""));
        assert!(!matches_requested("bad\0", "bad\0"));
    }
}
