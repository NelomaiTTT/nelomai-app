//! Pure policy shared by the Windows launcher and portable regression tests.

pub(crate) fn native_handles(args: &[&str]) -> Option<[usize; 2]> {
    if args.len() != 3 || args[0] != "--private-runtime-v1" {
        return None;
    }
    let parse = |s: &str| {
        let value = s.parse::<usize>().ok()?;
        (value != 0 && value != usize::MAX && value.to_string() == s).then_some(value)
    };
    let handles = [parse(args[1])?, parse(args[2])?];
    (handles[0] != handles[1]).then_some(handles)
}

pub(crate) fn ace_allowed(
    kind: u8,
    flags: u8,
    mask: u32,
    privileged: bool,
    ancestor: bool,
) -> bool {
    if !matches!(kind, 0 | 1) {
        return false;
    }
    if flags & 8 != 0 || kind == 1 || privileged {
        return true;
    }
    // Unknown/generic access must be mapped by the OS before acceptance. At
    // ancestors, creating a sibling cannot replace the already protected child;
    // DELETE_CHILD and changes to the ancestor ACL/owner are still forbidden.
    let mutations = 0xf00d_0150 | if ancestor { 0 } else { 0x6 };
    mask & mutations == 0
}

pub(crate) fn quoted_argument(value: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in value.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        out.extend(std::iter::repeat_n(
            '\\',
            if c == '"' { slashes * 2 + 1 } else { slashes },
        ));
        slashes = 0;
        out.push(c);
    }
    out.extend(std::iter::repeat_n('\\', slashes * 2));
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_bootstrap_accepts_only_two_distinct_canonical_handle_ids() {
        assert_eq!(
            native_handles(&["--private-runtime-v1", "12", "16"]),
            Some([12, 16])
        );
        for args in [
            vec!["--private-runtime-v1"],
            vec!["--private-runtime-v1", "12", "12"],
            vec!["--private-runtime-v1", "0", "16"],
            vec!["--private-runtime-v1", "-1", "16"],
            vec!["--private-runtime-v1", "012", "16"],
            vec!["--private-runtime-v1", "+12", "16"],
            vec!["--private-runtime-v1", "12", "16", "extra"],
            vec!["--other", "12", "16"],
        ] {
            assert_eq!(native_handles(&args), None, "{args:?}");
        }
        assert_eq!(
            native_handles(&["--private-runtime-v1", &usize::MAX.to_string(), "16"]),
            None
        );
    }

    #[test]
    fn acl_never_admits_an_untrusted_writer_or_unknown_ace() {
        for mask in [
            0x40000000, 0x10000000, 0x10000, 0x40000, 0x80000, 2, 4, 0x10, 0x100, 0x40,
        ] {
            assert!(!ace_allowed(0, 0, mask, false, false), "mask {mask:x}");
            assert!(ace_allowed(0, 0, mask, true, false));
        }
        assert!(ace_allowed(0, 0, 0x1200a9, false, false)); // read/execute
        assert!(ace_allowed(1, 0, u32::MAX, false, false)); // deny does not grant
        assert!(ace_allowed(0, 8, u32::MAX, false, false)); // inherit-only: not this object
        assert!(!ace_allowed(5, 0, 0, false, false)); // unfamiliar/object callback ACE
        assert!(!ace_allowed(0, 0, 0x20000000, false, false)); // generic execute unmapped
    }

    #[test]
    fn ancestors_allow_sibling_creation_but_not_replacement_of_existing_child() {
        assert!(ace_allowed(0, 0, 2 | 4, false, true));
        assert!(!ace_allowed(0, 0, 0x40, false, true)); // FILE_DELETE_CHILD
        assert!(!ace_allowed(0, 0, 0x40000, false, true)); // WRITE_DAC
    }

    #[test]
    fn command_line_quotes_paths_with_spaces_and_trailing_slashes() {
        assert_eq!(
            quoted_argument("C:\\Program Files\\Nelomai\\runtime.exe"),
            "\"C:\\Program Files\\Nelomai\\runtime.exe\""
        );
        assert_eq!(quoted_argument("a\\\"b\\"), "\"a\\\\\\\"b\\\\\"");
    }
}
