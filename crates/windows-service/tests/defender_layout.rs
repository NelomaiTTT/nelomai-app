#[path = "../src/windows/defender_layout.rs"]
mod layout;

#[test]
fn only_exact_staged_awg_dll_gets_stage_and_final_protection() {
    let root = std::env::temp_dir().join("nelomai-layout-fixture");
    let generation = format!("{}-123abc", "a".repeat(64));
    let stage = root
        .join("releases")
        .join(format!(".stage-{generation}"))
        .join("engines/latest/0.2.16/amneziawg-tunnel.dll");
    let paths = layout::copy_exclusion_paths(&root, &stage)
        .unwrap()
        .unwrap();
    assert_eq!(paths.0, stage);
    assert_eq!(
        paths.1,
        root.join("releases")
            .join(generation)
            .join("engines/latest/0.2.16/amneziawg-tunnel.dll")
    );
    assert!(
        layout::copy_exclusion_paths(&root, &root.join("ordinary.bin"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn malformed_or_external_destination_never_becomes_an_exclusion() {
    let root = std::env::temp_dir().join("nelomai-layout-fixture");
    let generation = format!("{}-123abc", "a".repeat(64));
    for relative in [
        format!("releases/{generation}/engines/latest/0.2.16/amneziawg-tunnel.dll"),
        "releases/.stage-bad/engines/latest/0.2.16/amneziawg-tunnel.dll".into(),
        format!("releases/.stage-{generation}/engines/other/0.2.16/amneziawg-tunnel.dll"),
        format!("releases/.stage-{generation}/engines/latest/../amneziawg-tunnel.dll"),
        format!("releases/.stage-{generation}/engines/latest/0.2.16/nested/amneziawg-tunnel.dll"),
    ] {
        assert!(layout::copy_exclusion_paths(&root, &root.join(relative)).is_err());
    }
    assert!(layout::copy_exclusion_paths(
        &root,
        &root
            .with_file_name("elsewhere")
            .join("amneziawg-tunnel.dll")
    )
    .is_err());
}
