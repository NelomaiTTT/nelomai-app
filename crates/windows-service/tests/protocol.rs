use nelomai_windows_service::{
    authorize_client, decode_request, decode_response, encode_request, encode_response,
    service_command_line, ClientIdentity, ClientPolicy, Request, Response, ServiceError,
    ServiceTunnelState, MAX_FRAME_SIZE, PROTOCOL_VERSION,
};
use std::path::{Path, PathBuf};

#[test]
fn start_request_is_framed_and_redacted() {
    let request = Request::start("PrivateKey = never-log-this".to_string());
    let frame = encode_request(&request).expect("encode request");
    let decoded = decode_request(&frame).expect("decode request");

    assert_eq!(decoded, request);
    assert_eq!(
        format!("{request:?}"),
        "Start { protocol_version: 4, configuration: \"<redacted>\", options: DesktopTunnelOptions { excluded_ipv4_cidrs_count: 0, exclude_local_networks: false, policy_hash_present: false } }"
    );
    assert!(!format!("{request:?}").contains("never-log-this"));
}

#[test]
fn old_start_request_decodes_for_an_explicit_protocol_rejection() {
    let payload =
        br#"{"command":"start","protocolVersion":2,"configuration":"PrivateKey = redacted"}"#;
    let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(payload);

    let request = decode_request(&frame).expect("decode previous protocol request");

    assert_eq!(request.protocol_version(), 2);
}

#[test]
fn previous_helper_response_decodes_without_a_fingerprint_field() {
    let payload = br#"{"protocolVersion":2,"ok":true,"state":"running","serviceVersion":"0.1.6","errorCode":null}"#;
    let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(payload);

    let response = decode_response(&frame).expect("decode previous helper response");

    assert_eq!(response.protocol_version, 2);
    assert_eq!(response.physical_network_fingerprint, None);
}

#[test]
fn decoder_rejects_oversized_or_truncated_frames() {
    let oversized = (MAX_FRAME_SIZE as u32 + 1).to_le_bytes().to_vec();
    assert_eq!(
        decode_request(&oversized).unwrap_err(),
        ServiceError::FrameTooLarge
    );

    let truncated = vec![8, 0, 0, 0, b'{'];
    assert_eq!(
        decode_request(&truncated).unwrap_err(),
        ServiceError::TruncatedFrame
    );
}

#[test]
fn response_uses_the_same_bounded_frame_contract() {
    let response = Response::success(Some(ServiceTunnelState::Running));
    let frame = encode_response(&response).expect("encode response");

    assert_eq!(decode_response(&frame).expect("decode response"), response);

    let oversized = (MAX_FRAME_SIZE as u32 + 1).to_le_bytes().to_vec();
    assert_eq!(
        decode_response(&oversized).unwrap_err(),
        ServiceError::FrameTooLarge
    );
}

#[test]
fn protocol_rejects_every_command_outside_the_typed_allowlist() {
    let unsupported = format!(r#"{{"protocolVersion":{PROTOCOL_VERSION},"command":"run_shell"}}"#);
    let mut frame = (unsupported.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(unsupported.as_bytes());

    assert!(matches!(
        decode_request(&frame),
        Err(ServiceError::InvalidRequest)
    ));
}

#[test]
fn client_requires_owner_sid_and_exact_installed_binary() {
    let policy = ClientPolicy {
        owner_sid: "S-1-5-21-1000".to_string(),
        installed_client_path: PathBuf::from(r"C:\Program Files\Nelomai\Nelomai.exe"),
    };
    let identity = ClientIdentity {
        sid: "S-1-5-21-1000".to_string(),
        process_path: PathBuf::from(r"c:/program files/nelomai/NELOMAI.EXE"),
    };

    authorize_client(&policy, &identity).expect("authorize installed client");

    let extended_path = ClientIdentity {
        sid: policy.owner_sid.clone(),
        process_path: PathBuf::from(r"\\?\C:\Program Files\Nelomai\Nelomai.exe"),
    };
    authorize_client(&policy, &extended_path).expect("authorize normalized Windows path");

    let wrong_sid = ClientIdentity {
        sid: "S-1-5-21-2000".to_string(),
        process_path: identity.process_path.clone(),
    };
    assert_eq!(
        authorize_client(&policy, &wrong_sid).unwrap_err(),
        ServiceError::UnauthorizedClient
    );

    let copied_binary = ClientIdentity {
        sid: policy.owner_sid.clone(),
        process_path: PathBuf::from(r"C:\Users\User\Downloads\Nelomai.exe"),
    };
    assert_eq!(
        authorize_client(&policy, &copied_binary).unwrap_err(),
        ServiceError::UnauthorizedClient
    );
}

#[test]
fn wireguard_service_command_quotes_executable_and_config() {
    let command = service_command_line(
        Path::new(r"C:\Program Files\Nelomai\nelomai-windows-service.exe"),
        Path::new(r"C:\ProgramData\Nelomai\tunnel\nelomai.conf"),
    )
    .expect("build service command");

    assert_eq!(
        command,
        r#""C:\Program Files\Nelomai\nelomai-windows-service.exe" --wireguard-service "C:\ProgramData\Nelomai\tunnel\nelomai.conf""#
    );
}

#[test]
fn command_line_rejects_quote_injection() {
    let error = service_command_line(
        Path::new(r#"C:\Program Files\Nelomai\helper".exe"#),
        Path::new(r"C:\ProgramData\Nelomai\nelomai.conf"),
    )
    .unwrap_err();

    assert_eq!(error, ServiceError::UnsafePath);
}
